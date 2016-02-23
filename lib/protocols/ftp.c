/*
 * ftp.c
 * Copyright (C) 2009 by ipoque GmbH
 * 
 * This file is part of OpenDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * OpenDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * OpenDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with OpenDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#include "ipq_protocols.h"

#ifdef IPOQUE_PROTOCOL_FTP


static void ipoque_int_ftp_add_connection(struct ipoque_detection_module_struct
										  *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_FTP;
	packet->detected_protocol = IPOQUE_PROTOCOL_FTP;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_FTP);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_FTP);
	}
}


/*
  return 0 if nothing has been detected
  return 1 if a pop packet
*/

static inline u8 search_ftp(struct ipoque_detection_module_struct *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;

//      struct ipoque_id_struct         *src=ipoque_struct->src;
//      struct ipoque_id_struct         *dst=ipoque_struct->dst;



	/* Check for initial Server response */
	if ((flow->ftp_stage == 0)
		&& packet->payload_packet_len > 2) {

		/* check if the packet starts with "220 " */
		if (memcmp(packet->payload, "220", 3) == 0) {
			flow->ftp_stage = 1 + packet->packet_direction;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP maybe hit\n");
			return 2;
		}
	}
	if (flow->ftp_stage == 1 + packet->packet_direction &&
		(flow->packet_counter <= 10 || (packet->payload_packet_len > 2 && memcmp(packet->payload, "220", 3) == 0))) {
		IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP maybe hit\n");
		return 2;
	}
	if (flow->ftp_stage == 2 - packet->packet_direction && packet->payload_packet_len > 4) {

		if (ipq_mem_cmp(packet->payload, "USER ", 5) == 0 || ipq_mem_cmp(packet->payload, "user ", 5) == 0) {

			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP detected\n");
			ipoque_int_ftp_add_connection(ipoque_struct);

			return 1;
		}
		if (ipq_mem_cmp(packet->payload, "FEAT", 4) == 0 || ipq_mem_cmp(packet->payload, "feat", 4) == 0) {

			flow->ftp_stage = 3 + packet->packet_direction;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP maybe hit\n");
			return 2;

		}
	}
	if (flow->ftp_stage == 4 - packet->packet_direction && packet->payload_packet_len > 5) {
		if (ipq_mem_cmp(packet->payload, "211-", 4) == 0) {
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP detected\n");
			ipoque_int_ftp_add_connection(ipoque_struct);
			return 1;
		}
	}

	return 0;

}


static inline void search_passive_ftp_mode(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_id_struct *dst = ipoque_struct->dst;
	struct ipoque_id_struct *src = ipoque_struct->src;
	u16 plen;
	u8 i;
	u32 ftp_ip;



	if (packet->payload_packet_len > 30
		&& (ipq_mem_cmp(packet->payload, "227 Entering Passive Mode", 25) == 0
			|| ipq_mem_cmp(packet->payload, "227 Entering passive mode", 25) == 0)) {
		IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP passive mode initial string\n");
		plen = 26;
		for (;;) {
			if (plen >= packet->payload_packet_len)
				return;
			if (packet->payload[plen] == '(')
				break;
			if (packet->payload[plen] != ' ')
				return;
			plen++;
		}

		plen++;
		if (plen >= packet->payload_packet_len)
			return;

		ftp_ip = 0;
		for (i = 0; i < 4; i++) {
			u16 oldplen = plen;
			ftp_ip =
				(ftp_ip << 8) +
				ipq_bytestream_to_number(&packet->payload[plen], packet->payload_packet_len - plen, &plen);
			if (oldplen == plen || plen >= packet->payload_packet_len) {
				IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP passive mode %u value parse failed\n",
						i);
				return;
			}
			if (packet->payload[plen] != ',') {

				IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG,
						"FTP passive mode %u value parse failed, char ',' is missing\n", i);
				return;
			}
			plen++;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG,
					"FTP passive mode %u value parsed, ip is now: %u\n", i, ftp_ip);

		}
		if (dst != NULL) {
			dst->ftp_ip = htonl(ftp_ip);
			dst->ftp_timer = packet->tick_timestamp;
			dst->ftp_timer_set = 1;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to dst");
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP PASSIVE MODE FOUND: use  Server %u\n",
					ftp_ip);
		}
		if (src != NULL) {
			src->ftp_ip = packet->iph->daddr;
			src->ftp_timer = packet->tick_timestamp;
			src->ftp_timer_set = 1;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to src");
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP PASSIVE MODE FOUND: use  Server %u\n",
					ftp_ip);
		}
		return;
	}

	if (packet->payload_packet_len > 34 && ipq_mem_cmp(packet->payload, "229 Entering Extended Passive Mode", 34) == 0) {
		if (dst != NULL) {
			dst->ftp_ip = packet->iph->saddr;
			dst->ftp_timer = packet->tick_timestamp;
			dst->ftp_timer_set = 1;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to dst");
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG,
					"FTP Extended PASSIVE MODE FOUND: use Server %u\n", ntohl(dst->ftp_ip));
		}
		if (src != NULL) {
			src->ftp_ip = packet->iph->daddr;
			src->ftp_timer = packet->tick_timestamp;
			src->ftp_timer_set = 1;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to src");
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG,
					"FTP Extended PASSIVE MODE FOUND: use Server %u\n", ntohl(src->ftp_ip));
		}
		return;
	}
}


static inline void search_active_ftp_mode(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	if (packet->payload_packet_len > 5
		&& (ipq_mem_cmp(packet->payload, "PORT ", 5) == 0 || ipq_mem_cmp(packet->payload, "EPRT ", 5) == 0)) {

		//src->local_ftp_data_port = htons(data_port_number);
		if (src != NULL) {
			src->ftp_ip = packet->iph->daddr;
			src->ftp_timer = packet->tick_timestamp;
			src->ftp_timer_set = 1;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP ACTIVE MODE FOUND, command is %.*s\n", 4,
					packet->payload);
		}
		if (dst != NULL) {
			dst->ftp_ip = packet->iph->saddr;
			dst->ftp_timer = packet->tick_timestamp;
			dst->ftp_timer_set = 1;
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "FTP ACTIVE MODE FOUND, command is %.*s\n", 4,
					packet->payload);
		}
	}
	return;
}


void ipoque_search_ftp_tcp(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;




	if (src != NULL && src->ftp_ip == packet->iph->daddr
		&& packet->tcp->syn != 0 && packet->tcp->ack == 0
		&& packet->detected_protocol == IPOQUE_PROTOCOL_UNKNOWN
		&& IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask,
											  IPOQUE_PROTOCOL_FTP) != 0 && src->ftp_timer_set != 0) {
		IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "possible ftp data, src!= 0.\n");

		if (((IPOQUE_TIMESTAMP_COUNTER_SIZE)
			 (packet->tick_timestamp - src->ftp_timer)) >= ipoque_struct->ftp_connection_timeout) {
			src->ftp_timer_set = 0;
		} else if (ntohs(packet->tcp->dest) > 1024
				   && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "detected FTP data stream.\n");
			ipoque_int_ftp_add_connection(ipoque_struct);
			return;
		}
	}

	if (dst != NULL && dst->ftp_ip == packet->iph->saddr
		&& packet->tcp->syn != 0 && packet->tcp->ack == 0
		&& packet->detected_protocol == IPOQUE_PROTOCOL_UNKNOWN
		&& IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
											  IPOQUE_PROTOCOL_FTP) != 0 && dst->ftp_timer_set != 0) {
		IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "possible ftp data; dst!= 0.\n");

		if (((IPOQUE_TIMESTAMP_COUNTER_SIZE)
			 (packet->tick_timestamp - dst->ftp_timer)) >= ipoque_struct->ftp_connection_timeout) {
			dst->ftp_timer_set = 0;

		} else if (ntohs(packet->tcp->dest) > 1024
				   && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
			IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "detected FTP data stream.\n");
			ipoque_int_ftp_add_connection(ipoque_struct);
			return;
		}
	}
	// ftp data asymmetrically


	/* skip packets without payload */
	if (packet->payload_packet_len == 0 || (packet->detected_protocol == IPOQUE_PROTOCOL_FTP)) {
		IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG,
				"FTP test skip because of data connection or zero byte packet_payload.\n");
		return;
	}
	/* skip excluded connections */

	// we test for FTP connection and search for passive mode
	if (packet->detected_protocol == IPOQUE_PROTOCOL_FTP) {
		IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG,
				"detected ftp command mode. going to test data mode.\n");
		search_passive_ftp_mode(ipoque_struct);

		search_active_ftp_mode(ipoque_struct);
		return;
	}

	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_FTP);
	IPQ_LOG(IPOQUE_PROTOCOL_FTP, ipoque_struct, IPQ_LOG_DEBUG, "exclude ftp.\n");

}

#endif
