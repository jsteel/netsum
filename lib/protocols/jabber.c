/*
 * jabber.c
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

#ifdef IPOQUE_PROTOCOL_UNENCRYPED_JABBER

static void ipoque_int_jabber_add_connection(struct ipoque_detection_module_struct
											 *ipoque_struct)
{
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_UNENCRYPED_JABBER);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_UNENCRYPED_JABBER);
	}
}


void ipoque_search_jabber_tcp(struct ipoque_detection_module_struct
							  *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;

	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	u16 x;

	IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct, IPQ_LOG_DEBUG, "search jabber.\n");

	/* search for jabber file transfer */
	/* this part is working asymmetrically */
	if (packet->tcp != NULL && packet->tcp->syn != 0 && packet->payload_packet_len == 0) {
		if (src != NULL && src->jabber_file_transfer_port != 0) {
			if (((IPOQUE_TIMESTAMP_COUNTER_SIZE)
				 (packet->tick_timestamp - src->jabber_stun_or_ft_ts)) >= ipoque_struct->jabber_file_transfer_timeout) {
				IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct,
						IPQ_LOG_DEBUG, "JABBER src stun timeout %u %u\n", src->jabber_stun_or_ft_ts,
						packet->tick_timestamp);
				src->jabber_file_transfer_port = 0;
			} else if (src->jabber_file_transfer_port == packet->tcp->dest
					   || src->jabber_file_transfer_port == packet->tcp->source) {
				IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct, IPQ_LOG_DEBUG,
						"found jabber file transfer.\n");
				ipoque_int_jabber_add_connection(ipoque_struct);
			}
		}
		if (dst != NULL && dst->jabber_file_transfer_port != 0) {
			if (((IPOQUE_TIMESTAMP_COUNTER_SIZE)
				 (packet->tick_timestamp - dst->jabber_stun_or_ft_ts)) >= ipoque_struct->jabber_file_transfer_timeout) {
				IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct,
						IPQ_LOG_DEBUG, "JABBER dst stun timeout %u %u\n", dst->jabber_stun_or_ft_ts,
						packet->tick_timestamp);
				dst->jabber_file_transfer_port = 0;
			} else if (dst->jabber_file_transfer_port == packet->tcp->dest
					   || dst->jabber_file_transfer_port == packet->tcp->source) {
				IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct, IPQ_LOG_DEBUG,
						"found jabber file transfer.\n");
				ipoque_int_jabber_add_connection(ipoque_struct);
			}
		}
		return;
	}

	if (packet->tcp != 0 && packet->payload_packet_len == 0) {
		return;
	}


	/* this part parses a packet and searches for port=. it works asymmetrically. */
	if (packet->detected_protocol == IPOQUE_PROTOCOL_UNENCRYPED_JABBER) {
		u16 lastlen;
		u16 j_port = 0;
		/* check for google jabber voip connections ... */
		/* need big packet */
		if (packet->payload_packet_len < 100) {
			return;
		}
		/* need message to or type for file-transfer */
		if (memcmp(packet->payload, "<iq to=\"", 8) != 0 && memcmp(packet->payload, "<iq type=", 9) != 0) {
			return;
		}
		IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct, IPQ_LOG_DEBUG, "JABBER <iq to=\"/type=\"\n");
		lastlen = packet->payload_packet_len - 21;
		for (x = 8; x < lastlen; x++) {
			/* invalid character */
			if (packet->payload[x] < 32 || packet->payload[x] > 127) {
				return;
			}
			if (packet->payload[x] == '@') {
				IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct, IPQ_LOG_DEBUG, "JABBER @\n");
				break;
			}
		}
		if (x >= lastlen) {
			return;
		}

		lastlen = packet->payload_packet_len - 10;
		for (; x < lastlen; x++) {
			if (packet->payload[x] == 'p') {
				if (ipq_mem_cmp(&packet->payload[x], "port=", 5) == 0) {
					IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct, IPQ_LOG_DEBUG, "port=\n");
					if (src != NULL) {
						src->jabber_stun_or_ft_ts = packet->tick_timestamp;
					}

					if (dst != NULL) {
						dst->jabber_stun_or_ft_ts = packet->tick_timestamp;
					}

					x += 6;
					j_port = htons(ipq_bytestream_to_number(&packet->payload[x], packet->payload_packet_len, &x));
					IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct,
							IPQ_LOG_DEBUG, "JABBER port : %u\n", ntohs(j_port));

					if (src != NULL && src->jabber_voice_stun_used_ports < JABBER_MAX_STUN_PORTS - 1) {
						if (packet->payload[5] == 'o') {
							src->jabber_voice_stun_port[src->jabber_voice_stun_used_ports++]
								= j_port;
						} else {
							src->jabber_file_transfer_port = j_port;
							IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct,
									IPQ_LOG_DEBUG, "src->jabber_file_transfer_port = j_port = %u;\n", ntohs(j_port));
						}
					}

					if (dst != NULL && dst->jabber_voice_stun_used_ports < JABBER_MAX_STUN_PORTS - 1) {
						if (packet->payload[5] == 'o') {
							dst->jabber_voice_stun_port[dst->jabber_voice_stun_used_ports++]
								= j_port;
						} else {
							dst->jabber_file_transfer_port = j_port;
							IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct,
									IPQ_LOG_DEBUG, "dst->jabber_file_transfer_port = j_port = %u;\n", ntohs(j_port));
						}
					}
					return;
				}
			}
		}
		return;
	}


	/* search for jabber here */
	/* this part is working asymmetrically */
	if ((packet->payload_packet_len > 13 && memcmp(packet->payload, "<?xml version=",
												   14) == 0) || (packet->payload_packet_len > 17
																 && memcmp(packet->payload, "<stream:stream to=",
																		   18) == 0)) {

		if (packet->payload_packet_len > 47) {
			const u16 lastlen = packet->payload_packet_len - 47;
			for (x = 0; x < lastlen; x++) {
				if (ipq_mem_cmp
					(&packet->payload[x],
					 "xmlns:stream='http://etherx.jabber.org/streams'", 47) == 0
					|| ipq_mem_cmp(&packet->payload[x], "xmlns:stream=\"http://etherx.jabber.org/streams\"", 47) == 0) {
					IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct, IPQ_LOG_TRACE, "found JABBER.\n");
					ipoque_int_jabber_add_connection(ipoque_struct);
					return;
				}
			}
		}
	}
	if (flow->packet_counter < 3) {
		IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct,
				IPQ_LOG_TRACE, "packet_counter: %u\n", flow->packet_counter);
		return;
	}



	IPQ_LOG(IPOQUE_PROTOCOL_UNENCRYPED_JABBER, ipoque_struct, IPQ_LOG_DEBUG, "Excluding jabber connection\n");
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_UNENCRYPED_JABBER);
}

#endif
