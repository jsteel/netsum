/*
 * yahoo.c
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

#ifdef IPOQUE_PROTOCOL_YAHOO

struct ipoque_yahoo_header {
	u8 YMSG_str[4];
	u16 version;
	u16 nothing0;
	u16 len;
	u16 service;
	u32 status;
	u32 session_id;
};

static void ipoque_int_yahoo_add_connection(struct ipoque_detection_module_struct
											*ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_YAHOO;
	packet->detected_protocol = IPOQUE_PROTOCOL_YAHOO;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO);
	}
}

static inline u8 check_ymsg(const u8 * payload, u16 payload_packet_len)
{

	const struct ipoque_yahoo_header *yahoo = (struct ipoque_yahoo_header *) payload;

	u16 yahoo_len_parsed = 0;
	do {
		u16 ylen = ntohs(yahoo->len);

		yahoo_len_parsed += 20 + ylen;	/* possible overflow here: 20 + ylen = 0x10000 --> 0 --> infinite loop */

		if (ylen >= payload_packet_len || yahoo_len_parsed >= payload_packet_len)
			break;

		yahoo = (struct ipoque_yahoo_header *) (payload + yahoo_len_parsed);
	}
	while (memcmp(yahoo->YMSG_str, "YMSG", 4) == 0);

	if (yahoo_len_parsed == payload_packet_len)
		return 1;
	return 0;
}

static void ipoque_search_yahoo_tcp(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	const struct ipoque_yahoo_header *yahoo = (struct ipoque_yahoo_header *) packet->payload;
	if (packet->payload_packet_len == 0) {
		return;
	}

	/* packet must be at least 20 bytes long */
	if (packet->payload_packet_len >= 20
		&& memcmp(yahoo->YMSG_str, "YMSG", 4) == 0 && ((packet->payload_packet_len - 20) == ntohs(yahoo->len)
													   || check_ymsg(packet->payload, packet->payload_packet_len))) {
		IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE, "YAHOO FOUND\n");
		flow->yahoo_detection_finished = 2;
		if (ntohs(yahoo->service) == 24 || ntohs(yahoo->service) == 152 || ntohs(yahoo->service) == 74) {
			IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE, "YAHOO conference or chat invite  found");
			if (src != NULL) {
				src->yahoo_conf_logged_in = 1;
			}
			if (dst != NULL) {
				dst->yahoo_conf_logged_in = 1;
			}
		}
		if (ntohs(yahoo->service) == 27 || ntohs(yahoo->service) == 155 || ntohs(yahoo->service) == 160) {
			IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE, "YAHOO conference or chat logoff found");
			if (src != NULL) {
				src->yahoo_conf_logged_in = 0;
				src->yahoo_voice_conf_logged_in = 0;
			}
		}
		ipoque_int_yahoo_add_connection(ipoque_struct);
		return;
	} else if (flow->yahoo_detection_finished == 2 && packet->detected_protocol == IPOQUE_PROTOCOL_YAHOO) {
		return;
	}
	/* now test for http login, at least 100 a bytes packet */
	if (ipoque_struct->yahoo_detect_http_connections != 0 && packet->payload_packet_len > 100) {
		if (memcmp(packet->payload, "POST /relay?token=", 18) == 0
			|| memcmp(packet->payload, "GET /relay?token=", 17) == 0
			|| memcmp(packet->payload, "GET /?token=", 12) == 0
			|| memcmp(packet->payload, "HEAD /relay?token=", 18) == 0) {
			if ((src != NULL
				 && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO)
				 != 0) || (dst != NULL
						   && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO)
						   != 0)) {
				/* this is mostly a file transfer */
				if (0) {
				}
				ipoque_int_yahoo_add_connection(ipoque_struct);
				return;
			}
		}
		if (memcmp(packet->payload, "POST ", 5) == 0) {
			u16 a;
			ipq_parse_packet_line_info(ipoque_struct);

			if (IPQ_SRC_OR_DST_HAS_PROTOCOL(src, dst, IPOQUE_PROTOCOL_YAHOO)
				&& packet->parsed_lines > 5
				&& memcmp(&packet->payload[5], "/Messenger.", 11) == 0
				&& packet->line[1].len >= 17
				&& ipq_mem_cmp(packet->line[1].ptr, "Connection: Close",
							   17) == 0 && packet->line[2].len >= 6
				&& ipq_mem_cmp(packet->line[2].ptr, "Host: ", 6) == 0
				&& packet->line[3].len >= 16
				&& ipq_mem_cmp(packet->line[3].ptr, "Content-Length: ",
							   16) == 0 && packet->line[4].len >= 23
				&& ipq_mem_cmp(packet->line[4].ptr, "User-Agent: Mozilla/5.0",
							   23) == 0 && packet->line[5].len >= 23
				&& ipq_mem_cmp(packet->line[5].ptr, "Cache-Control: no-cache", 23) == 0) {
				IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE,
						"YAHOO HTTP POST P2P FILETRANSFER FOUND\n");
				if (0) {
				}
				ipoque_int_yahoo_add_connection(ipoque_struct);
				return;
			}

			if (packet->host_line.ptr != NULL && packet->host_line.len >= 26 &&
				ipq_mem_cmp(packet->host_line.ptr, "filetransfer.msg.yahoo.com", 26) == 0) {
				IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE, "YAHOO HTTP POST FILETRANSFER FOUND\n");
				if (0) {
				}
				ipoque_int_yahoo_add_connection(ipoque_struct);
				return;
			}
			/* now check every line */
			for (a = 0; a < packet->parsed_lines; a++) {
				if (packet->line[a].len >= 4 && ipq_mem_cmp(packet->line[a].ptr, "YMSG", 4) == 0) {
					IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct,
							IPQ_LOG_TRACE,
							"YAHOO HTTP POST FOUND, line is: %.*s\n", packet->line[a].len, packet->line[a].ptr);
					ipoque_int_yahoo_add_connection(ipoque_struct);
					return;
				}
			}
		}
		if (memcmp(packet->payload, "GET /Messenger.", 15) == 0) {
			if ((src != NULL
				 && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO)
				 != 0) || (dst != NULL
						   && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO)
						   != 0)) {
				IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE, "YAHOO HTTP GET /Messenger. match\n");
				ipoque_int_yahoo_add_connection(ipoque_struct);
				return;
			}
		}
	}
	/* found another http login command for yahoo, it is like OSCAR */
	/* detect http connections */
	if (packet->payload_packet_len > 38 && memcmp(packet->payload, "CONNECT scs.msg.yahoo.com:5050 HTTP/1.", 38) == 0) {
		IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE, "YAHOO-HTTP FOUND\n");
		ipoque_int_yahoo_add_connection(ipoque_struct);
		return;
	}

	if ((src != NULL && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO) != 0)
		|| (dst != NULL
			&& IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO) != 0)) {
		if (packet->payload_packet_len == 6 && memcmp(packet->payload, "YAHOO!", 6) == 0) {
			IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE, "YAHOO-GAMES FOUND\n");
			ipoque_int_yahoo_add_connection(ipoque_struct);
			return;
		}
		/* asymmetric detection for SNDIMG not done yet.
		 * See ./Yahoo8.1-VideoCall-LAN.pcap and ./Yahoo-VideoCall-inPublicIP.pcap */


		if (packet->payload_packet_len == 8
			&& (memcmp(packet->payload, "<SNDIMG>", 8) == 0 || memcmp(packet->payload, "<REQIMG>", 8) == 0)) {
			IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_TRACE, "YAHOO SNDIMG or REQIMG FOUND\n");
			if (src != NULL) {
				if (memcmp(packet->payload, "<SNDIMG>", 8) == 0) {
					src->yahoo_video_lan_dir = 0;
				} else {
					src->yahoo_video_lan_dir = 1;
				}
				src->yahoo_video_lan_timer = packet->tick_timestamp;
			}
			if (dst != NULL) {
				if (memcmp(packet->payload, "<SNDIMG>", 8) == 0) {
					dst->yahoo_video_lan_dir = 0;
				} else {
					dst->yahoo_video_lan_dir = 1;
				}
				dst->yahoo_video_lan_timer = packet->tick_timestamp;

			}
			ipoque_int_yahoo_add_connection(ipoque_struct);
			return;
		}
		if (src != NULL && packet->tcp->dest == htons(5100)
			&& ((IPOQUE_TIMESTAMP_COUNTER_SIZE)
				(packet->tick_timestamp - src->yahoo_video_lan_timer) < ipoque_struct->yahoo_lan_video_timeout)) {
			if (src->yahoo_video_lan_dir == 1) {
				ipoque_int_yahoo_add_connection(ipoque_struct);
				IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_DEBUG, "IMG MARKED");
				return;
			}

		}
		if (dst != NULL && packet->tcp->dest == htons(5100)
			&& ((IPOQUE_TIMESTAMP_COUNTER_SIZE)
				(packet->tick_timestamp - dst->yahoo_video_lan_timer) < ipoque_struct->yahoo_lan_video_timeout)) {
			if (dst->yahoo_video_lan_dir == 0) {
				ipoque_int_yahoo_add_connection(ipoque_struct);
				IPQ_LOG(IPOQUE_PROTOCOL_YAHOO, ipoque_struct, IPQ_LOG_DEBUG, "IMG MARKED");
				return;
			}

		}
	}
//  flow->yahoo_detection_finished = 1;
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO);
}

static inline void ipoque_search_yahoo_udp(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
//      struct ipoque_id_struct         *dst=ipoque_struct->dst;
	if (src == NULL || IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO) == 0) {
		goto excl_yahoo_udp;
	}
  excl_yahoo_udp:

	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_YAHOO);
}

void ipoque_search_yahoo(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;


	if (packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 0) {
		if (packet->tcp != NULL && packet->tcp_retransmission == 0) {
#ifdef IPOQUE_PROTOCOL_HTTP
			if (packet->detected_protocol == IPOQUE_PROTOCOL_UNKNOWN
				|| packet->detected_protocol == IPOQUE_PROTOCOL_HTTP)
#else
			if (packet->detected_protocol == IPOQUE_PROTOCOL_UNKNOWN)
#endif
			{
				ipoque_search_yahoo_tcp(ipoque_struct);
			}
		} else if (packet->udp != NULL) {
			ipoque_search_yahoo_udp(ipoque_struct);
		}
	}
	if (packet->payload_packet_len > 0 && flow->yahoo_detection_finished == 2) {
		if (packet->tcp != NULL && packet->tcp_retransmission == 0) {
			ipoque_search_yahoo_tcp(ipoque_struct);
		}
	}
}
#endif
