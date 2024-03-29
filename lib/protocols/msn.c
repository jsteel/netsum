/*
 * msn.c
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

#ifdef IPOQUE_PROTOCOL_MSN

#define MAX_PACKETS_FOR_MSN 100
static void ipoque_int_msn_add_connection(struct ipoque_detection_module_struct
										  *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_MSN;
	packet->detected_protocol = IPOQUE_PROTOCOL_MSN;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_MSN);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_MSN);
	}
}


static void ipoque_search_msn_tcp(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	u16 plen;
	u16 status = 0;

	IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "search msn.\n");
#ifdef IPOQUE_PROTOCOL_SSL
	if (packet->detected_protocol == IPOQUE_PROTOCOL_SSL) {
		if (flow->packet_counter < 7) {
		} else if (flow->packet_counter == 7 && packet->payload_packet_len > 300) {
			if (memcmp(packet->payload + 24, "MSNSLP", 6) == 0
				|| (get_u32(packet->payload, 0) == htonl(0x30000000) && get_u32(packet->payload, 4) == 0x00000000)) {
				ipoque_int_msn_add_connection(ipoque_struct);
				if (0) {

				}
				IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "detected MSN File Transfer, ifdef ssl.\n");
				return;
			}
		}
		if ((flow->packet_counter == 5 || flow->packet_counter == 6)
			&& (get_u32(packet->payload, 0) == htonl(0x18000000)
				&& get_u32(packet->payload, 4) == 0x00000000)) {
			flow->msn_ssl_ft++;
			if (flow->msn_ssl_ft == 2) {
				ipoque_int_msn_add_connection(ipoque_struct);
			}
			return;
		}
	}
#endif


	/* we detect the initial connection only ! */
	/* match: "VER " ..... "CVR" x 0x0d 0x0a
	 * len should be small, lets say less than 100 bytes
	 * x is now "0", but can be increased
	 */
	/* now we have a look at the first packet only. */
	if (flow->packet_counter == 1) {

		/* this part is working asymmetrically */
		if (packet->payload_packet_len > 32
			&& packet->payload[0] == 0x02
			&& ntohl(get_u32(packet->payload, 8)) == 0x2112a442
			&& ntohl(get_u32(packet->payload, 24)) == 0x000f0004 && ntohl(get_u32(packet->payload, 28)) == 0x72c64bc6) {
			IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
					"found MSN in packets that also contain voice.messenger.live.com.\n");
			ipoque_int_msn_add_connection(ipoque_struct);
			return;
		}

		/* this case works asymmetrically */
		if (packet->payload_packet_len > 12 && packet->payload_packet_len < 100) {
			if (get_u8(packet->payload, packet->payload_packet_len - 2) == 0x0d
				&& get_u8(packet->payload, packet->payload_packet_len - 1) == 0x0a) {
				/* The MSNP string is used in XBOX clients. */
				if (memcmp(packet->payload, "VER ", 4) == 0
					&&
					(memcmp
					 (&packet->payload[packet->payload_packet_len - 6], "CVR",
					  3) == 0 || memcmp(&packet->payload[packet->payload_packet_len - 8], "MSNP", 4) == 0)) {
					IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
							"found MSN by pattern VER...CVR/MSNP ODOA.\n");
					ipoque_int_msn_add_connection(ipoque_struct);
					return;
				}
			}
		}
		/* not seen this pattern in any trace */
		/* now test for http login, at least 100 a bytes packet */
		if (packet->payload_packet_len > 100) {
			if (memcmp(packet->payload, "POST http://", 12) == 0) {
				/* scan packet if not already done... */
				ipq_parse_packet_line_info(ipoque_struct);

				if (packet->content_line.ptr != NULL
					&& packet->content_line.len == 27
					&& memcmp(packet->content_line.ptr, "application/x-msn-messenger", 27) == 0) {
					IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
							"found MSN by pattern POST http:// .... application/x-msn-messenger.\n");
					ipoque_int_msn_add_connection(ipoque_struct);
					return;
				}
			}
		}

		/* now test for http login that uses a gateway, at least 400 a bytes packet */
		/* for this case the asymmetric detection is asym (1) */
		if (packet->payload_packet_len > 400) {
			if ((memcmp(packet->payload, "POST ", 5) == 0)) {
				u16 c;
				if (memcmp(&packet->payload[5], "http://", 7) == 0) {
					/*
					 * We are searching for a paten "POST http://gateway.messenger.hotmail.com/gateway/gateway.dll" or
					 * "POST http://<some ip addres here like 172.0.0.0>/gateway/gateway.dll"
					 * POST http:// is 12 byte so we are searching for 13 to 70 byte for this paten.
					 */
					for (c = 13; c < 50; c++) {
						if (memcmp(&packet->payload[c], "/", 1) == 0) {
							if (memcmp(&packet->payload[c], "/gateway/gateway.dll", 20) == 0) {
								IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
										"found MSN by pattern http://.../gateway/gateway.ddl.\n");
								status = 1;
								break;
							}
						}
					}
				} else if ((memcmp(&packet->payload[5], "/gateway/gateway.dll", 20) == 0)) {
					IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
							"found MSN by pattern http://.../gateway/gateway.ddl.\n");
					status = 1;
				}
			}
			if (status) {
				u16 a;

				ipq_parse_packet_line_info(ipoque_struct);

				if (packet->content_line.ptr != NULL
					&& packet->content_line.len == 23
					&& memcmp(packet->content_line.ptr, "text/xml; charset=utf-8", 23) == 0) {

					if ((src != NULL
						 && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_MSN)
						 != 0) || (dst != NULL
								   && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
																		 IPOQUE_PROTOCOL_MSN)
								   != 0)) {
						IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
								"found MSN with pattern text/xml; charset=utf-8.\n");
						ipoque_int_msn_add_connection(ipoque_struct);
						return;
					}
					for (a = 0; a < packet->parsed_lines; a++) {
						if (packet->line[a].len >= 4 &&
							(memcmp(packet->line[a].ptr, "CVR ", 4) == 0
							 || memcmp(packet->line[a].ptr, "VER ",
									   4) == 0 || memcmp(packet->line[a].ptr, "ANS ", 4) == 0)) {
							IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
									"found MSN with pattern text/sml; charset0utf-8.\n");
							IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct,
									IPQ_LOG_TRACE, "MSN xml CVS / VER / ANS found\n");
							ipoque_int_msn_add_connection(ipoque_struct);
							return;
						}
					}
				}
			}
		}

		/* did not find any trace with this pattern !!!!! */
		/* now block proxy connection */
		if (packet->payload_packet_len >= 42) {
			if (memcmp(packet->payload, "CONNECT messenger.hotmail.com:1863 HTTP/1.", 42) == 0) {
				IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
						"found MSN  with pattern CONNECT messenger.hotmail.com:1863 HTTP/1..\n");
				ipoque_int_msn_add_connection(ipoque_struct);
				return;
			}
		}

		if (packet->payload_packet_len >= 18) {

			if (memcmp(packet->payload, "USR ", 4) == 0 || memcmp(packet->payload, "ANS ", 4) == 0) {
				/* now we must see a number */
				const u16 endlen = packet->payload_packet_len - 12;
				plen = 4;
				while (1) {
					if (packet->payload[plen] == ' ') {
						break;
					}
					if (packet->payload[plen] < '0' || packet->payload[plen] > '9') {
						goto ipq_msn_exclude;
					}
					plen++;
					if (plen >= endlen) {
						goto ipq_msn_exclude;
					}
				}

				while (plen < endlen) {
					if (ipoque_check_for_email_address(ipoque_struct, plen) != 0) {
						IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "found mail address\n");
						break;
					}
					if (packet->payload_packet_len > plen + 1
						&& (packet->payload[plen] < 20 || packet->payload[plen] > 128)) {
						goto ipq_msn_exclude;
					}
					plen++;
					if (plen >= endlen) {
						goto ipq_msn_exclude;
					}

				}
				IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE,
						"found MSN  with pattern USR/ANS ...mail_address.\n");
				ipoque_int_msn_add_connection(ipoque_struct);
				return;
			}
		}
	}


	/* finished examining the first packet only. */
	/* direct user connection (file transfer,...) */

	if ((src != NULL && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_MSN) != 0)
		|| (dst != NULL
			&& IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_MSN) != 0)) {
		if (flow->packet_counter == 1 &&
			packet->payload_packet_len > 12 && memcmp(packet->payload, "recipientid=", 12) == 0) {
			IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_DEBUG, "detected file transfer.\n");
			ipoque_int_msn_add_connection(ipoque_struct);
			return;
		}
	}

	/* MSN File Transfer of MSN 8.1 and 8.5
	 * first packet with length 4 and pattern 0x04000000
	 * second packet (in the same direction), with length 56 and pattern 0x00000000 from payload[16]
	 * third packet (in the opposite direction to 1 & 2), with length 4 and pattern 0x30000000
	 */
	if (flow->msn_stage == 0) {
		/* asymmetric detection to this pattern is asym (2) */
		if (packet->payload_packet_len == 4 && get_u32(packet->payload, 0) == htonl(0x04000000)) {
			IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_DEBUG, "maybe first TCP MSN detected\n");
			flow->msn_stage = 1 + packet->packet_direction;
			return;
		}
		/* asymmetric detection to this pattern is asym (2) */
	} else if (flow->msn_stage == 1 + packet->packet_direction) {
		if (packet->payload_packet_len > 10 && get_u32(packet->payload, 0) == htonl(0x666f6f00)) {
			ipoque_int_msn_add_connection(ipoque_struct);
			if (0) {

			}
			IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "MSN File Transfer detected 1\n");
			return;
		}
		/* did not see this pattern in any trace */
		if (packet->payload_packet_len == 56 && get_u32(packet->payload, 16) == 0) {
			IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_DEBUG, "maybe Second TCP MSN detected\n");
			flow->msn_stage = 3 + packet->packet_direction;
			return;
		}


	} else if ((flow->msn_stage == 3 + packet->packet_direction)
			   || (flow->msn_stage == 4 - packet->packet_direction)) {
		if (packet->payload_packet_len == 4 && get_u32(packet->payload, 0) == htonl(0x30000000)) {
			ipoque_int_msn_add_connection(ipoque_struct);
			IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "MSN File Transfer detected 2\n");
			return;
		}
	}
	IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "msn 7.\n");
	if (flow->packet_counter <= MAX_PACKETS_FOR_MSN) {
		if (packet->tcp->source == htons(443)
			|| packet->tcp->dest == htons(443)) {
			if (packet->payload_packet_len > 300) {
				if (memcmp(&packet->payload[56], "INVITE MSNMSGR", 14) == 0
					|| memcmp(&packet->payload[172], "INVITE MSNMSGR", 14) == 0) {
					ipoque_int_msn_add_connection(ipoque_struct);

					IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "MSN File Transfer detected 3\n");
					return;
				}
			}
			return;
		}
		/* For no
		   n port 443 flows exclude flow bitmask after first packet itself */
	}
	IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "exclude msn.\n");
  ipq_msn_exclude:
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_MSN);
}



static inline void ipoque_search_udp_msn_misc(struct ipoque_detection_module_struct
											  *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;


	/* do we have an msn login ? */
	if ((src == NULL || IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_MSN) == 0)
		&& (dst == NULL
			|| IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_MSN) == 0)) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_MSN);
		return;
	}

/* asymmetric ft detection works */
	if (packet->payload_packet_len == 20
		&& get_u32(packet->payload, 4) == 0 && packet->payload[9] == 0
		&& get_u16(packet->payload, 10) == htons(0x0100)) {
		IPQ_LOG(IPOQUE_PROTOCOL_MSN, ipoque_struct, IPQ_LOG_TRACE, "msn udp misc data connection detected\n");
		ipoque_int_msn_add_connection(ipoque_struct);
	}

	/* asymmetric detection working. */
	return;
	//}
}


void ipoque_search_msn(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	/* this if request should always be true */
	if (IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_MSN) == 0) {
		/* we deal with tcp now */
		if (packet->tcp != NULL) {
			/* msn can use http or ssl for connection. That's why every http, ssl and ukn packet must enter in the msn detection */
			/* the detection can swich out the http or the ssl detection. In this case we need not check those protocols */
			// need to do the ceck when protocol == http too (POST /gateway ...)
#if defined(IPOQUE_PROTOCOL_HTTP) && defined(IPOQUE_PROTOCOL_SSL)
			if (packet->detected_protocol == IPOQUE_PROTOCOL_UNKNOWN
				|| packet->detected_protocol == IPOQUE_PROTOCOL_HTTP
				|| packet->detected_protocol == IPOQUE_PROTOCOL_SSL)
#elif defined(IPOQUE_PROTOCOL_HTTP)
			if (packet->detected_protocol == IPOQUE_PROTOCOL_UNKNOWN
				|| packet->detected_protocol == IPOQUE_PROTOCOL_HTTP)
#elif defined(IPOQUE_PROTOCOL_SSL)
			if (packet->detected_protocol == IPOQUE_PROTOCOL_UNKNOWN
				|| packet->detected_protocol == IPOQUE_PROTOCOL_SSL)
#else
			if (packet->detected_protocol == IPOQUE_PROTOCOL_UNKNOWN)
#endif
			{
				ipoque_search_msn_tcp(ipoque_struct);
			}
		} else if (packet->udp != NULL) {
			ipoque_search_udp_msn_misc(ipoque_struct);
		}
	}
}

#endif
