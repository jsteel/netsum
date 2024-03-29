/*
 * directdownloadlink.c
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
#ifdef IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK


#ifdef IPOQUE_DEBUG_DIRECT_DOWNLOAD_LINK
//#define IPOQUE_DEBUG_DIRECT_DOWNLOAD_LINK_NOTHING_FOUND
//#define IPOQUE_DEBUG_DIRECT_DOWNLOAD_LINK_PACKET_TOO_SMALL
#define IPOQUE_DEBUG_DIRECT_DOWNLOAD_LINK_IP
#endif

static void ipoque_int_direct_download_link_add_connection(struct
														   ipoque_detection_module_struct
														   *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK;
	packet->detected_protocol = IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK;

	flow->ddlink_server_direction = packet->packet_direction;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK);
	}
}



/*
  return 0 if nothing has been detected
  return 1 if it is a megaupload packet
*/
u8 search_ddl_domains(struct ipoque_detection_module_struct *ipoque_struct);
u8 search_ddl_domains(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
//      struct ipoque_id_struct         *src=ipoque_struct->src;
//      struct ipoque_id_struct         *dst=ipoque_struct->dst;

	u16 filename_start = 0;
	u8 i = 1;
	u16 host_line_len_without_port;

	if (packet->payload_packet_len < 100) {
		IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG, "DDL: Packet too small.\n");
		goto end_directdownloadlink_nothing_found;
	}



	if (memcmp(packet->payload, "POST ", 5) == 0) {
		filename_start = 5;		// POST
		IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG, "DDL: POST FOUND\n");
	} else if (memcmp(packet->payload, "GET ", 4) == 0) {
		filename_start = 4;		// GET
		IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG, "DDL: GET FOUND\n");
	} else {
		goto end_directdownloadlink_nothing_found;
	}
	// parse packet
	ipq_parse_packet_line_info(ipoque_struct);

	if (packet->host_line.ptr == NULL) {
		IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG, "DDL: NO HOST FOUND\n");
		goto end_directdownloadlink_nothing_found;
	}

	IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG, "DDL: Host: found\n");

	if (packet->line[0].len < 9 + filename_start
		|| memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) != 0) {
		IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct,
				IPQ_LOG_DEBUG, "DDL: PACKET NOT HTTP CONFORM.\nXXX%.*sXXX\n",
				8, &packet->line[0].ptr[packet->line[0].len - 9]);
		goto end_directdownloadlink_nothing_found;
	}
// BEGIN OF AUTOMATED CODE GENERATION
	// first see if we have ':port' at the end of the line
	host_line_len_without_port = packet->host_line.len;
	if (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] >= '0'
		&& packet->host_line.ptr[packet->host_line.len - i] <= '9') {
		i = 2;
		while (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] >= '0'
			   && packet->host_line.ptr[host_line_len_without_port - i] <= '9') {
			IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG, "DDL: number found\n");
			i++;
		}
		if (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] == ':') {
			IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG, "DDL: ':' found\n");
			host_line_len_without_port = host_line_len_without_port - i;
		}
	}
	// then start automated code generation
	if (host_line_len_without_port >= 0 + 4
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 4], ".com", 4) == 0) {
		if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'd') {
			if (host_line_len_without_port >= 5 + 6 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 6], "4share",
						  6) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 8 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "fileclou",
						  8) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 5
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "uploa", 5) == 0) {
				if (host_line_len_without_port >= 10 + 4 + 1
					&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "mega",
							  4) == 0
					&& (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
						|| packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == '.')) {
					goto end_directdownloadlink_found;
				}
				if (host_line_len_without_port >= 10 + 5 + 1
					&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "rapid",
							  5) == 0
					&& (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
						|| packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
					goto end_directdownloadlink_found;
				}
				goto end_directdownloadlink_nothing_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'o') {
			if (host_line_len_without_port >= 5 + 6 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 6], "badong",
						  6) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 5 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "fileh",
						  5) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 4 + 8 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 8], "bigfilez",
					  8) == 0 && (packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == ' '
								  || packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'e') {
			if (host_line_len_without_port >= 5 + 1 && packet->host_line.ptr[host_line_len_without_port - 5 - 1] == 'r') {
				if (host_line_len_without_port >= 6 + 3
					&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 3], "sha", 3) == 0) {
					if (host_line_len_without_port >= 9 + 1
						&& packet->host_line.ptr[host_line_len_without_port - 9 - 1] == '-') {
						if (host_line_len_without_port >= 10 + 4 + 1
							&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4],
									  "easy", 4) == 0
							&& (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
								|| packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == '.')) {
							goto end_directdownloadlink_found;
						}
						if (host_line_len_without_port >= 10 + 4 + 1
							&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4],
									  "live", 4) == 0
							&& (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
								|| packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == '.')) {
							goto end_directdownloadlink_found;
						}
						goto end_directdownloadlink_nothing_found;
					}
					if (host_line_len_without_port >= 9 + 4 + 1
						&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4],
								  "ftp2", 4) == 0
						&& (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
							|| packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
						goto end_directdownloadlink_found;
					}
					if (host_line_len_without_port >= 9 + 4 + 1
						&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4],
								  "gige", 4) == 0
						&& (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
							|| packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
						goto end_directdownloadlink_found;
					}
					if (host_line_len_without_port >= 9 + 4 + 1
						&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4],
								  "mega", 4) == 0
						&& (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
							|| packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
						goto end_directdownloadlink_found;
					}
					if (host_line_len_without_port >= 9 + 5 + 1
						&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 5],
								  "rapid", 5) == 0
						&& (packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == ' '
							|| packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == '.')) {
						goto end_directdownloadlink_found;
					}
					goto end_directdownloadlink_nothing_found;
				}
				if (host_line_len_without_port >= 6 + 7 + 1
					&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 7],
							  "mediafi", 7) == 0
					&& (packet->host_line.ptr[host_line_len_without_port - 6 - 7 - 1] == ' '
						|| packet->host_line.ptr[host_line_len_without_port - 6 - 7 - 1] == '.')) {
					goto end_directdownloadlink_found;
				}
				goto end_directdownloadlink_nothing_found;
			}
			if (host_line_len_without_port >= 5 + 7 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "gigasiz",
						  7) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 3
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 3], "fil", 3) == 0) {
				if (host_line_len_without_port >= 8 + 2 + 1
					&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 2], "mo",
							  2) == 0
					&& (packet->host_line.ptr[host_line_len_without_port - 8 - 2 - 1] == ' '
						|| packet->host_line.ptr[host_line_len_without_port - 8 - 2 - 1] == '.')) {
					goto end_directdownloadlink_found;
				}
				if (host_line_len_without_port >= 8 + 2
					&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 2], "p-", 2) == 0) {
					if (host_line_len_without_port >= 10 + 2 + 1
						&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 2],
								  "vi", 2) == 0
						&& (packet->host_line.ptr[host_line_len_without_port - 10 - 2 - 1] == ' '
							|| packet->host_line.ptr[host_line_len_without_port - 10 - 2 - 1] == '.')) {
						goto end_directdownloadlink_found;
					}
					if (host_line_len_without_port >= 10 + 1 + 1
						&& packet->host_line.ptr[host_line_len_without_port - 10 - 1] == 'u'
						&& (packet->host_line.ptr[host_line_len_without_port - 10 - 1 - 1] == ' '
							|| packet->host_line.ptr[host_line_len_without_port - 10 - 1 - 1] == '.')) {
						goto end_directdownloadlink_found;
					}
					goto end_directdownloadlink_nothing_found;
				}
				goto end_directdownloadlink_nothing_found;
			}
			if (host_line_len_without_port >= 5 + 8 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "sendspac",
						  8) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 7 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "sharebe",
						  7) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 5 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "adriv",
						  5) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 4 + 11 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 11], "filefactory",
					  11) == 0 && (packet->host_line.ptr[host_line_len_without_port - 4 - 11 - 1] == ' '
								   || packet->host_line.ptr[host_line_len_without_port - 4 - 11 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 't') {
			if (host_line_len_without_port >= 5 + 8 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "filefron",
						  8) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 10 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 10],
						  "uploadingi", 10) == 0
				&& (packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == ' '
					|| packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 11 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 11],
						  "yourfilehos", 11) == 0
				&& (packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == ' '
					|| packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 's') {
			if (host_line_len_without_port >= 5 + 10 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 10],
						  "fileupyour", 10) == 0
				&& (packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == ' '
					|| packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 5 + 9 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 9], "megashare",
						  9) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 9 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 9 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'g') {
			if (host_line_len_without_port >= 5 + 2
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 2], "in", 2) == 0) {
				if (host_line_len_without_port >= 7 + 9 + 1
					&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 7 - 9],
							  "quickshar", 9) == 0
					&& (packet->host_line.ptr[host_line_len_without_port - 7 - 9 - 1] == ' '
						|| packet->host_line.ptr[host_line_len_without_port - 7 - 9 - 1] == '.')) {
					goto end_directdownloadlink_found;
				}
				if (host_line_len_without_port >= 7 + 6 + 1
					&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 7 - 6], "upload",
							  6) == 0
					&& (packet->host_line.ptr[host_line_len_without_port - 7 - 6 - 1] == ' '
						|| packet->host_line.ptr[host_line_len_without_port - 7 - 6 - 1] == '.')) {
					goto end_directdownloadlink_found;
				}
				goto end_directdownloadlink_nothing_found;
			}
			if (host_line_len_without_port >= 5 + 6 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 6], "hostgg",
						  6) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 4 + 9 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 9], "megarotic",
					  9) == 0 && (packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == ' '
								  || packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		if (host_line_len_without_port >= 4 + 10 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 10], "massmirror",
					  10) == 0 && (packet->host_line.ptr[host_line_len_without_port - 4 - 10 - 1] == ' '
								   || packet->host_line.ptr[host_line_len_without_port - 4 - 10 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		goto end_directdownloadlink_nothing_found;
	}
	if (host_line_len_without_port >= 0 + 4
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 4], ".net", 4) == 0) {
		if (host_line_len_without_port >= 4 + 7 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 7], "badongo",
					  7) == 0 && (packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == ' '
								  || packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		if (host_line_len_without_port >= 4 + 5 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 5], "filer", 5) == 0
			&& (packet->host_line.ptr[host_line_len_without_port - 4 - 5 - 1] == ' '
				|| packet->host_line.ptr[host_line_len_without_port - 4 - 5 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		if (host_line_len_without_port >= 4 + 6
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 6], "upload", 6) == 0) {
			if (host_line_len_without_port >= 10 + 5 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "file-",
						  5) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 10 + 6 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 6], "simple",
						  6) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 10 + 3 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 3], "wii",
						  3) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 3 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 10 - 3 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 4 + 6 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 6], "zshare", 6) == 0
			&& (packet->host_line.ptr[host_line_len_without_port - 4 - 6 - 1] == ' '
				|| packet->host_line.ptr[host_line_len_without_port - 4 - 6 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		goto end_directdownloadlink_nothing_found;
	}
	if (host_line_len_without_port >= 0 + 3
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 3], ".ru", 3) == 0) {
		if (host_line_len_without_port >= 3 + 10 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 10], "filearchiv",
					  10) == 0 && (packet->host_line.ptr[host_line_len_without_port - 3 - 10 - 1] == ' '
								   || packet->host_line.ptr[host_line_len_without_port - 3 - 10 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		if (host_line_len_without_port >= 3 + 8 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 8], "filepost",
					  8) == 0 && (packet->host_line.ptr[host_line_len_without_port - 3 - 8 - 1] == ' '
								  || packet->host_line.ptr[host_line_len_without_port - 3 - 8 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		if (host_line_len_without_port >= 3 + 7 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 7], "ifolder",
					  7) == 0 && (packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == ' '
								  || packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		goto end_directdownloadlink_nothing_found;
	}
	if (host_line_len_without_port >= 0 + 3
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 3], ".to", 3) == 0) {
		if (host_line_len_without_port >= 3 + 5 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 5], "files", 5) == 0
			&& (packet->host_line.ptr[host_line_len_without_port - 3 - 5 - 1] == ' '
				|| packet->host_line.ptr[host_line_len_without_port - 3 - 5 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		if (host_line_len_without_port >= 3 + 1 && packet->host_line.ptr[host_line_len_without_port - 3 - 1] == 'd') {
			if (host_line_len_without_port >= 4 + 7 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 7], "uploade",
						  7) == 0 && (packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 4 + 3 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 3], "loa",
						  3) == 0 && (packet->host_line.ptr[host_line_len_without_port - 4 - 3 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 4 - 3 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 3 + 8 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 8], "filebase",
					  8) == 0 && (packet->host_line.ptr[host_line_len_without_port - 3 - 8 - 1] == ' '
								  || packet->host_line.ptr[host_line_len_without_port - 3 - 8 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		goto end_directdownloadlink_nothing_found;
	}
	if (host_line_len_without_port >= 0 + 3
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 3], ".de", 3) == 0) {
		if (host_line_len_without_port >= 3 + 5
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 5], "share", 5) == 0) {
			if (host_line_len_without_port >= 8 + 5 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 5], "rapid",
						  5) == 0 && (packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			if (host_line_len_without_port >= 8 + 5 + 1
				&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 5], "ultra",
						  5) == 0 && (packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == ' '
									  || packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == '.')) {
				goto end_directdownloadlink_found;
			}
			goto end_directdownloadlink_nothing_found;
		}
		if (host_line_len_without_port >= 3 + 15 + 1
			&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 15],
					  "uploadyourfiles", 15) == 0
			&& (packet->host_line.ptr[host_line_len_without_port - 3 - 15 - 1] == ' '
				|| packet->host_line.ptr[host_line_len_without_port - 3 - 15 - 1] == '.')) {
			goto end_directdownloadlink_found;
		}
		goto end_directdownloadlink_nothing_found;
	}
	if (host_line_len_without_port >= 0 + 14 + 1
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 14], "speedshare.org",
				  14) == 0 && (packet->host_line.ptr[host_line_len_without_port - 0 - 14 - 1] == ' '
							   || packet->host_line.ptr[host_line_len_without_port - 0 - 14 - 1] == '.')) {
		goto end_directdownloadlink_found;
	}
	if (host_line_len_without_port >= 0 + 13 + 1
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 13], "yourfiles.biz",
				  13) == 0 && (packet->host_line.ptr[host_line_len_without_port - 0 - 13 - 1] == ' '
							   || packet->host_line.ptr[host_line_len_without_port - 0 - 13 - 1] == '.')) {
		goto end_directdownloadlink_found;
	}
	if (host_line_len_without_port >= 0 + 10 + 1
		&& memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 10], "netload.in",
				  10) == 0 && (packet->host_line.ptr[host_line_len_without_port - 0 - 10 - 1] == ' '
							   || packet->host_line.ptr[host_line_len_without_port - 0 - 10 - 1] == '.')) {
		goto end_directdownloadlink_found;
	}
// END OF AUTOMATED CODE GENERATION

	/* This is the hard way. We do this in order to find the download of services when other
	   domains are involved. This is not significant if ddl is blocked. --> then the link can not be started because
	   the ads are not viewed. But when ddl is only limited then the download is the important part.
	 */

  end_directdownloadlink_nothing_found:
	IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG,
			"Nothing Found\n%.*s\n", packet->payload_packet_len, packet->payload);
	return 0;

  end_directdownloadlink_found:
	IPQ_LOG(IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK, ipoque_struct, IPQ_LOG_DEBUG, "DDL: DIRECT DOWNLOAD LINK FOUND\n");
	ipoque_int_direct_download_link_add_connection(ipoque_struct);
	return 1;
}


void ipoque_search_direct_download_link_tcp(struct
											ipoque_detection_module_struct
											*ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
//      struct ipoque_id_struct         *src=ipoque_struct->src;
//      struct ipoque_id_struct         *dst=ipoque_struct->dst;
	if (ipoque_struct->direct_download_link_counter_callback != NULL) {
		if (packet->detected_protocol == IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK) {
			/* skip packets not requests from the client to the server */
			if (packet->packet_direction == flow->ddlink_server_direction) {
				search_ddl_domains(ipoque_struct);	// do the detection again in order to get the URL in keep alive streams
			} else {
				// just count the packet
				ipoque_struct->direct_download_link_counter_callback(flow->hash_id_number, packet->l3_packet_len);
			}
		}
		return;
	}
	// do not detect again if it is already ddl
	if (packet->detected_protocol != IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK) {
		if (search_ddl_domains(ipoque_struct) != 0) {
			return;
		}
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK);
	}

}
#endif
