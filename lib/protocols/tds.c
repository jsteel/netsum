/*
 * tds.c
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
#ifdef IPOQUE_PROTOCOL_TDS

static void ipoque_int_tds_add_connection(struct ipoque_detection_module_struct
										  *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_TDS;
	packet->detected_protocol = IPOQUE_PROTOCOL_TDS;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_TDS);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_TDS);
	}
}

void ipoque_search_tds_tcp(struct ipoque_detection_module_struct
						   *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
//      struct ipoque_id_struct         *src=ipoque_struct->src;
//      struct ipoque_id_struct         *dst=ipoque_struct->dst;

	if (packet->payload_packet_len > 8
		&& packet->payload_packet_len < 512
		&& packet->payload[1] < 0x02
		&& ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len && get_u16(packet->payload, 4) == 0x0000) {

		if (flow->tds_stage == 0) {
			if (packet->payload[0] != 0x02 && packet->payload[0] != 0x07 && packet->payload[0] != 0x12) {
				goto exclude_tds;
			} else {
				flow->tds_stage = 1 + packet->packet_direction;
				flow->tds_login_version = packet->payload[0];
				return;
			}
		} else if (flow->tds_stage == 2 - packet->packet_direction) {
			switch (flow->tds_login_version) {
			case 0x12:
				if (packet->payload[0] == 0x04) {
					flow->tds_stage = 3 + packet->packet_direction;
					return;
				} else {
					goto exclude_tds;
				}
				//TODO: add more cases for other versions
			default:
				goto exclude_tds;
			}
		} else if (flow->tds_stage == 4 - packet->packet_direction) {
			switch (flow->tds_login_version) {
			case 0x12:
				if (packet->payload[0] == 0x12) {
					IPQ_LOG(IPOQUE_PROTOCOL_TDS, ipoque_struct, IPQ_LOG_DEBUG, "TDS detected\n");
					ipoque_int_tds_add_connection(ipoque_struct);
					return;
				} else {
					goto exclude_tds;
				}
				//TODO: add more cases for other versions
			default:
				goto exclude_tds;
			}
		}
	}

  exclude_tds:

	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_TDS);
}

#endif
