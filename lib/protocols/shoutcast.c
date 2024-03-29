/*
 * shoutcast.c
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

#ifdef IPOQUE_PROTOCOL_SHOUTCAST

static void ipoque_int_shoutcast_add_connection(struct ipoque_detection_module_struct
												*ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_SHOUTCAST;
	packet->detected_protocol = IPOQUE_PROTOCOL_SHOUTCAST;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_SHOUTCAST);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_SHOUTCAST);
	}
}

void ipoque_search_shoutcast_tcp(struct ipoque_detection_module_struct
								 *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;

	if (flow->packet_counter == 1) {


		if (packet->payload_packet_len > 1
			&& packet->payload_packet_len < 80 && packet->payload[packet->payload_packet_len - 1] == 0x0a) {
			IPQ_LOG(IPOQUE_PROTOCOL_SHOUTCAST, ipoque_struct, IPQ_LOG_DEBUG, "Shoutcast stage 1, end is 0x0a.\n");
			return;
		} else
			goto exclude_shoutcast;

	}
	if (flow->packet_counter == 2) {


		if (packet->payload_packet_len > 3 && ipq_mem_cmp(&packet->payload[0], "OK2", 3) == 0) {
			IPQ_LOG(IPOQUE_PROTOCOL_SHOUTCAST, ipoque_struct, IPQ_LOG_DEBUG, "Shoutcast stage 2, OK2 found.\n");
			return;
		} else
			goto exclude_shoutcast;
	} else if (flow->packet_counter == 3) {
		if (packet->payload_packet_len > 4 && ipq_mem_cmp(&packet->payload[0], "icy-", 4) == 0) {
			IPQ_LOG(IPOQUE_PROTOCOL_SHOUTCAST, ipoque_struct, IPQ_LOG_DEBUG, "Shoutcast detected.\n");
			ipoque_int_shoutcast_add_connection(ipoque_struct);
			return;
		} else
			goto exclude_shoutcast;
	}

  exclude_shoutcast:
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_SHOUTCAST);
	IPQ_LOG(IPOQUE_PROTOCOL_SHOUTCAST, ipoque_struct, IPQ_LOG_DEBUG, "Shoutcast excluded.\n");
}
#endif
