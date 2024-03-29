/*
 * ssh.c
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
#ifdef IPOQUE_PROTOCOL_SSH

static void ipoque_int_ssh_add_connection(struct ipoque_detection_module_struct
										  *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_SSH;
	packet->detected_protocol = IPOQUE_PROTOCOL_SSH;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_SSH);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_SSH);
	}
}

void ipoque_search_ssh_tcp(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
//      struct ipoque_id_struct         *src=ipoque_struct->src;
//      struct ipoque_id_struct         *dst=ipoque_struct->dst;



	if (flow->ssh_stage == 0) {
		if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
			&& memcmp(packet->payload, "SSH-", 4) == 0) {
			IPQ_LOG(IPOQUE_PROTOCOL_SSH, ipoque_struct, IPQ_LOG_DEBUG, "ssh stage 0 passed\n");
			flow->ssh_stage = 1 + packet->packet_direction;
			return;
		}
	} else if (flow->ssh_stage == (2 - packet->packet_direction)) {
		if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
			&& memcmp(packet->payload, "SSH-", 4) == 0) {
			IPQ_LOG(IPOQUE_PROTOCOL_SSH, ipoque_struct, IPQ_LOG_DEBUG, "found ssh\n");
			ipoque_int_ssh_add_connection(ipoque_struct);
			return;

		}


	}

	IPQ_LOG(IPOQUE_PROTOCOL_SSH, ipoque_struct, IPQ_LOG_DEBUG, "excluding ssh at stage %d\n", flow->ssh_stage);

	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_SSH);
}

#endif
