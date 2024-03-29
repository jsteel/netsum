/*
 * xbox.c
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
#ifdef IPOQUE_PROTOCOL_XBOX

static void ipoque_int_xbox_add_connection(struct ipoque_detection_module_struct
										   *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_XBOX;
	packet->detected_protocol = IPOQUE_PROTOCOL_XBOX;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_XBOX);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_XBOX);
	}
}


void ipoque_search_xbox(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	//  struct ipoque_id_struct *src = ipoque_struct->src;
	//  struct ipoque_id_struct *dst = ipoque_struct->dst;

	/*
	 * THIS IS TH XBOX UDP DETCTION ONLY !!!
	 * the xbox tcp detection is done by http code
	 */


	/* this detection also works for asymmetric xbox udp traffic */
	if (packet->udp != NULL) {

		if (packet->payload_packet_len > 12 &&
			get_u32(packet->payload, 0) == 0 && packet->payload[5] == 0x58 &&
			memcmp(&packet->payload[7], "\x00\x00\x00", 3) == 0) {

			if ((packet->payload[4] == 0x0c && packet->payload[6] == 0x76) ||
				(packet->payload[4] == 0x02 && packet->payload[6] == 0x18) ||
				(packet->payload[4] == 0x0b && packet->payload[6] == 0x80) ||
				(packet->payload[4] == 0x03 && packet->payload[6] == 0x40) ||
				(packet->payload[4] == 0x06 && packet->payload[6] == 0x4e)) {

				ipoque_int_xbox_add_connection(ipoque_struct);
				IPQ_LOG(IPOQUE_PROTOCOL_XBOX, ipoque_struct, IPQ_LOG_DEBUG, "xbox udp connection detected\n");
				return;
			}
		}

		IPQ_LOG(IPOQUE_PROTOCOL_XBOX, ipoque_struct, IPQ_LOG_DEBUG, "xbox udp excluded.\n");
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_XBOX);
	}
	/* to not exclude tcp traffic here, done by http code... */
}

#endif
