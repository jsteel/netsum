/*
 * ipq_main.h
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


#ifndef __IPOQUE_MAIN_INCLUDE_FILE__
#define __IPOQUE_MAIN_INCLUDE_FILE__


#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <endian.h>
#include <byteswap.h>
/* default includes */
#include <netinet/ip6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

//#include <arpa/inet.h>

#ifndef u64
#define u64 	uint64_t
#endif
#ifndef u32
#define u32 	uint32_t
#endif
#ifndef u16
#define u16 	uint16_t
#endif
#ifndef u8
#define u8 	uint8_t
#endif

#include "ipq_api.h"
#include "ipq_structs.h"

#define IPOQUE_USE_ASYMMETRIC_DETECTION             0
#define IPQ_SELECTION_BITMASK_PROTOCOL_SIZE			u32

#define IPQ_SELECTION_BITMASK_PROTOCOL_IP			(1<<0)
#define IPQ_SELECTION_BITMASK_PROTOCOL_INT_TCP			(1<<1)
#define IPQ_SELECTION_BITMASK_PROTOCOL_INT_UDP			(1<<2)
#define IPQ_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP		(1<<3)
#define IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD		(1<<4)
#define IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION	(1<<5)
#define IPQ_SELECTION_BITMASK_PROTOCOL_IPV6			(1<<6)
#define IPQ_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6			(1<<7)
#define IPQ_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC		(1<<8)
/* now combined detections */

/* v4 */
#define IPQ_SELECTION_BITMASK_PROTOCOL_TCP (IPQ_SELECTION_BITMASK_PROTOCOL_IP | IPQ_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define IPQ_SELECTION_BITMASK_PROTOCOL_UDP (IPQ_SELECTION_BITMASK_PROTOCOL_IP | IPQ_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define IPQ_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP (IPQ_SELECTION_BITMASK_PROTOCOL_IP | IPQ_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)

/* v6 */
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP (IPQ_SELECTION_BITMASK_PROTOCOL_IPV6 | IPQ_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_UDP (IPQ_SELECTION_BITMASK_PROTOCOL_IPV6 | IPQ_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP (IPQ_SELECTION_BITMASK_PROTOCOL_IPV6 | IPQ_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)

/* v4 or v6 */
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP (IPQ_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | IPQ_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP (IPQ_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | IPQ_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP (IPQ_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | IPQ_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)


#define IPQ_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

/* does it make sense to talk about udp with payload ??? have you ever seen empty udp packets ? */
#define IPQ_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_V6_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define IPQ_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD		(IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define IPQ_SELECTION_BITMASK_PROTOCOL_TCP_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)

#define IPQ_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)

#define IPQ_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define IPQ_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(IPQ_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | IPQ_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | IPQ_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

/* safe src/dst protocol check macros... */

#define IPQ_SRC_HAS_PROTOCOL(src,protocol) ((src) != NULL && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK((src)->detected_protocol_bitmask,(protocol)) != 0)

#define IPQ_DST_HAS_PROTOCOL(dst,protocol) ((dst) != NULL && IPOQUE_COMPARE_PROTOCOL_TO_BITMASK((dst)->detected_protocol_bitmask,(protocol)) != 0)

#define IPQ_SRC_OR_DST_HAS_PROTOCOL(src,dst,protocol) (IPQ_SRC_HAS_PROTOCOL(src,protocol) || IPQ_SRC_HAS_PROTOCOL(dst,protocol))

/* misc definitions */
#define IPOQUE_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE 0x10000


/* TODO: rebuild all memory areas to have a more aligned memory block here */



/* DEFINITION OF MAX LINE NUMBERS FOR line parse algorithm */
#define IPOQUE_MAX_PARSE_LINES_PER_PACKET 200

#define IPOQUE_DIRECTCONNECT_CONNECTION_IP_TICK_TIMEOUT          600

#define IPOQUE_GADGADU_PEER_CONNECTION_TIMEOUT        		 120
#define IPOQUE_EDONKEY_UPPER_PORTS_ONLY                          0
#define IPOQUE_FTP_CONNECTION_TIMEOUT                            5
#define IPOQUE_IMESH_CONNECTION_TIMEOUT                          5
#define IPOQUE_PPLIVE_CONNECTION_TIMEOUT                         120
#define IPOQUE_IRC_CONNECTION_TIMEOUT                            120
#define IPOQUE_GNUTELLA_CONNECTION_TIMEOUT                       60
#define IPOQUE_BATTLEFIELD_CONNECTION_TIMEOUT                    60
#define IPOQUE_THUNDER_CONNECTION_TIMEOUT                        30
#define IPOQUE_RTSP_CONNECTION_TIMEOUT                           5
#define IPOQUE_TVANTS_CONNECTION_TIMEOUT                         5
#define IPOQUE_YAHOO_DETECT_HTTP_CONNECTIONS                     1
#define IPOQUE_YAHOO_LAN_VIDEO_TIMEOUT                           30
#define IPOQUE_ZATTOO_CONNECTION_TIMEOUT                         120
#define IPOQUE_JABBER_STUN_TIMEOUT                               30
#define IPOQUE_JABBER_FT_TIMEOUT								 5
#define IPOQUE_SOULSEEK_CONNECTION_IP_TICK_TIMEOUT               600
#define IPOQUE_MANOLITO_SUBSCRIBER_TIMEOUT                       120

#ifdef IPOQUE_ENABLE_DEBUG_MESSAGES


#define IPQ_LOG_BITTORRENT(proto, mod, log_level, args...) \
    IPQ_LOG(proto,mod,log_level,args)

#define IPQ_LOG_GNUTELLA(proto, mod, log_level, args...) \
    IPQ_LOG(proto,mod,log_level,args)

#define IPQ_LOG_EDONKEY(proto, mod, log_level, args...) \
    IPQ_LOG(proto,mod,log_level,args)
#define IPQ_LOG(proto, mod, log_level, args...)                   \
{                                                                 \
    if(mod != NULL) {                                             \
      mod->ipoque_debug_print_file=__FILE__;                      \
      mod->ipoque_debug_print_function=__FUNCTION__;              \
      mod->ipoque_debug_print_line=__LINE__;                      \
      mod->ipoque_debug_printf(proto, mod, log_level, args);      \
    }                                                             \
}


#else							/* IPOQUE_ENABLE_DEBUG_MESSAGES */

#define IPQ_LOG_BITTORRENT(proto, mod, log_level, args...) {}

#define IPQ_LOG_GNUTELLA(proto, mod, log_level, args...) {}

#define IPQ_LOG_EDONKEY(proto, mod, log_level, args...) {}
#define IPQ_LOG(proto, mod, log_level, args...) {}

#endif							/* IPOQUE_ENABLE_DEBUG_MESSAGES */
typedef struct ipq_call_function_struct {
	IPOQUE_PROTOCOL_BITMASK detection_bitmask;
	IPOQUE_PROTOCOL_BITMASK excluded_protocol_bitmask;
	IPQ_SELECTION_BITMASK_PROTOCOL_SIZE ipq_selection_bitmask;
	void (*func) (struct ipoque_detection_module_struct *);
} ipq_call_function_struct_t;


typedef struct ipoque_int_one_line_struct {
	const u8 *ptr;
	u16 len;
} ipoque_int_one_line_struct_t;

typedef struct ipoque_packet_struct {
	const struct iphdr *iph;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	const u8 *payload;
	IPOQUE_TIMESTAMP_COUNTER_SIZE tick_timestamp;
	u32 detected_protocol;
	u16 l3_packet_len;
	u16 l4_packet_len;
	u16 payload_packet_len;
	u16 actual_payload_len;
	u16 num_retried_bytes;
	u8 packet_direction;
	u8 tcp_retransmission;
	u8 detected_sub_protocol;

	u8 packet_lines_parsed_complete;
	u8 packet_unix_lines_parsed_complete;
	u8 empty_line_position_set;
	u16 parsed_lines;
	u16 parsed_unix_lines;
	u16 empty_line_position;
	struct ipoque_int_one_line_struct line[IPOQUE_MAX_PARSE_LINES_PER_PACKET];
	struct ipoque_int_one_line_struct
	 unix_line[IPOQUE_MAX_PARSE_LINES_PER_PACKET];
	struct ipoque_int_one_line_struct host_line;
	struct ipoque_int_one_line_struct referer_line;
	struct ipoque_int_one_line_struct content_line;
	struct ipoque_int_one_line_struct accept_line;
	struct ipoque_int_one_line_struct user_agent_line;
	struct ipoque_int_one_line_struct http_url_name;
	struct ipoque_int_one_line_struct http_encoding;
	struct ipoque_int_one_line_struct http_transfer_encoding;
	struct ipoque_int_one_line_struct http_contentlen;
	struct ipoque_int_one_line_struct http_cookie;
	struct ipoque_int_one_line_struct http_x_session_type;
} ipoque_packet_struct_t;


typedef struct ipoque_detection_module_struct {
	IPOQUE_PROTOCOL_BITMASK detection_bitmask;
	IPOQUE_PROTOCOL_BITMASK generic_http_packet_bitmask;

	IPOQUE_TIMESTAMP_COUNTER_SIZE current_ts;
	u32 ticks_per_second;

#ifdef IPOQUE_ENABLE_DEBUG_MESSAGES
	void *user_data;
#endif
	/* internal structures to save functions calls */
	struct ipoque_packet_struct packet;
	struct ipoque_flow_struct *flow;
	struct ipoque_id_struct *src;
	struct ipoque_id_struct *dst;
	/* callback function buffer */
	struct ipq_call_function_struct
	 callback_buffer[IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1];
	u32 callback_buffer_size;

	struct ipq_call_function_struct
	 callback_buffer_tcp_no_payload[IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1];
	u32 callback_buffer_size_tcp_no_payload;

	struct ipq_call_function_struct
	 callback_buffer_tcp_payload[IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1];
	u32 callback_buffer_size_tcp_payload;


	struct ipq_call_function_struct
	 callback_buffer_udp[IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1];
	u32 callback_buffer_size_udp;

	struct ipq_call_function_struct
	 callback_buffer_non_tcp_udp[IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1];
	u32 callback_buffer_size_non_tcp_udp;
#ifdef IPOQUE_ENABLE_DEBUG_MESSAGES
	/* debug callback, only set when debug is used */
	ipoque_debug_function_ptr ipoque_debug_printf;
	const char *ipoque_debug_print_file;
	const char *ipoque_debug_print_function;
	u32 ipoque_debug_print_line;
#endif
	void (*direct_download_link_counter_callback) (u32 ddl_id, u16 packet_size);
	/* misc parameters */
	u32 tcp_max_retransmission_window_size;

	u32 edonkey_upper_ports_only:1;
	u32 edonkey_safe_mode:1;
	u32 directconnect_connection_ip_tick_timeout;

/*gadu gadu*/
	u32 gadugadu_peer_connection_timeout;
	/* pplive params */
	u32 pplive_connection_timeout;
	/* ftp parameters */
	u32 ftp_connection_timeout;
	/* irc parameters */
	u32 irc_timeout;
	/* gnutella parameters */
	u32 gnutella_timeout;
	/* battlefield parameters */
	u32 battlefield_timeout;
	/* thunder parameters */
	u32 thunder_timeout;
	/* iMesh parameters */
	u32 imesh_connection_timeout;
	/* SoulSeek parameters */
	u32 soulseek_connection_ip_tick_timeout;
	/* rtsp parameters */
	u32 rtsp_connection_timeout;
	/* tvants parameters */
	u32 tvants_connection_timeout;
	u32 orb_rstp_ts_timeout;
	/* yahoo */
//      u32 yahoo_http_filetransfer_timeout;
	u8 yahoo_detect_http_connections;
	u32 yahoo_lan_video_timeout;
	u32 zattoo_connection_timeout;
	u32 jabber_stun_timeout;
	u32 jabber_file_transfer_timeout;
	u32 manolito_subscriber_timeout;
} ipoque_detection_module_struct_t;
u32 ipq_bytestream_to_number(const u8 * str, u16 max_chars_to_read, u16 * bytes_read);
u64 ipq_bytestream_to_number64(const u8 * str, u16 max_chars_to_read, u16 * bytes_read);

u32 ipq_bytestream_dec_or_hex_to_number(const u8 * str, u16 max_chars_to_read, u16 * bytes_read);
u64 ipq_bytestream_dec_or_hex_to_number64(const u8 * str, u16 max_chars_to_read, u16 * bytes_read);

u32 ipq_bytestream_to_ipv4(const u8 * str, u16 max_chars_to_read, u16 * bytes_read);


/* function to parse a packet which has line based information into a line based structure
 * this function will also set some well known line pointers like:
 *  - host, user agent, empty line,....
 */
void ipq_parse_packet_line_info(struct ipoque_detection_module_struct
								*ipoque_struct);

void ipq_parse_packet_line_info_unix(struct ipoque_detection_module_struct
									 *ipoque_struct);

u16 ipoque_check_for_email_address(struct ipoque_detection_module_struct *ipoque_struct, u16 counter);
#endif							/* __IPOQUE_MAIN_INCLUDE_FILE__ */
