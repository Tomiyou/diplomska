#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <stdbool.h>

enum xfe_nl_msg_type {
	XFE_MSG_MAP_FD,
	XFE_MSG_MAP_LOOKUP,
	XFE_MSG_MAP_DELETE,
	XFE_MSG_MAP_UPDATE
};

struct xfe_nl_msg {
	enum xfe_nl_msg_type msg_type;
	unsigned int msg_value;
};

struct xfe_flow {
	struct bpf_spin_lock lock;		/* Spinlock for every entry */

	/* Fields for matching packet to a flow */
	__u32 match_if_index;			/* Network device */
	unsigned char match_dst_mac[ETH_ALEN];	/* Destination MAC */
	__be16 match_eth_proto;			/* Ethernet protocol */
	__u8   match_ip_proto;			/* IP protocol */
	__be32 match_src_ip;			/* Source IP address */
	__be32 match_dest_ip;			/* Destination IP address */
	__be16 match_src_port;			/* Source port/connection ident */
	__be16 match_dest_port;			/* Destination port/connection ident */

	/* Remember if we need to do NAT */
	bool do_xlate;

	/* Fields for translating a packet */
	__u32 dest_if_index;			/* Network device */
	unsigned char apply_dst_mac[ETH_ALEN];	/* Destination MAC */
	__be16 apply_eth_proto;			/* Ethernet protocol */
	__u8   apply_ip_proto;			/* IP protocol */
	__be32 apply_src_ip;			/* Source IP address */
	__be32 apply_dest_ip;			/* Destination IP address */
	__be16 apply_src_port;			/* Source port/connection ident */
	__be16 apply_dest_port;			/* Destination port/connection ident */

	/* Stats */
	__u32 rx_packet_count;
	__u32 rx_byte_count;

	/* QoS information */
	__u8 tos;
};
