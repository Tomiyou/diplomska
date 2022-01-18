/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

/* BPF stuff */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xfe_types.h"

/* Lesson: See how a map is defined.
 * - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
struct bpf_map_def SEC("maps") xfe_flows = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct xfe_flow),
	.max_entries = 254,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

/* Map hash lookup */
#define SFE_IPV4_CONNECTION_HASH_SHIFT 12
#define SFE_IPV4_CONNECTION_HASH_SIZE (1 << SFE_IPV4_CONNECTION_HASH_SHIFT)
#define SFE_IPV4_CONNECTION_HASH_MASK (SFE_IPV4_CONNECTION_HASH_SIZE - 1)

static __always_inline __u32 get_flow_hash(
	__u32 match_if_index,
	unsigned char match_dst_mac[ETH_ALEN],
	__be16 match_eth_proto,
	__u8   match_ip_proto,
	__be32 match_src_ip,
	__be32 match_dest_ip,
	__be16 match_src_port,
	__be16 match_dest_port
)
{
	size_t dev_addr = (size_t)dev;
	u32 hash = ((u32)dev_addr) ^ ntohl(src_ip ^ dest_ip) ^ protocol ^ ntohs(src_port ^ dest_port);
	return ((hash >> SFE_IPV4_CONNECTION_HASH_SHIFT) ^ hash) & SFE_IPV4_CONNECTION_HASH_MASK;
}

/* Parse ethernet header */
static __always_inline struct ethhdr *parse_ethhdr(void *data_start,
						   void *data_end)
{
	struct ethhdr *eth_header = data_start;
	int hdr_size = sizeof(*eth_header);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return eth_header; /* network-byte-order */
}

/* Parse IPv4 header */
static __always_inline struct iphdr *parse_iphdr(void *data_start,
						 void *data_end)
{
	struct iphdr *ip_header = data_start;
	int hdr_size = sizeof(*ip_header);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return ip_header; /* network-byte-order */
}

/* Parse UDP header */
static __always_inline struct udphdr *parse_udphdr(void *data_start,
						   void *data_end)
{
	struct udphdr *udp_header = data_start;
	int hdr_size = sizeof(*udp_header);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return udp_header; /* network-byte-order */
}

SEC("xfe_ingress")
int xfe_ingress_fn(struct xdp_md *ctx)
{
	void *data_start = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *frame_pointer = data_start;

	/* Packet headers */
	struct ethhdr *eth_header;
	struct iphdr *ip_header;
	struct udphdr *udp_header;

	/* Default action */
	__u32 action = XDP_PASS;

	/* Parse ethernet header */
	eth_header = parse_ethhdr(frame_pointer, data_end);
	if (eth_header == NULL)
		goto out;
	/* Move frame pointer */
	frame_pointer += sizeof(*eth_header);

	/* Only allow IPv4 packets through */
	if (eth_header->h_proto != bpf_htons(ETH_P_IP))
		goto out;

	/* Parse IPv4 header */
	ip_header = parse_iphdr(frame_pointer, data_end);
	if (eth_header == NULL)
		goto out;
	/* Move frame pointer */
	frame_pointer += sizeof(*ip_header);

	/* Only allow UDP packets through */
	if (ip_header->protocol != bpf_htons(IPPROTO_UDP))
		goto out;

	/* Parse UDP header */
	udp_header = parse_udphdr(frame_pointer, data_end);
	if (eth_header == NULL)
		goto out;
	/* Move frame pointer */
	frame_pointer += sizeof(*udp_header);

	/* Ready to process UDP packet */
out:
	return action;
}

char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 *
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 *
struct xdp_md {
	// (Note: type __u32 is NOT the real-type)
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	// Below access go through struct xdp_rxq_info
	__u32 ingress_ifindex; // rxq->dev->ifindex
	__u32 rx_queue_index;  // rxq->queue_index
};
*/
