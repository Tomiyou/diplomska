/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/types.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

/* BPF stuff */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Debug logging */
#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
	static const char ____fmt[] = fmt;              \
	bpf_trace_printk(____fmt, sizeof(____fmt),      \
			 ##__VA_ARGS__);                \
})

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

/* Parse ethernet header */
static __always_inline struct ethhdr *parse_ethhdr(void *data_start,
						   void *data_end)
{
	struct ethhdr *eth_hdr = data_start;
	int hdr_size = sizeof(*eth_hdr);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return eth_hdr; /* network-byte-order */
}

/* Parse IPv4 header */
static __always_inline struct iphdr *parse_iphdr(void *data_start,
						 void *data_end)
{
	struct iphdr *ip_hdr = data_start;
	int hdr_size = sizeof(*ip_hdr);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return ip_hdr; /* network-byte-order */
}

/* Parse TCP header */
static __always_inline struct tcphdr *parse_tcphdr(void *data_start,
						   void *data_end)
{
	struct tcphdr *tcp_header = data_start;
	int hdr_size = sizeof(*tcp_header);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return tcp_header; /* network-byte-order */
}

/* IPv4 */
__attribute__((__always_inline__))
static inline __u16 csum_fold_helper1(__u64 csum) {
	int i;
	#pragma unroll
	for (i = 0; i < 4; i ++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

__attribute__((__always_inline__))
static inline void ipv4_csum(void *data_start, int data_size,  __u64 *csum) {
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper1(*csum);
}

/* L4 */
static __always_inline uint32_t csum_add(uint32_t addend, uint32_t csum) 
{
	uint32_t res = csum;
	res += addend;
	return (res + (res < addend));
}

static __always_inline uint32_t csum_sub(uint32_t addend, uint32_t csum) 
{
	return csum_add(csum, ~addend);
}

static __always_inline uint16_t csum_fold_helper2(uint32_t csum) 
{
	uint32_t r = csum << 16 | csum >> 16;
	csum = ~csum;
	csum -= r;
	return (uint16_t)(csum >> 16);
}

static __always_inline uint16_t csum_diff4(uint32_t from, uint32_t to, uint16_t csum) 
{
	uint32_t tmp = csum_sub(from, ~((uint32_t)csum));
	return csum_fold_helper2(csum_add(to, tmp));
}

SEC("ingress")
int xfe_ingress_fn(struct xdp_md *ctx)
{
	void *data_start = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *frame_pointer = data_start;

	/* Packet headers */
	struct ethhdr *eth_hdr;
	struct iphdr *ip_hdr;

	/* Default action */
	long action = XDP_PASS;

	__u32 xmit_ifindex = 0;

	/* Parse ethernet header */
	eth_hdr = parse_ethhdr(frame_pointer, data_end);
	if (eth_hdr == NULL) {
		goto out;
	}
	/* Move frame pointer */
	frame_pointer += sizeof(*eth_hdr);

	/* Only allow IPv4 packets through */
	if (eth_hdr->h_proto != bpf_htons(ETH_P_IP)) {
		goto out;
	}

	/* Parse IPv4 header */
	ip_hdr = parse_iphdr(frame_pointer, data_end);
	if (ip_hdr == NULL) {
		goto out;
	}
	/* Move frame pointer */
	frame_pointer += sizeof(*ip_hdr);

	if (ip_hdr->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp_hdr;

		/* Parse TCP header */
		tcp_hdr = parse_tcphdr(frame_pointer, data_end);
		if (tcp_hdr == NULL) {
			goto out;
		}
		/* Move frame pointer */
		frame_pointer += sizeof(*tcp_hdr);

		__be16 orig_src = tcp_hdr->dest;
		__be16 orig_dst = tcp_hdr->source;

		if (ctx->ingress_ifindex == 5) {
			// ip_hdr->daddr = 0x164a8c0;
			// ip_hdr->saddr = 0x264a8c0;
			// ip_hdr->ttl = ip_hdr->ttl - 1;
			// ip_hdr->check = 0x7cf4;

			/* L3 header */
			tcp_hdr->check = csum_diff4(ip_hdr->daddr, 0x164a8c0, tcp_hdr->check);
			ip_hdr->daddr = 0x164a8c0;
			tcp_hdr->check = csum_diff4(ip_hdr->saddr, 0x264a8c0, tcp_hdr->check);
			ip_hdr->saddr = 0x264a8c0;
		} else {
			tcp_hdr->check = csum_diff4(ip_hdr->daddr, 0x20aa8c0, tcp_hdr->check);
			ip_hdr->daddr = 0x20aa8c0;
			tcp_hdr->check = csum_diff4(ip_hdr->saddr, 0x164a8c0, tcp_hdr->check);
			ip_hdr->saddr = 0x164a8c0;
		}
		ip_hdr->ttl = ip_hdr->ttl - 1;

		/* L4 header */
		tcp_hdr->check = csum_diff4(tcp_hdr->source, orig_dst, tcp_hdr->check);
		tcp_hdr->source = orig_dst;
		tcp_hdr->check = csum_diff4(tcp_hdr->dest, orig_src, tcp_hdr->check);
		tcp_hdr->dest = orig_src;
	} else {
		goto out;
	}

	/* IPv4 checksum */
	ip_hdr->check = 0;
	__u64 ip_csum = 0;
	ipv4_csum(ip_hdr, sizeof(*ip_hdr), &ip_csum);
	ip_hdr->check = ip_csum;

	if (ctx->ingress_ifindex == 5) {
		xmit_ifindex = 3;
		eth_hdr->h_source[0] = 0x98;
		eth_hdr->h_source[1] = 0xb7;
		eth_hdr->h_source[2] = 0x85;
		eth_hdr->h_source[3] = 0x89;
		eth_hdr->h_source[4] = 0x78;
		eth_hdr->h_source[5] = 0xe0;
		eth_hdr->h_dest[0] = 0x00;
		eth_hdr->h_dest[1] = 0x30;
		eth_hdr->h_dest[2] = 0x93;
		eth_hdr->h_dest[3] = 0x10;
		eth_hdr->h_dest[4] = 0x3d;
		eth_hdr->h_dest[5] = 0x95;
	} else {
		xmit_ifindex = 5;
		eth_hdr->h_source[0] = 0x98;
		eth_hdr->h_source[1] = 0xb7;
		eth_hdr->h_source[2] = 0x85;
		eth_hdr->h_source[3] = 0x89;
		eth_hdr->h_source[4] = 0x78;
		eth_hdr->h_source[5] = 0xba;
		eth_hdr->h_dest[0] = 0x00;
		eth_hdr->h_dest[1] = 0x30;
		eth_hdr->h_dest[2] = 0x93;
		eth_hdr->h_dest[3] = 0x10;
		eth_hdr->h_dest[4] = 0x1b;
		eth_hdr->h_dest[5] = 0xcf;
	}

	// bpf_printk("L2 %x:%x:%x", eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2]);
	// bpf_printk("   %x:%x:%x ->", eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
	// bpf_printk("   %x:%x:%x", eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2]);
	// bpf_printk("   %x:%x:%x", eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
	// bpf_printk("L3 %x %x %x", ip_hdr->daddr, ip_hdr->saddr, ip_hdr->check);

	/* Redirect the packet to the correct output interface */
	action = bpf_redirect(xmit_ifindex, 0);
	if (action == XDP_ABORTED) {
		// bpf_printk("Redirect did not go through %d %ld\n", xmit_ifindex, action);
	}

	// bpf_printk("forward %u %u", ctx->ingress_ifindex, xmit_ifindex);

out:
	return action;
}

char _license[] SEC("license") = "GPL";
