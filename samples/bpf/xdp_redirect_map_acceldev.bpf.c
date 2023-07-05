// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"
#include "qat_xdp_acceldata.h"

#define ACCELDEV_NUM_DEFAULT (128)
#define KEY_ERROR_CODE (0xFFFFFFFF)

#define PRINT_ACCELDEV_LOG(...)
/* #define PRINT_ACCELDEV_LOG(...) bpf_printk(__VA_ARGS__); */

struct {
        __uint(type, BPF_MAP_TYPE_XSKMAP);
        __uint(max_entries, 4);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(int));
} xsks_map_chained_acceldev SEC(".maps");

SEC("xdp_sock") int xdp_sock_for_acceldev_prog(struct xdp_md *ctx)
{
	PRINT_ACCELDEV_LOG("=====================%s start xdp_sock_for_acceldev_prog", __func__);

	/* Hard coded queue 0 for test */
	return bpf_redirect_map(&xsks_map_chained_acceldev, 0, 0);
}

extern u32 bpf_xdp_inst_index(struct xdp_md *xdp_md) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(long));
	__uint(value_size, sizeof(struct bpf_acceldevmap_val) + sizeof(struct qat_xdp_acceldata));
	__uint(map_flags, BPF_F_ACCELDEVMAP_HASH);
	__uint(max_entries, ACCELDEV_NUM_DEFAULT);
} acceldev_redirect_map SEC(".maps");

static __always_inline
bool parse_eth(struct ethhdr *eth, void *data_end,
	       u16 *eth_proto, u64 *l3_offset)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;

	/* Skip non 802.3 Ethertypes */
	if (__builtin_expect(bpf_ntohs(eth_type) < ETH_P_802_3_MIN, 0))
		return false;

	/* Handle VLAN tagged packet */
	if (eth_type == bpf_htons(ETH_P_8021Q) ||
	    eth_type == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}
	/* Handle double VLAN tagged packet */
	if (eth_type == bpf_htons(ETH_P_8021Q) ||
	    eth_type == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = bpf_ntohs(eth_type);
	*l3_offset = offset;
	return true;
}

static __always_inline
int get_proto_ipv4(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->protocol;
}

static __always_inline
int get_proto_ipv6(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;
	return ip6h->nexthdr;
}

SEC("xdp")
int xdp_acceldev_preprocess(struct xdp_md *ctx)
{
	u64 key = 0;
	u64 nh_off;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	u16 eth_type;
	u16 eth_proto = 0;
	u64 l3_offset = 0;
	u8 ip_proto = IPPROTO_UDP;
	u32 spi = 0;

	PRINT_ACCELDEV_LOG("=====================%s start", __func__);

	if (data + sizeof(struct ethhdr) > data_end) {
		PRINT_ACCELDEV_LOG("Error : data + sizeof(struct ethhdr) > data_end");
		PRINT_ACCELDEV_LOG("=====================%s end (Do nothing)\n", __func__);
		return XDP_PASS;
	}

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		PRINT_ACCELDEV_LOG("parse_eth() : XDP_PASS");
		PRINT_ACCELDEV_LOG("=====================%s end (Do nothing)\n", __func__);
		return XDP_PASS; /* Just skip */
	}

	nh_off = sizeof(*eth);
	eth_type = eth->h_proto;

	PRINT_ACCELDEV_LOG("[h_source : %x %x %x %x %x %x]", eth->h_source[0],
			   eth->h_source[1],
			eth->h_source[2],
			eth->h_source[3],
			eth->h_source[4],
			eth->h_source[5]);
	PRINT_ACCELDEV_LOG("[h_dest : %x %x %x %x %x %x]",
			   eth->h_dest[0],
			eth->h_dest[1],
			eth->h_dest[2],
			eth->h_dest[3],
			eth->h_dest[4],
			eth->h_dest[5]);
	PRINT_ACCELDEV_LOG("[eth_type : %d]", eth_type);
	PRINT_ACCELDEV_LOG("[sizeof(struct ethhdr) : %d]", sizeof(struct ethhdr));
	PRINT_ACCELDEV_LOG("[data is : %p]", data);
	PRINT_ACCELDEV_LOG("[eth is : %p]", eth);
	PRINT_ACCELDEV_LOG("[ctx is : %p]", ctx);

	/* Get eth protocol */
	switch (eth_proto) {
	case ETH_P_IP:
			PRINT_ACCELDEV_LOG("eth_proto is ETH_P_IP");
			ip_proto = get_proto_ipv4(ctx, l3_offset);
			break;
	case ETH_P_IPV6:
			PRINT_ACCELDEV_LOG("eth_proto is ETH_P_IPV6");
			ip_proto = get_proto_ipv6(ctx, l3_offset);
			break;
	default:
			PRINT_ACCELDEV_LOG("Not ETH_P_IP or ETH_P_IPV6, return XDP_PASS");
			PRINT_ACCELDEV_LOG("=====================%s end (Do nothing)\n", __func__);
			return XDP_PASS;
	}

	/* Do redirect if ESP protocol */
	switch (ip_proto) {
	case IPPROTO_ESP:
			PRINT_ACCELDEV_LOG("ip_proto is IPPROTO_ESP, continue to redirect");
			break;
	default:
			PRINT_ACCELDEV_LOG("ip_proto is not IPPROTO_ESP, return XDP_PASS");
			PRINT_ACCELDEV_LOG("=====================%s end (Do nothing)\n", __func__);
			return XDP_PASS;
	}

	/* Get key */
	key = bpf_xdp_inst_index(ctx);
	if (KEY_ERROR_CODE == (KEY_ERROR_CODE & key)) {
		PRINT_ACCELDEV_LOG("Error : get key failed(0x%x)", key);
		return XDP_PASS;
	}
	key = key << 32;
	PRINT_ACCELDEV_LOG("%s get key by bpf_xdp_inst_index() : %llX", __func__, key);
	PRINT_ACCELDEV_LOG("=====================%s end\n", __func__);

	return bpf_redirect_map(&acceldev_redirect_map, key, 0);
}

SEC("xdp")
int xdp_acceldev_postprocess(struct xdp_md *ctx)
{
	u64 nh_off;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	u16 eth_type;
	u16 eth_proto = 0;
	u64 l3_offset = 0;

	PRINT_ACCELDEV_LOG("=====================%s start", __func__);

	if (data + sizeof(struct ethhdr) > data_end) {
		PRINT_ACCELDEV_LOG("Error : data + sizeof(struct ethhdr) > data_end");
		PRINT_ACCELDEV_LOG("=====================%s end (Do nothing)\n", __func__);
		return XDP_PASS;
	}

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		PRINT_ACCELDEV_LOG("parse_eth() : XDP_PASS");
		PRINT_ACCELDEV_LOG("=====================%s end (Do nothing)\n", __func__);
		return XDP_PASS; /* Just skip */
	}

	nh_off = sizeof(*eth);
	eth_type = eth->h_proto;

	PRINT_ACCELDEV_LOG("[h_source : %x %x %x %x %x %x]", eth->h_source[0],
			   eth->h_source[1],
			eth->h_source[2],
			eth->h_source[3],
			eth->h_source[4],
			eth->h_source[5]);
	PRINT_ACCELDEV_LOG("[h_dest : %x %x %x %x %x %x]",
			   eth->h_dest[0],
			eth->h_dest[1],
			eth->h_dest[2],
			eth->h_dest[3],
			eth->h_dest[4],
			eth->h_dest[5]);
	PRINT_ACCELDEV_LOG("[eth_type : %d]", eth_type);
	PRINT_ACCELDEV_LOG("[sizeof(struct ethhdr) : %d]", sizeof(struct ethhdr));
	PRINT_ACCELDEV_LOG("[data is : %p]", data);
	PRINT_ACCELDEV_LOG("[eth is : %p]", eth);
	PRINT_ACCELDEV_LOG("[ctx is : %p]", ctx);
	PRINT_ACCELDEV_LOG("=====================%s end\n", __func__);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
