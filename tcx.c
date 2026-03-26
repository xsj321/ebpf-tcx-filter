//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_CAPTURE_SIZE 128
#define DIRECTION_INGRESS 1
#define DIRECTION_EGRESS 2
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
};

__u64 ingress_pkt_count = 0;
__u64 egress_pkt_count  = 0;

struct event {
	__u32 ifindex;
	__u32 pkt_len;
	__u32 cap_len;
	__u8 direction;
	__u8 dropped;
	__u8 data[MAX_CAPTURE_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
	__type(value, struct event);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} blocked_dst_v4 SEC(".maps");

static __always_inline int should_drop_egress_v4(struct __sk_buff *skb)
{
	struct ethhdr eth;
	struct iphdr iph;
	__u16 ether_type;
	__u32 l3_offset = sizeof(struct ethhdr);
	__u8 vlan_hdr[4];
	__u32 daddr;

	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
		return 0;

	ether_type = __builtin_bswap16(eth.h_proto);
	if (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD) {
		if (bpf_skb_load_bytes(skb, l3_offset, vlan_hdr, sizeof(vlan_hdr)) < 0)
			return 0;

		ether_type = ((__u16)vlan_hdr[2] << 8) | vlan_hdr[3];
		l3_offset += sizeof(vlan_hdr);
	}

	if (ether_type != ETH_P_IP)
		return 0;

	if (bpf_skb_load_bytes(skb, l3_offset, &iph, sizeof(iph)) < 0)
		return 0;

	if (iph.version != 4)
		return 0;

	daddr = __builtin_bswap32(iph.daddr);
	return bpf_map_lookup_elem(&blocked_dst_v4, &daddr) != 0;
}

static __always_inline void submit_skb_event(struct __sk_buff *skb, __u8 direction, __u8 dropped)
{
	struct event *event;
	__u32 cap_len = skb->len;

	if (cap_len > MAX_CAPTURE_SIZE)
		cap_len = MAX_CAPTURE_SIZE;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return;

	event->ifindex = skb->ifindex;
	event->pkt_len = skb->len;
	event->cap_len = cap_len;
	event->direction = direction;
	event->dropped = dropped;

	if (cap_len > 0 && bpf_skb_load_bytes(skb, 0, event->data, cap_len) < 0) {
		bpf_ringbuf_discard(event, 0);
		return;
	}

	bpf_ringbuf_submit(event, 0);
}

SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
	__sync_fetch_and_add(&ingress_pkt_count, 1);
	submit_skb_event(skb, DIRECTION_INGRESS, 0);
	return TC_ACT_OK;
}

SEC("tc")
int egress_prog_func(struct __sk_buff *skb) {
	__sync_fetch_and_add(&egress_pkt_count, 1);
	if (should_drop_egress_v4(skb)) {
		submit_skb_event(skb, DIRECTION_EGRESS, 1);
		return TC_ACT_SHOT;
	}

	submit_skb_event(skb, DIRECTION_EGRESS, 0);
	return TC_ACT_OK;
}
