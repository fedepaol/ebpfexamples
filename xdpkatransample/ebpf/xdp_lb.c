// go:build ignore

#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 1
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct arguments
{
  __u8 dst_mac[6];
  __u32 daddr;
  __u32 saddr;
  __u32 vip;
};

struct arguments *unused __attribute__((unused));

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_MAP_ENTRIES);
  __type(key, __u32);
  __type(value, struct arguments);
} xdp_params_array SEC(".maps");

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
    __u64 csum)
{
  int i;
#pragma unroll
  for (i = 0; i < 4; i++)
  {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__)) static inline void ipv4_csum_inline(
    void *iph,
    __u64 *csum)
{
  __u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++)
  {
    *csum += *next_iph_u16++;
  }
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv4_csum(void* data_start, int data_size, __u64* csum) {
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void create_v4_hdr(
    struct iphdr *iph,
    __u32 saddr,
    __u32 daddr,
    __u16 pkt_bytes,
    __u8 proto)
{
  __u64 csum = 0;
  iph->version = 4;
  iph->ihl = 5;
  iph->frag_off = 0;
  iph->protocol = proto;
  iph->check = 0;

  iph->tot_len = bpf_htons(pkt_bytes + sizeof(struct iphdr));
  iph->daddr = daddr;
  iph->saddr = saddr;
  iph->ttl = 64;
  ipv4_csum_inline(iph, &csum);
  iph->check = csum;
}

__attribute__((__always_inline__)) static inline bool encap_v4(
    struct xdp_md *xdp,
    __u8 dst_mac[],
    __u32 saddr,
    __u32 daddr,
    __u32 pkt_bytes)
{
  void *data;
  void *data_end;
  struct iphdr *iph;
  struct ethhdr *new_eth;
  struct ethhdr *old_eth;

  __u64 csum = 0;
  // ipip encap
  if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr)))
  {
    return false;
  }
  data = (void *)(long)xdp->data;
  data_end = (void *)(long)xdp->data_end;
  new_eth = data;
  iph = data + sizeof(struct ethhdr);
  old_eth = data + sizeof(struct iphdr);
  if ((void *)new_eth + 1 > data_end || (void *)old_eth + 1 > data_end || (void *)iph + (sizeof(struct iphdr)) > data_end)
  {
    return false;
  }
  memcpy(new_eth->h_dest, dst_mac, 6);
  if (old_eth->h_dest + 6 > data_end)
  {
    return false;
  }
  memcpy(new_eth->h_source, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IP;

  create_v4_hdr(
      iph,
      saddr,
      daddr,
      pkt_bytes,
      IPPROTO_IPIP);

  return true;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  nh_off = sizeof(struct ethhdr);

  if (data + nh_off + 1 > data_end)
  {
    return XDP_DROP;
  }
  eth_proto = eth->h_proto;
  if (eth_proto == BE_ETH_P_IPV6)
  {
    return XDP_PASS;
  }

  bpf_printk("got a packet");

  struct iphdr *iph;

  iph = data + sizeof(struct ethhdr);
  if ((iph + 1) > data_end)
  {
    bpf_printk("malformed");
    return XDP_DROP;
  }

  if (iph->protocol != IPPROTO_TCP)
  {
    bpf_printk("not tcp");
    return XDP_PASS;
  }

  __u32 payload_len = bpf_ntohs(iph->tot_len);

  struct arguments *args = 0;
  __u32 key = 0;
  args = (struct arguments *)bpf_map_lookup_elem(&xdp_params_array, &key);
  if (!args)
  {
    bpf_printk("no args");
    return XDP_PASS;
  }

  bpf_printk("Args: dstmac[%d] daddr[%u] saddr[%u] vip [%u]", args->dst_mac, args->daddr, args->saddr, args->vip);
  if (args->vip != bpf_htonl(iph->daddr))
  {
    bpf_printk("Not vip addr %u %u %u", bpf_ntohl(iph->daddr), iph->daddr, bpf_htonl(iph->daddr));
    return XDP_PASS;
  }
  bool res = encap_v4(ctx, args->dst_mac, bpf_htonl(args->saddr), bpf_htonl(args->daddr), payload_len);
  bpf_printk("sending back %d", res);
  return XDP_TX;
}
