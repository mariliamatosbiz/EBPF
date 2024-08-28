#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct ipv4_hdr {
    __u8 ihl;
    __u8 version;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

SEC("maps")
struct bpf_map_def SEC("maps") ip_count_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(__u64),
    .max_entries = 4096,
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 key;
    __u64 *ip_count;

    // Verifica se o pacote é grande o suficiente para ter um cabeçalho IPv4
    if ((data + sizeof(*eth) + sizeof(struct ipv4_hdr)) > data_end)
        goto out;

    struct ipv4_hdr *ip = data + sizeof(*eth);

    // Extrai o endereço IP de origem
    key = ip->saddr;

    // Incrementa a contagem de pacotes para esse IP
    ip_count = bpf_map_lookup_elem(&ip_count_map, &key);
    if (ip_count) {
        __u64 new_count = __sync_fetch_and_add(ip_count, 1);
        
        // Verifica se a nova contagem excede o limite
        if (new_count >= 10) {
            // Aqui você pode adicionar a lógica para lidar com IPs que excederam o limite
            // Por exemplo, registrar o evento ou tomar outras medidas
            // Note que ações mais complexas podem exigir comunicação com espaço de usuário ou outros mecanismos
        }
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&ip_count_map, &key, &init_val, BPF_ANY);
    }

out:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
