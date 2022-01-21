#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <string.h>

#include "xfe_types.h"

int main() {
    int err;
    int map_fd;
    __u32 key = 27;
    struct xfe_flow flow = {};
    struct xfe_flow value = {};

    memset(&flow, 0, sizeof(struct xfe_flow));
    flow.match_if_index = 3;
    flow.match_eth_proto = htons(ETH_P_IP);
    flow.match_ip_proto = IPPROTO_UDP;
    flow.match_src_ip = htonl(0xc0a88702);
    flow.match_dest_ip = htonl(0xc0a88701);
    flow.match_dest_port = htons(0x82a);
    flow.is_bridged = false;
    flow.dest_if_index = 3;

    map_fd = bpf_obj_get("/sys/fs/bpf/xfe/xfe_flows");
    if (map_fd < 0) {
        printf("Error obtaining map FD\n");
        return -1;
    }

    err = bpf_map_update_elem(map_fd, &key, &flow, 0);
    if (err != 0) {
        printf("Error occured during update\n");
        close(map_fd);
        return -1;
    }

    err = bpf_map_lookup_elem(map_fd, &key, &value);
    if (err != 0) {
        printf("Error occured during lookup\n");
        close(map_fd);
        return -1;
    }

    printf("Looked up value: %d\n", value.rx_packet_count);

    close(map_fd);

    printf("Successful lookup\n");
    return 0;
}
