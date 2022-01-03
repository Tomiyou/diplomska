#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "xfe_types.h"

int main() {
    int err;
    int map_fd;
    __u32 key = 37;
    struct xfe_flow value;
    struct xfe_flow _value = {
        .stats = 25
    };

    map_fd = bpf_obj_get("/sys/fs/bpf/xfe/xfe_flows");
    if (map_fd < 0) {
        printf("Error obtaining map FD\n");
        return -1;
    }

    err = bpf_map_update_elem(map_fd, &key, &_value, 0);
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

    printf("Looked up value: %d\n", value.stats);

    close(map_fd);

    printf("Successful lookup\n");
    return 0;
}
