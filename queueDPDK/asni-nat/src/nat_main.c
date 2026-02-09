#include "nat_main.h"
#include <stdio.h>

struct FlowManager *flow_manager;
struct nf_config config;

bool nf_init(void) {

    // Setups the configuration
    config.start_port = 1024;
    // config.max_flows = 1024;
    config.max_flows = 16384;
    config.expiration_time = 60 * 1000000; // 60 seconds
    config.device_macs =
        calloc(rte_eth_dev_count_avail(), sizeof(struct rte_ether_addr));
    config.endpoint_macs =
        calloc(rte_eth_dev_count_avail(), sizeof(struct rte_ether_addr));
    for (uint8_t i = 0; i < rte_eth_dev_count_avail(); i++) {
        config.device_macs[i].addr_bytes[0] = 0x00;
        config.device_macs[i].addr_bytes[1] = 0x00;
        config.device_macs[i].addr_bytes[2] = 0x00;
        config.device_macs[i].addr_bytes[3] = 0x00;
        config.device_macs[i].addr_bytes[4] = 0x00;
        config.device_macs[i].addr_bytes[5] = i;

        config.endpoint_macs[i].addr_bytes[0] = 0x00;
        config.endpoint_macs[i].addr_bytes[1] = 0x00;
        config.endpoint_macs[i].addr_bytes[2] = 0x00;
        config.endpoint_macs[i].addr_bytes[3] = 0x00;
        config.endpoint_macs[i].addr_bytes[4] = 0x00;
        config.endpoint_macs[i].addr_bytes[5] = i;
    }
    config.external_addr = 1 << 24 | 1 << 16 | 1 << 8 | 1;
    config.wan_device = 2;
    config.lan_main_device = 0;

    flow_manager = flow_manager_allocate(
        config.start_port, config.external_addr, config.wan_device,
        config.expiration_time, config.max_flows);

    return flow_manager != NULL;
}
void uint32_to_ipv4(uint32_t ip, char *buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    // Convert the binary IP address to a string
    const char *result = inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
    if (result == NULL) {
        perror("inet_ntop");
    }
}
int nf_process(uint16_t device, uint8_t *payload, uint16_t ether_type,
               uint8_t ip_proto, uint32_t ip_src, uint32_t ip_dst,
               uint16_t port_src, uint16_t port_dst, vigor_time_t now) {
    //flow_manager_expire(flow_manager, now);

#ifdef ENABLE_LOG
    char ip_src_str[256];
    char ip_dst_str[256];
    uint32_to_ipv4(ip_src, ip_src_str);
    uint32_to_ipv4(ip_dst, ip_dst_str);
    // Convert the binary IP address to a string
    NF_DEBUG("Flows have been expired");
    NF_DEBUG("Ether-type %u", ether_type);
    NF_DEBUG("IP protocol %u", ip_proto);
    NF_DEBUG("IP source %s", ip_src_str);
    NF_DEBUG("IP destination %s", ip_dst_str);
    NF_DEBUG("Port source %u", htons(port_src));
    NF_DEBUG("Port destination %u", htons(port_dst));
#endif
    // Do simple pointer arithmetic to prepare headers
    struct rte_ether_hdr *rte_ether_header = (struct rte_ether_hdr *)payload;
    struct rte_ipv4_hdr *rte_ipv4_header =
        (struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr));
    struct tcpudp_hdr *tcpudp_header =
        (struct tcpudp_hdr *)(payload + sizeof(struct rte_ether_hdr) +
                              sizeof(struct rte_ipv4_hdr));

    // Check ethertype
    if (ether_type != 0x0800) {
        NF_DEBUG("Not IPv4, dropping");
        // printf("Not IPv4, dropping\n");
        // return EXPLICIT_DROP;
    }

    // Check IP protocol
    if (ip_proto != 0x06 && ip_proto != 0x11) {
        NF_DEBUG("Not TCP/UDP, dropping");
        // printf("Not TCP/UDP, dropping\n");
        // return EXPLICIT_DROP;
    }

    uint16_t dst_device;
    if (device == config.wan_device) {
        NF_DEBUG("Device %" PRIu16 " is external", device);

        struct FlowId internal_flow;
        if (flow_manager_get_external(flow_manager, port_dst, now,
                                      &internal_flow)) {
            NF_DEBUG("Found internal flow.");

            if (internal_flow.dst_ip != ip_src ||
                internal_flow.dst_port != port_dst ||
                internal_flow.protocol != ip_proto) {

                NF_DEBUG("Spoofing attempt, dropping.");
                // printf("spoofing attempt, dropping\n");
                // return EXPLICIT_DROP;
            }

            // This time we have no choice, we have to manually go into the
            // payload and change the IP and port
            rte_ipv4_header->dst_addr = internal_flow.src_ip;
            tcpudp_header->dst_port = internal_flow.src_port;
            dst_device = internal_flow.internal_device;
        } else {
            NF_DEBUG("Unknown flow, dropping");
            // printf("unknown flow, dropping\n");
            // return EXPLICIT_DROP;
        }
    } else {
        struct FlowId id = {.src_port = port_src,
                            .dst_port = port_dst,
                            .src_ip = ip_src,
                            .dst_ip = ip_dst,
                            .protocol = ip_proto,
                            .internal_device = device};
        NF_DEBUG("For id:");

        NF_DEBUG("Device %" PRIu16 " is internal (not %" PRIu16 ")", device,
                 config.wan_device);

        uint16_t external_port;
        if (!flow_manager_get_internal(flow_manager, &id, now,
                                       &external_port)) {
            NF_DEBUG("New flow");

            if (!flow_manager_allocate_flow(flow_manager, &id, device, now,
                                            &external_port)) {
                NF_DEBUG("No space for the flow, dropping");
                // printf("no space for the flow\n");
                // return EXPLICIT_DROP;
            }
        }
        NF_DEBUG("Forwarding from ext port:%d", external_port);
        // printf("Forwarding from ext port:%d\n", external_port);
        rte_ipv4_header->src_addr = config.external_addr;
        tcpudp_header->src_port = external_port;
        dst_device = config.wan_device;
    }
    // concretize_devices(&dst_device, 2);
    return dst_device;
}

// #ifdef WITH_XCHG
// int nf_process(uint16_t device, uint8_t *buffer, uint16_t
// packet_length,vigor_time_t now, struct descriptor *desc) #elif
// defined(WITH_DPDK) int nf_process(uint16_t device, uint8_t *buffer, uint16_t
// packet_length,vigor_time_t now) #endif
//   {
//   UNUSED(packet_length);
//   NF_DEBUG("It is %" PRId64, now);

//   flow_manager_expire(flow_manager, now);
//   NF_DEBUG("Flows have been expired");

//   struct rte_ether_hdr *rte_ether_header;
//   uint8_t *ip_options;
//   struct rte_ipv4_hdr *rte_ipv4_header;
//   struct tcpudp_hdr *tcpudp_header;
//   #ifdef WITH_DPDK
//   rte_ether_header = nf_then_get_rte_ether_header(buffer);
//   rte_ipv4_header = nf_then_get_rte_ipv4_header(rte_ether_header, buffer,
//   &ip_options); if (rte_ipv4_header == NULL) {
//     NF_DEBUG("Not IPv4, dropping");
//     return EXPLICIT_DROP;
//   }
//   tcpudp_header =
//       nf_then_get_tcpudp_header(rte_ipv4_header, buffer);
//   if (tcpudp_header == NULL) {
//     NF_DEBUG("Not TCP/UDP, dropping");
//     return EXPLICIT_DROP;
//   }
//   NF_DEBUG("Forwarding an IPv4 packet on device %" PRIu16, device);
//   NF_DEBUG("Source IP: %s", nf_rte_ipv4_to_str(rte_ipv4_header->src_addr));
//   NF_DEBUG("Destination IP: %s",
//   nf_rte_ipv4_to_str(rte_ipv4_header->dst_addr)); NF_DEBUG("Source port: %"
//   PRIu16, tcpudp_header->src_port); NF_DEBUG("Destination port: %" PRIu16,
//   tcpudp_header->dst_port); #elif defined(WITH_XCHG)
//   // Compute pointers
//   rte_ether_header = buffer;
//   tcpudp_header = (struct tcpudp_hdr *)(buffer + sizeof(struct
//   rte_ether_hdr)); rte_ipv4_header = (struct rte_ipv4_hdr *)(buffer +
//   sizeof(struct rte_ether_hdr));
//   // Check ethertype
//   if (desc->eth_type != 0x0800) {
//     NF_DEBUG("Not IPv4, dropping");
//     return EXPLICIT_DROP;
//   }
//   // Ensure UDP/TCP
//   if (desc->ip_proto != 0x06 && desc->ip_proto != 0x11) {
//     NF_DEBUG("Not TCP/UDP, dropping");
//     return EXPLICIT_DROP;
//   }
//   NF_DEBUG("Forwarding an IPv4 packet on device %" PRIu16, device);
//   NF_DEBUG("Source IP: %s", nf_rte_ipv4_to_str(desc->ip_src));
//   NF_DEBUG("Destination IP: %s", nf_rte_ipv4_to_str(desc->ip_dst));
//   NF_DEBUG("Source port: %" PRIu16, desc->port_src);
//   NF_DEBUG("Destination port: %" PRIu16, desc->port_dst);
//   #endif

//   uint16_t dst_device;
//   if (device == config.wan_device) {
//     NF_DEBUG("Device %" PRIu16 " is external", device);

//     struct FlowId internal_flow;
//     #ifdef WITH_DPDK
//     if (flow_manager_get_external(flow_manager, tcpudp_header->dst_port, now,
//     #elif defined(WITH_XCHG)
//     if (flow_manager_get_external(flow_manager, desc->port_dst, now,
//     #endif
//                                   &internal_flow)) {
//       NF_DEBUG("Found internal flow.");
//       // LOG_FLOWID(&internal_flow, NF_DEBUG);

//     #ifdef WITH_DPDK
//       if (internal_flow.dst_ip != rte_ipv4_header->src_addr ||
//           internal_flow.dst_port != tcpudp_header->src_port ||
//           internal_flow.protocol != rte_ipv4_header->next_proto_id)
//       #elif defined(WITH_XCHG)
//       if (internal_flow.dst_ip != desc->ip_src ||
//           internal_flow.dst_port != desc->port_src ||
//           internal_flow.protocol != desc->ip_proto)
//       #endif
//       {

//         NF_DEBUG("Spoofing attempt, dropping.");
//         return EXPLICIT_DROP;
//       }

//       // This time we have no choice, we have to manually go into the payload
//       // and change the IP and port
//       rte_ipv4_header->dst_addr = internal_flow.src_ip;
//       tcpudp_header->dst_port = internal_flow.src_port;
//       dst_device = internal_flow.internal_device;
//     } else {
//       NF_DEBUG("Unknown flow, dropping");
//       return EXPLICIT_DROP;
//     }
//   } else {
//     struct FlowId id =
//     #ifdef WITH_DPDK
//                       {.src_port = tcpudp_header->src_port,
//                         .dst_port = tcpudp_header->dst_port,
//                         .src_ip = rte_ipv4_header->src_addr,
//                         .dst_ip = rte_ipv4_header->dst_addr,
//                         .protocol = rte_ipv4_header->next_proto_id,
//                         .internal_device = device};
//     #elif defined(WITH_XCHG)
//                       {.src_port = desc->port_src,
//                         .dst_port = desc->port_dst,
//                         .src_ip = desc->ip_src,
//                         .dst_ip = desc->ip_dst,
//                         .protocol = desc->ip_proto,
//                         .internal_device = device};
//     #endif
//     NF_DEBUG("For id:");
//     // LOG_FLOWID(&id, NF_DEBUG);

//     NF_DEBUG("Device %" PRIu16 " is internal (not %" PRIu16 ")", device,
//              config.wan_device);

//     uint16_t external_port;
//     if (!flow_manager_get_internal(flow_manager, &id, now, &external_port)) {
//       NF_DEBUG("New flow");

//       if (!flow_manager_allocate_flow(flow_manager, &id, device, now,
//                                       &external_port)) {
//         NF_DEBUG("No space for the flow, dropping");
//         return EXPLICIT_DROP;
//       }
//     }

//     NF_DEBUG("Forwarding from ext port:%d", external_port);
//     rte_ipv4_header->src_addr = config.external_addr;
//     tcpudp_header->src_port = external_port;
//     dst_device = config.wan_device;
//   }

//   // No need to recompute checksum manually, it is offloaded to the NIC
//   // Recompute checksums
//   // nf_set_rte_ipv4_udptcp_checksum(rte_ipv4_header, tcpudp_header, buffer);

//   concretize_devices(&dst_device, 2);

//   return dst_device;
// }
