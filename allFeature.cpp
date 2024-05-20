#include <iostream>
#include <pcap.h>
#include <netinet/in.h> // For sockaddr_in
#include <netinet/ip.h> // For iphdr
#include <netinet/tcp.h> // For tcphdr
#include <netinet/udp.h> // For udphdr
#include <chrono>
#include <unordered_map>


struct PacketFeatures {
    // Define variables for each feature
    int destinationPort;
    int flowDuration;
    // Add more features as needed
};

// Data structure to store flow information
struct FlowInfo {
    int packet_count;
    int total_bytes;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
};

// Global variable to store flow information
static std::unordered_map<std::string, FlowInfo> flows;
// Function to handle captured packets
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Extract Ethernet header
    const u_char *ethernet_header = packet;
    
    
    std::string sourceMacAddress;

    // Extract source MAC address
    sourceMacAddress.clear(); // Clear any existing content
    for (int i = 0; i < 6; ++i) {
    // Convert each byte to a hexadecimal string with two digits and padding with zeros
    char macByte[3];
    snprintf(macByte, sizeof(macByte), "%02x", ethernet_header[i]);
    sourceMacAddress.append(macByte);
    if (i != 5) {
        sourceMacAddress.append(":");
    }
    }

    std::cout << "Source MAC Address: " << sourceMacAddress << std::endl;
    std::string destinationMacAddress;

    // Extract destination MAC address
    destinationMacAddress.clear(); // Clear any existing content
    for (int i = 6; i < 12; ++i) {
    // Convert each byte to a hexadecimal string with two digits and padding with zeros
    char macByte[3];
    snprintf(macByte, sizeof(macByte), "%02x", ethernet_header[i]);
    destinationMacAddress.append(macByte);
    if (i != 11) {
        destinationMacAddress.append(":");
    }
    }

    std::cout << "Destination MAC Address: " << destinationMacAddress << std::endl;
    // Extract Ethernet type (e.g., IPv4, IPv6)
    uint16_t ether_type = (ethernet_header[12] << 8) | ethernet_header[13];
    std::cout << "Ethernet Type: " << std::hex << ether_type << std::dec << std::endl;

    // Skip Ethernet header to get IP header
    const u_char *ip_header = packet + 14;

    // Extract IP header
    const struct iphdr *ip = reinterpret_cast<const struct iphdr *>(ip_header);
    
    // Extract source IP address
    std::string sourceIPAddress=inet_ntoa(*(struct in_addr *)&ip->saddr);
    std::cout << "Source IP Address: " << sourceIPAddress << std::endl;
    
    // Extract destination IP address
    std::string destIPAddress=inet_ntoa(*(struct in_addr *)&ip->daddr);
    std::cout << "Destination IP Address: " << destIPAddress << std::endl;

    // Extract IP Protocol
    std::string protocol;
    switch (ip->protocol) {
        case IPPROTO_TCP:
            protocol = "TCP";
            break;
        case IPPROTO_UDP:
            protocol = "UDP";
            break;
        case IPPROTO_ICMP:
            protocol = "ICMP";
            break;
        default:
            protocol = "Unknown";
    }
    std::cout << "IP Protocol: " << protocol << std::endl;

    // Extract Time-to-Live (TTL)
    int ttl=static_cast<int>(ip->ttl);
    std::cout << "Time-to-Live (TTL): " << ttl << std::endl;

    // Extract IP Version
    std::string ip_version = (ip->version == 4) ? "IPv4" : "IPv6";
    std::cout << "IP Version: " << ip_version << std::endl;

    // Extract Header Length
    int headerLength=static_cast<int>(ip->ihl) * 4;
    std::cout << "Header Length: " << headerLength << " bytes" << std::endl;

    // Extract Fragmentation Flags
    bool frag=(ntohs(ip->frag_off) & IP_RF);
    std::cout << "Fragmentation Flags: " <<  ((frag)? "Fragmented" : "Not Fragmented") << std::endl;

    // Extract Total Length
    int totalL=ntohs(ip->tot_len);
    std::cout << "Total Length: " << totalL << " bytes" << std::endl;

    // Extract Identification
    uint16_t identification=ntohs(ip->id);
    std::cout << "Identification: " << identification << std::endl;

    // Extract Flags
    bool flags=(ip->frag_off & IP_RF);
    std::cout << "Flags: " << (flags ? "Reserved" : "Not Reserved") << std::endl;

    // Extract Checksum
    const uint16_t checksum=ip->check;
    std::cout << "Checksum: " << checksum << std::endl;

    // Extract Options (if any)
    if (ip->ihl > 5) {
        int options_length = (ip->ihl - 5) * 4;
        // Skip the header length to reach options
        const u_char *options_start = ip_header + 20;
        std::cout << "Options: ";
        for (int i = 0; i < options_length; ++i) {
            printf("%02x ", options_start[i]);
        }
        std::cout << std::endl;
    }

    std::cout << std::endl;

    // Skip IP header to get TCP header
    const u_char *tcp_header = ip_header + (ip->ihl * 4);

    // Extract TCP header
    const struct tcphdr *tcp = reinterpret_cast<const struct tcphdr *>(tcp_header);

    // Extract source port
    std::cout << "Source Port: " << ntohs(tcp->source) << std::endl;

    // Extract destination port
    std::cout << "Destination Port: " << ntohs(tcp->dest) << std::endl;

    // Extract sequence number
    std::cout << "Sequence Number: " << ntohl(tcp->seq) << std::endl;

    // Extract acknowledgment number
    std::cout << "Acknowledgment Number: " << ntohl(tcp->ack_seq) << std::endl;

    // Extract window size
    std::cout << "Window Size: " << ntohs(tcp->window) << std::endl;

    // Extract checksum
    std::cout << "Checksum: " << ntohs(tcp->check) << std::endl;

    // Extract urgent pointer
    std::cout << "Urgent Pointer: " << ntohs(tcp->urg_ptr) << std::endl;

    // Extract TCP flags
    std::cout << "Flags: ";
    std::cout << "SYN: " << (tcp->syn ? "Set" : "Not set") << ", ";
    std::cout << "ACK: " << (tcp->ack ? "Set" : "Not set") << ", ";
    std::cout << "FIN: " << (tcp->fin ? "Set" : "Not set") << ", ";
    std::cout << "RST: " << (tcp->rst ? "Set" : "Not set") << ", ";
    std::cout << "PSH: " << (tcp->psh ? "Set" : "Not set") << ", ";
    std::cout << "URG: " << (tcp->urg ? "Set" : "Not set") << std::endl;

    // Extract TCP options (if any)
    int options_length = (tcp->doff - 5) * 4; // doff is the data offset field in the TCP header
    if (options_length > 0) {
        // Skip the header length to reach options
        const u_char *options_start = tcp_header + 20; // 20 is the size of the TCP header without options
        std::cout << "Options: ";
        for (int i = 0; i < options_length; ++i) {
            printf("%02x ", options_start[i]);
        }
        std::cout << std::endl;
    }

    std::cout << std::endl;

    // Extract Packet Length
    std::cout << "Packet Length: " << pkthdr->len << " bytes" << std::endl;

    std::cout << std::endl;

    // Calculate TCP header length
    int tcp_header_length = tcp->doff * 4;

    // Skip TCP header to get payload data
    const u_char *payload_data = packet + 14 + (ip->ihl * 4) + tcp_header_length;

    // Calculate payload length
    int payload_length = pkthdr->len - (14 + (ip->ihl * 4) + tcp_header_length);

    // Print payload length
    std::cout << "Payload Length: " << payload_length << " bytes" << std::endl;

    // Print payload data
    std::cout << "Payload Data: ";
    for (int i = 0; i < payload_length; ++i) {
        printf("%02x ", payload_data[i]);
    }
    std::cout << std::endl;

    std::cout << std::endl;

    // Check if IP version is IPv4
    if (ip->version == 4) {
        // Extract source and destination IP addresses
        in_addr source_ip_addr, dest_ip_addr;
        source_ip_addr.s_addr = ip->saddr;
        dest_ip_addr.s_addr = ip->daddr;

        // Extract source and destination ports if the packet is TCP
        if (ip->protocol == IPPROTO_TCP) {
            const u_char *tcp_header = ip_header + (ip->ihl * 4);
            const struct tcphdr *tcp = reinterpret_cast<const struct tcphdr *>(tcp_header);
            uint16_t source_port = ntohs(tcp->source);
            uint16_t dest_port = ntohs(tcp->dest);

            // Construct a flow key using source and destination IP addresses and ports
            std::string flow_key = inet_ntoa(source_ip_addr);
            flow_key += ":" + std::to_string(source_port) + "-" + inet_ntoa(dest_ip_addr) + ":" + std::to_string(dest_port);

            // Get current timestamp
            auto current_time = std::chrono::steady_clock::now();

            // Retrieve or create flow information for the current flow
            //static std::unordered_map<std::string, FlowInfo> flows; // Static to retain state between function calls
            FlowInfo &flow = flows[flow_key];

            // Update flow information
            if (flow.packet_count == 0) {
                // First packet of the flow, set start time
                flow.start_time = current_time;
            }
            flow.packet_count++;
            flow.total_bytes += pkthdr->len;
            flow.end_time = current_time;

            // Calculate flow duration in seconds
            std::chrono::duration<double> duration = flow.end_time - flow.start_time;
            double flow_duration = duration.count();

            // Print flow information
            std::cout << "Flow: " << flow_key << std::endl;
            std::cout << "Number of packets: " << flow.packet_count << std::endl;
            std::cout << "Total bytes transferred: " << flow.total_bytes << " bytes" << std::endl;
            std::cout << "Flow duration: " << flow_duration << " seconds" << std::endl;
            std::cout << std::endl;
        }
    }
}

int main() {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the list of available network devices/interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    // Find the active network device/interface
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->flags & PCAP_IF_UP && dev->flags & PCAP_IF_RUNNING) {
            break;
        }
    }

    // Open the active network device/interface for packet capture
    pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Create an unordered_map to store packet features
    std::unordered_map<std::string, PacketFeatures> packetDictionary;


    // Start capturing packets
    pcap_loop(handle, 2, packet_handler, NULL);

    // Close the handle and free device list when done
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
