#include <iostream>
#include <pcap.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Extracting Ethernet frame information
    std::cout << "Source MAC Address: ";
    for (int i = 0; i < 6; ++i) {
        printf("%02x", packet[i]);
        if (i != 5) std::cout << ":";
    }
    std::cout << std::endl;

    std::cout << "Destination MAC Address: ";
    for (int i = 6; i < 12; ++i) {
        printf("%02x", packet[i]);
        if (i != 11) std::cout << ":";
    }
    std::cout << std::endl;

    // Extracting Ethernet type
    int ether_type = (packet[12] << 8) + packet[13];
    std::cout << "Ethernet Type: 0x" << std::hex << ether_type << std::dec << std::endl;

    // Extracting frame length
    std::cout << "Frame Length: " << pkthdr->len << std::endl;
    std::cout << std::endl;
    // Extracting IP header information
    int ip_header_length = (packet[14] & 0x0F) * 4;
    std::cout << "Source IP Address: " << std::dec
              << (int)packet[26] << "." << (int)packet[27] << "." << (int)packet[28] << "." << (int)packet[29] << std::endl;
    std::cout << "Destination IP Address: " << std::dec
              << (int)packet[30] << "." << (int)packet[31] << "." << (int)packet[32] << "." << (int)packet[33] << std::endl;

    // Extracting IP protocol
    int protocol = packet[23];
    std::cout << "IP Protocol: " << protocol << std::endl;

    // Extracting Time-to-Live (TTL)
    int ttl = packet[22];
    std::cout << "TTL: " << ttl << std::endl;

    // Print packet length
    std::cout << "Packet Length: " << pkthdr->len << std::endl;
    std::cout << std::endl;

    int transport_protocol = packet[14 + ip_header_length + 9]; // Protocol field in IP header
    std::cout << "transport protocol: "<<transport_protocol;

    // Check if the transport protocol is TCP (6) or UDP (17)
    if (transport_protocol == 6) { // TCP
        // Extract TCP header information
        int tcp_header_length = (packet[14 + ip_header_length + 12] >> 4) * 4;
        int source_port = (packet[14 + ip_header_length] << 8) + packet[14 + ip_header_length + 1];
        int destination_port = (packet[14 + ip_header_length + 2] << 8) + packet[14 + ip_header_length + 3];
        std::cout << "Transport Protocol: TCP" << std::endl;
        std::cout << "Source Port: " << source_port << std::endl;
        std::cout << "Destination Port: " << destination_port << std::endl;
    } else if (transport_protocol == 17) { // UDP
        // Extract UDP header information
        int source_port = (packet[14 + ip_header_length] << 8) + packet[14 + ip_header_length + 1];
        int destination_port = (packet[14 + ip_header_length + 2] << 8) + packet[14 + ip_header_length + 3];
        std::cout << "Transport Protocol: UDP" << std::endl;
        std::cout << "Source Port: " << source_port << std::endl;
        std::cout << "Destination Port: " << destination_port << std::endl;
    } else {
        std::cout << "Unknown Transport Protocol" << std::endl;
    }

    std::cout << std::endl;

    // Extracting application-layer protocol information
    const u_char *payload = packet + 14 + ((packet[14] & 0x0F) * 4); // Skip Ethernet and IP headers
    int payload_length = pkthdr->len - (payload - packet);
    
    // Assuming HTTP
    if (payload_length > 4 && payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') {
        std::cout << "Application Layer Protocol: HTTP" << std::endl;
        std::cout << "HTTP Request: " << std::string(reinterpret_cast<const char*>(payload), payload_length) << std::endl;
    }
    // Assuming DNS
    else if (payload_length > 12 && payload[2] == 1) {
        std::cout << "Application Layer Protocol: DNS" << std::endl;
        std::cout << "DNS Query: ";
        for (int i = 12; i < payload_length; ++i) {
            if (payload[i] == 0) break;
            std::cout << payload[i];
        }
        std::cout << std::endl;
    }
    // Add more conditions for other application-layer protocols as needed

    std::cout << std::endl;
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

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the handle and free device list when done
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
