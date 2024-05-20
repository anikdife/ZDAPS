#include <iostream>
#include <pcap.h>
#include <netinet/in.h> // For sockaddr_in
#include <netinet/ip.h> // For iphdr
#include <netinet/tcp.h> // For tcphdr
#include <netinet/udp.h> // For udphdr
#include <chrono>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip> 

struct PacketFeatures {
    int destinationPort;
    int flowDuration;
    int ttl;
    std::string protocol;
    std::string sourceIP;
    std::string destinationIP;
    std::string flags;
    std::string options;
    int headerLength;
    std::string ipVersion;
    std::string fragmentationFlags;
    int totalLength;
    int identification;
    int checksum;
    int sourcePort;
    int sequenceNumber;
    int acknowledgmentNumber;
    int windowSize;
    int urgentPointer;
    std::string payloadData;
    int payloadLength;
    std::string flowKey;
};

static std::unordered_map<int, PacketFeatures> packetDictionary;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const u_char *ethernet_header = packet;
    const u_char *ip_header = packet + 14;
    const struct iphdr *ip = reinterpret_cast<const struct iphdr *>(ip_header);

    PacketFeatures packetFeatures;

    std::ostringstream flowKeyStream;

    in_addr source_ip_addr, dest_ip_addr;
    source_ip_addr.s_addr = ip->saddr;
    dest_ip_addr.s_addr = ip->daddr;

    flowKeyStream << inet_ntoa(source_ip_addr) << ":" << ntohs(ip->protocol) << "-" << inet_ntoa(dest_ip_addr);
    packetFeatures.flowKey = flowKeyStream.str();

    packetFeatures.destinationPort = 0; // Initialize to zero
    packetFeatures.flowDuration = 0; // Initialize to zero
    packetFeatures.ttl = ip->ttl;
    packetFeatures.protocol = (ip->protocol == IPPROTO_TCP) ? "TCP" : ((ip->protocol == IPPROTO_UDP) ? "UDP" : "Other");
    packetFeatures.sourceIP = inet_ntoa(source_ip_addr);
    packetFeatures.destinationIP = inet_ntoa(dest_ip_addr);
    packetFeatures.flags = "";
    packetFeatures.options = "";
    packetFeatures.headerLength = ip->ihl * 4;
    packetFeatures.ipVersion = (ip->version == 4) ? "IPv4" : "IPv6";
    packetFeatures.fragmentationFlags = (ntohs(ip->frag_off) & IP_RF) ? "Fragmented" : "Not Fragmented";
    packetFeatures.totalLength = ntohs(ip->tot_len);
    packetFeatures.identification = ntohs(ip->id);
    packetFeatures.checksum = ip->check;

    if (ip->ihl > 5) {
        int options_length = (ip->ihl - 5) * 4;
        const u_char *options_start = ip_header + 20;
        for (int i = 0; i < options_length; ++i) {
            packetFeatures.options += std::to_string(options_start[i]) + " ";
        }
    }

    const u_char *tcp_header = ip_header + (ip->ihl * 4);
    const struct tcphdr *tcp = reinterpret_cast<const struct tcphdr *>(tcp_header);
    packetFeatures.sourcePort = ntohs(tcp->source);
    packetFeatures.destinationPort = ntohs(tcp->dest);
    packetFeatures.sequenceNumber = ntohl(tcp->seq);
    packetFeatures.acknowledgmentNumber = ntohl(tcp->ack_seq);
    packetFeatures.windowSize = ntohs(tcp->window);
    packetFeatures.urgentPointer = ntohs(tcp->urg_ptr);
    packetFeatures.flags = "SYN: " + std::to_string(tcp->syn) + ", ACK: " + std::to_string(tcp->ack) + ", FIN: " + std::to_string(tcp->fin) +
                           ", RST: " + std::to_string(tcp->rst) + ", PSH: " + std::to_string(tcp->psh) + ", URG: " + std::to_string(tcp->urg);

    int tcp_header_length = tcp->doff * 4;
    const u_char *payload_data = packet + 14 + (ip->ihl * 4) + tcp_header_length;
    int payload_length = pkthdr->len - (14 + (ip->ihl * 4) + tcp_header_length);
    packetFeatures.payloadLength = payload_length;

    std::ostringstream payloadDataStream;
    for (int i = 0; i < payload_length; ++i) {
        payloadDataStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(payload_data[i]) << " ";
    }
    packetFeatures.payloadData = payloadDataStream.str();

    packetDictionary[packetDictionary.size() + 1] = packetFeatures;
    std::cout<<packetDictionary.size();
}

int main() {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->flags & PCAP_IF_UP && dev->flags & PCAP_IF_RUNNING) {
            break;
        }
    }

    pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    // Print all the packet features
    for (const auto& pair : packetDictionary) {
        const int& key = pair.first;
        const PacketFeatures& features = pair.second;

        std::cout << "Packet " << key << " Features:" << std::endl;
        std::cout << "Flow Key: " << features.flowKey << std::endl;
        std::cout << "Destination Port: " << features.destinationPort << std::endl;
        std::cout << "Flow Duration: " << features.flowDuration << std::endl;
        std::cout << "TTL: " << features.ttl << std::endl;
        std::cout << "Protocol: " << features.protocol << std::endl;
        std::cout << "Source IP: " << features.sourceIP << std::endl;
        std::cout << "Destination IP: " << features.destinationIP << std::endl;
        std::cout << "Flags: " << features.flags << std::endl;
        std::cout << "Options: " << features.options << std::endl;
        std::cout << "Header Length: " << features.headerLength << std::endl;
        std::cout << "IP Version: " << features.ipVersion << std::endl;
        std::cout << "Fragmentation Flags: " << features.fragmentationFlags << std::endl;
        std::cout << "Total Length: " << features.totalLength << std::endl;
        std::cout << "Identification: " << features.identification << std::endl;
        std::cout << "Checksum: " << features.checksum << std::endl;
        std::cout << "Source Port: " << features.sourcePort << std::endl;
        std::cout << "Sequence Number: " << features.sequenceNumber << std::endl;
        std::cout << "Acknowledgment Number: " << features.acknowledgmentNumber << std::endl;
        std::cout << "Window Size: " << features.windowSize << std::endl;
        std::cout << "Urgent Pointer: " << features.urgentPointer << std::endl;
        std::cout << "Payload Length: " << features.payloadLength << std::endl;
        std::cout << "Payload Data: " << features.payloadData << std::endl;
        std::cout << std::endl;
    }

    return 0;
}
