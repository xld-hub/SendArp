#ifndef  __ARPSPOOFHEAD_H__
#define   __ARPSPOOFHEAD_H__


#include "StrToHex.h"
#include "Head.h"
#include <pcap.h>
#include <iostream>

struct ArpPacket
{
    ether_header EtherHead;
    arp_header ArpHead;
};

class ArpSpoof
{
private:
    pcap_t *m_fp;
    pcap_if_t *m_alldevices;
    pcap_if_t *m_device;
    ArpPacket m_arppacket;
    char errbuf[PCAP_ERRBUF_SIZE];

public:

    void initDevice();
    void SetArpPacker();
    void SendPacket();

    ArpSpoof();
    ~ArpSpoof();
};




#endif