#include <unistd.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include "../icmpHeader/IcmpHeader.h"

using namespace std;

struct ping_pkt {
    struct icmphdr hdr;
    char msg[64 - sizeof(struct icmphdr)];
    
};


int main()
{
    IcmpHeader packetIcmp;

    pacoteICMP imcp_h;

    imcp_h.type = '0';

    

    char packet_icmp[3];

    int socketConn = socket(AF_INET, SOCK_STREAM, 0);
    //int socketConn = socket(AF_INET, SOCK_RAW, 0);
    int newSocketConn, valRead;
    sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(5000);

    if(!socketConn){
        cout << "socket failed";
    }

    if(bind(socketConn, (struct sockaddr*)&address, sizeof(address)) == -1) {
        cout << "bind failed";
    }

    if(listen(socketConn, 1) == -1){
        cout << "listen failed";
    }

    newSocketConn = accept(socketConn, (struct sockaddr*)&address, (socklen_t*)&addrlen);

    if(newSocketConn == -1){
        cout << "accpet failed";
    }

    ping_pkt pckt;
    struct sockaddr_in r_addr;
    int addr_len = sizeof(r_addr);


    
    /*
    if(recvfrom(socketConn, &pckt, sizeof(pckt), 0, (struct sockaddr *) &r_addr, (socklen_t *) &addr_len) == -1){
            cout << "Falha ao receber o pacote" << endl;
    } else {
            cout << pckt.hdr.type;
    }
    */
    
    while(true){
    

        valRead = read(newSocketConn, buffer, 9);
        cout << buffer << endl;

        buffer[0] = '0';

        send(newSocketConn, buffer, sizeof(buffer), 0);

    }
    
    //packetIcmp.decode(buffer);

    //packetIcmp.encode(imcp_h, packet_icmp);

    //send(newSocketConn, packet_icmp, 15, 0);


    return 0;
}

