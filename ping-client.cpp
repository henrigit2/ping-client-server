#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>




using namespace std;



// * -> Simboliza dúvida uma certa linha de código ou em um conjunto de linhas de códigos

int pingLoop = 1;

struct ping_pkt {
    struct icmphdr hdr;
    char msg[64 - sizeof(struct icmphdr)];
    
};

void intHandler(int s){
    pingLoop = 0;
}



void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_ip, char *rev_host){
    int ttl_val = 64, msg_count = 0, i, addr_len, msg_received_cout = 0, flag = 1;

    struct ping_pkt pckt;
    struct sockaddr_in r_addr;
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec = 0, total_msec = 0;
    struct timeval tv_out;
    tv_out.tv_sec = 1;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs); // *

    if(setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) == 0){ // *
        cout << "Socket definido para TTL" << endl;
    } else {
        cout << "Configuracoes para socket TTL falhou" << endl;
        return;
    }

    if(sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) == -1) { // *
            cout << "Falha ao enviar o pacote" << endl;
            flag = 0;
        }

    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out)); // *

    while(pingLoop) {
        flag = 1; 

        bzero(&pckt, sizeof(pckt)); // *

        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = getpid(); // *

        for(i = 0; i < sizeof(pckt.msg) - 1; i++)
            pckt.msg[i] = i + '0';

        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = msg_count++;
        //pckt.hdr.checksum = checksum(&pckt, sizeof(pckt)); //*

        usleep(1000000); // *

        clock_gettime(CLOCK_MONOTONIC, &time_start); // *
        if(sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) == -1) { // *
            cout << "Falha ao enviar o pacote" << endl;
            flag = 0;
        }

        addr_len = sizeof(r_addr); // *

        if(recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr *) &r_addr, (socklen_t *) &addr_len) == -1 && msg_count > 1){
            cout << "Falha ao receber o pacote" << endl;
        } else {
            clock_gettime(CLOCK_MONOTONIC, &time_end); // *

            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0; // *
            rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed; // *

            if(flag){
                cout << 64 << " bytes from " << "h: " << rev_host << " " << ping_ip << " msg_seq=" << msg_count << " ttl=" << ttl_val << " rtt=" << rtt_msec << endl;

                msg_received_cout++;
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0;

    total_msec = (tfe.tv_sec - tfs.tv_sec)*1000.0 + timeElapsed;

    cout << ping_ip << " ping statistics" << endl;
    cout << msg_count << " packets sent," << msg_received_cout << " packets received " << ((msg_count - msg_received_cout)/msg_count) * 100.0 << " percent packet loss. Total time: " << total_msec << endl;
}

void send_ping2(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_ip, char *rev_host){
    int ttl_val = 64, msg_count = 0, i, addr_len, msg_received_cout = 0, flag = 1;

    struct ping_pkt pckt;
    struct sockaddr_in r_addr;
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec = 0, total_msec = 0;
    struct timeval tv_out;
    tv_out.tv_sec = 1;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs); // *

    if(setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) == 0){ // *
        cout << "Socket definido para TTL" << endl;
    } else {
        cout << "Configuracoes para socket TTL falhou" << endl;
        return;
    }

    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out)); // *

    while(pingLoop) {
        flag = 1; 

        bzero(&pckt, sizeof(pckt)); // *

        pckt.hdr.type = ICMP_ECHO;
        //pckt.hdr.un.echo.id = getpid(); // *
        pckt.hdr.un.echo.id = rand()*10; // *

        for(i = 0; i < sizeof(pckt.msg) - 1; i++)
            pckt.msg[i] = i + '0';

        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = msg_count++;
        //pckt.hdr.checksum = checksum(&pckt, sizeof(pckt)); //*

        usleep(1000000); // *

        clock_gettime(CLOCK_MONOTONIC, &time_start); // *
        /*
        if(sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) == -1) { // *
            cout << "Falha ao enviar o pacote" << endl;
            flag = 0;
        }
        */

        char pkt[9];
        pkt[0] = pckt.hdr.type + '0';
        pkt[1] = pckt.hdr.un.echo.id + '0';
        pkt[2] = '0' + pckt.hdr.un.echo.sequence;
        //pkt[3] = checksum(&pckt, sizeof(pckt));
        pkt[3] = '.';
        pkt[4] = '.';
        pkt[5] = '.';
        pkt[6] = 'm';
        pkt[7] = 's';
        pkt[8] = 'g';
        
        if(send(ping_sockfd, pkt, sizeof(pkt), 0) == -1){
            cout << "Falha ao enviar o pacote" << endl;
            flag = 0;
        } else {
            cout << "Pacote Enviado" << endl;
        }

        addr_len = sizeof(r_addr); // *

        if(read(ping_sockfd, pkt, 1024) == -1 && msg_count > 1){
            cout << "Falha ao receber o pacote" << endl;
        } else {
            cout << pkt[0] << " " << pkt[2] - '0' << endl;
        }

        /*

        if(recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr *) &r_addr, (socklen_t *) &addr_len) == -1 && msg_count > 1){
            cout << "Falha ao receber o pacote" << endl;
        } else {
            clock_gettime(CLOCK_MONOTONIC, &time_end); // *

            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0; // *
            rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed; // *

            if(flag){
                cout << 64 << " bytes from " << "h: " << rev_host << " " << ping_ip << " msg_seq=" << msg_count << " ttl=" << ttl_val << " rtt=" << rtt_msec << endl;

                msg_received_cout++;
            }
        }
        */
    }

    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0;

    total_msec = (tfe.tv_sec - tfs.tv_sec)*1000.0 + timeElapsed;

    cout << ping_ip << " ping statistics" << endl;
    cout << msg_count << " packets sent," << msg_received_cout << " packets received " << ((msg_count - msg_received_cout)/msg_count) * 100.0 << " percent packet loss. Total time: " << total_msec << endl;
}

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con)
{
    printf("\nResolving DNS..\n");
    struct hostent *host_entity;
    char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
  
    if ((host_entity = gethostbyname(addr_host)) == NULL)
    {
        // No ip found for hostname
        return NULL;
    }
      
    //filling up address structure
    strcpy(ip, inet_ntoa(*(struct in_addr *)
                          host_entity->h_addr));

    
    //(*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_family = AF_INET;
    (*addr_con).sin_port = htons(5000);
    //(*addr_con).sin_addr.s_addr  = *(long*)host_entity->h_addr;
    (*addr_con).sin_addr.s_addr = INADDR_ANY;
  
    return ip;
      
}

int main(int argc, char *argv[]){
    int sockfd;
    char *ip_addr;
    struct sockaddr_in addr_con;
    int addrlen = sizeof(addr_con);
    char net_buf[NI_MAXHOST];

    if(argc != 2){
        cout << "FORMATO " << argv[0] << " <address>";
        return 0;
    }

    //sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // *
    sockfd = socket(AF_INET, SOCK_STREAM, 0);


    ip_addr = dns_lookup(argv[1], &addr_con);
    if(ip_addr==NULL)
    {
        cout << "Falha dns_lookup" << endl;
        return 0;
    }


    if(sockfd == -1){
        cout << "Descritor do Socket não recebido" << endl;
        return 0;
    } else {
        cout << "Descritor do Socket " << sockfd << " recebido" << endl;
    }


    if (connect(sockfd, (struct sockaddr *)&addr_con, sizeof(addr_con)) < 0)
    {
        cout << "Connection Failed" << endl;
        return -1;
    }

    signal(SIGINT, intHandler);

/*
    char msg[3] = {'1', '2', '3'};
    send(sockfd, msg, 20, 0);
    */

    send_ping2(sockfd, &addr_con, ip_addr, argv[1]);

    return 0;
}