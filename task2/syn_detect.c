#define _GNU_SOURCE

/*
 * Assignment 2: TCP SYN Flood Detector
 * Usage: ./syn_detect <interface>
 *
 * Monitors a network interface using libpcap and detects TCP SYN flood
 * attacks. Reports the start and end of each attack, and identifies
 * sequential attacks (single-source floods).
 *
 * Detection strategy:
 *   - Track SYN packets per second in a sliding window.
 *   - If SYN/s exceeds a threshold, declare an attack.
 *   - Track per-source SYN counts to identify sequential (single-source) attacks.
 *   - When rate drops below threshold for a cooldown period, declare attack over.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

/* ---------- Tunable parameters ---------- */
#define SYN_THRESHOLD       50    /* SYN packets/s to trigger alert    */
#define WINDOW_SEC          1      /* Measurement window in seconds     */
#define COOLDOWN_SEC        5      /* Seconds below threshold to end    */
#define SEQ_THRESHOLD       50     /* SYN/s from one source = sequential*/
#define MAX_TRACKED_SRCS    4096   /* Hash table size for source IPs    */

/* ---------- Global state ---------- */
static volatile sig_atomic_t running = 1;

/* Per-source tracking entry */
typedef struct {
    uint32_t ip;
    unsigned count;
    int      flagged;   /* Is already reported as sequential? */
} src_entry_t;

/* Detector state */
typedef struct {
    unsigned    syn_count;          /* SYNs in current window            */
    time_t      window_start;       /* Start of current measurement      */
    int         attack_active;      /* Are we inside an attack?          */
    time_t      last_above;         /* Last time rate was above threshold*/
    time_t      attack_start_time;  /* When the current attack started   */
    src_entry_t sources[MAX_TRACKED_SRCS];
} detector_t;

static detector_t g_det;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* hash for IPv4 addresses */
static unsigned ip_hash(uint32_t ip)
{
    return (ip ^ (ip >> 16)) % MAX_TRACKED_SRCS;
}

/* Record a SYN from a source IP; return the entry */
static src_entry_t *record_source(uint32_t ip)
{
    unsigned idx = ip_hash(ip);

    /* Linear probing  */
    for (unsigned i = 0; i < MAX_TRACKED_SRCS; i++) {
        unsigned slot = (idx + i) % MAX_TRACKED_SRCS;
        // matched the ip
        if (g_det.sources[slot].ip == ip) {
            g_det.sources[slot].count++;
            return &g_det.sources[slot];
        }
        // the ip is not yet tracked -> claim the slot
        if (g_det.sources[slot].ip == 0) {
            g_det.sources[slot].ip    = ip;
            g_det.sources[slot].count = 1;
            g_det.sources[slot].flagged = 0;
            return &g_det.sources[slot];
        }
    }
    return NULL;  /* Table full — unlikely with 4096 slots */
}

/* Reset per-window source counters */
static void reset_sources(void)
{
    memset(g_det.sources, 0, sizeof(g_det.sources));
}

/* Format a timestamp for log output */
static void print_time(void)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    if (tm) {
        char buf[32];
        strftime(buf, sizeof(buf), "%H:%M:%S", tm);
        printf("[%s] ", buf);
    }
}

/*
Window evaluation runs only after 1 second after window_start -> during the 1s window check how many SYNs accumulated
 * Check the window, detect attacks, and print results.
 * Called after each SYN is counted.
 */
static void evaluate_window(void)
{
    time_t now = time(NULL);

    // window size of 1 sec: if still inside the same 1-second window -> return
    if (difftime(now, g_det.window_start) < WINDOW_SEC) {
        return;
    }

    /* Window elapsed — compute rate */
    unsigned rate = g_det.syn_count;  /* SYN count in the past window */

    // if rate went up -> check if not active (already starting)
    if (rate >= SYN_THRESHOLD) {
        g_det.last_above = now;

        if (!g_det.attack_active) { // not active - only starting
            /* attack started */
            g_det.attack_active     = 1;
            g_det.attack_start_time = g_det.window_start;

            print_time();
            printf("ATTACK DETECTED — SYN flood started "
                   "(rate: %u SYN/s, threshold: %d) ***\n", rate, SYN_THRESHOLD);
        } else {
            print_time();
            printf("    Attack ongoing (rate: %u SYN/s)\n", rate);
        }

        /* Check for sequential (single-source) attack */
        for (unsigned i = 0; i < MAX_TRACKED_SRCS; i++) {
            if (g_det.sources[i].ip != 0 &&
                g_det.sources[i].count >= SEQ_THRESHOLD &&
                !g_det.sources[i].flagged) {

                struct in_addr a;
                a.s_addr = g_det.sources[i].ip;
                print_time();
                printf("    >> Sequential attack detected from %s "
                       "(%u SYN/s)\n", inet_ntoa(a), g_det.sources[i].count);
                g_det.sources[i].flagged = 1;
            }
        }

    } else if (g_det.attack_active) { // if alredy active and the rate < threshold 
        /* Rate is below threshold — check cooldown */
        if (difftime(now, g_det.last_above) >= COOLDOWN_SEC) { // check if cooldown time is up
            print_time();
            printf("*** ATTACK ENDED — SYN flood stopped "
                   "(below threshold for %d s) ***\n", COOLDOWN_SEC);
            g_det.attack_active = 0;
        } else {    // rate only dropped
            print_time();
            printf("    Rate dropped (%u SYN/s), cooldown...\n", rate);
        }
    }

    /* Reset window */
    g_det.syn_count    = 0;
    g_det.window_start = now;
    reset_sources();
}

/*
 * libpcap callback — called for every captured packet.
 */
static void packet_handler(u_char *user,
                           const struct pcap_pkthdr *header,
                           const u_char *packet)
{
    (void)user;

    /* Need at least Ethernet + minimal IP header check, so no reading outside of the buffer */
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct iphdr)) {
        return;
    }

    // get the eth packet 
    const struct ether_header *eth = (const struct ether_header *)packet;
    // check for packet's eth type == IP
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // ge the ipv4 packet
    const struct iphdr *iph = (const struct iphdr *)(packet + sizeof(struct ether_header));

    // Validate IP header length 
    unsigned ip_hdr_len = (unsigned)iph->ihl * 4;
    if (ip_hdr_len < 20 || iph->protocol != IPPROTO_TCP) {
        return;
    }

    // Bounds check for TCP header 
    if (header->caplen < sizeof(struct ether_header) + ip_hdr_len + sizeof(struct tcphdr)) {
        return;
    }

    // get tcp packet
    const struct tcphdr *tcph =
        (const struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr_len);

    // We only care about SYN packets (SYN=1, ACK=0) 
    if (tcph->syn && !tcph->ack) {
        g_det.syn_count++;
        // record the source of the packet in the hash table
        record_source(iph->saddr);
        // after every processed tcp packet evaluate the window for new connections
        evaluate_window();
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <interface>\n", prog);
    fprintf(stderr, "  interface - network interface to monitor (e.g. eth0)\n");
}

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);  /* disable output buffering */
    
    if (argc != 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    // register interface from args
    const char *iface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Open the interface for live capture */
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1 /* promisc */, 100 /* ms */, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface, errbuf);
        return EXIT_FAILURE;
    }
    // set non-blocking
    if (pcap_setnonblock(handle, 1, errbuf) < 0)
        {
        fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    /* Compile a BPF filter: only TCP packets */
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp", 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    // set compiled filter for the handle
    if (pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    // free
    pcap_freecode(&fp);

    /* Init detector state */
    memset(&g_det, 0, sizeof(g_det));
    g_det.window_start = time(NULL);

    /* Handle Ctrl+C gracefully */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[*] SYN Flood Detector running on %s\n", iface);
    printf("[*] Threshold: %d SYN/s | Cooldown: %d s\n", SYN_THRESHOLD, COOLDOWN_SEC);
    printf("[*] Press Ctrl+C to stop.\n\n");

    /* Main capture loop */
    while (running) {
        int ret = pcap_dispatch(handle, 64, packet_handler, NULL);
        if (ret < 0) {
            if (ret == PCAP_ERROR_BREAK) break;
            fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(handle));
            break;
        }

        evaluate_window();
        usleep(100000);
    }

        printf("\n[*] Shutting down.\n");
        pcap_close(handle);
        return EXIT_SUCCESS;
    }
