#define _GNU_SOURCE

/*
 * Assignment 4: Ping of Death Detector
 * Usage: ./pod_detect <interface>
 *
 * Monitors a network interface for oversized ICMP packets by tracking
 * IP fragments and computing the reassembled datagram size.
 *
 * Detection threshold:
 *   Normal ICMP echo payloads are 56-64 bytes; even "jumbo" pings
 *   rarely exceed 1472 bytes (single unfragmented frame at MTU 1500).
 *   Any ICMP datagram requiring fragment reassembly to > 10000 bytes
 *   is suspicious.  The classic Ping of Death exceeds 65535 bytes.
 *   We use a conservative threshold of 10000 bytes — this passes all
 *   normal traffic while catching the Assignment 3 attack easily.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

/* ---------- Tunable parameters ---------- */

/*
 * ICMP reassembled-size threshold (bytes).
 * 10 000 bytes is well above any legitimate single ICMP exchange
 * yet far below the 65535-byte PoD boundary, giving a safety margin.
 */
#define POD_SIZE_THRESHOLD  10000

#define COOLDOWN_SEC        3       /* Seconds without alert to declare end */
#define MAX_TRACKED_IDS     2048    /* Fragment-group hash table size       */

/* Global state */
static volatile sig_atomic_t running = 1;

/*
 * Fragment group: tracks all fragments sharing the same
 * (src_ip, dst_ip, ip_id) tuple.
 */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t ip_id;
    uint8_t  active;        /* Slot in use?                       */
    uint8_t  alerted;       /* Already reported?                  */
    uint32_t total_bytes;   /* Sum of payload bytes across frags  */
    time_t   first_seen;
} frag_group_t;

typedef struct {
    frag_group_t groups[MAX_TRACKED_IDS];
    int          attack_active;
    time_t       last_alert;
    time_t       attack_start;
} detector_t;

static detector_t g_det;
static pcap_t *g_handle = NULL;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
    if (g_handle) {
        pcap_breakloop(g_handle);
    }
}

/* Hash (src, dst, id) into the table */
static unsigned frag_hash(uint32_t src, uint32_t dst, uint16_t id)
{
    uint32_t h = src ^ dst ^ ((uint32_t)id << 7);
    return (h ^ (h >> 16)) % MAX_TRACKED_IDS;
}

/*
 * Find or create a fragment group entry.
 * Returns NULL only if the table is full.
 */
static frag_group_t *find_group(uint32_t src, uint32_t dst, uint16_t id,
                                time_t now)
{
    unsigned idx = frag_hash(src, dst, id);

    for (unsigned i = 0; i < MAX_TRACKED_IDS; i++) {
        unsigned slot = (idx + i) % MAX_TRACKED_IDS;
        frag_group_t *g = &g_det.groups[slot];

        if (g->active &&
            g->src_ip == src && g->dst_ip == dst && g->ip_id == id) {
            return g;
        }

        if (!g->active) {
            /* Claim empty slot */
            memset(g, 0, sizeof(*g));
            g->src_ip     = src;
            g->dst_ip     = dst;
            g->ip_id      = id;
            g->active     = 1;
            g->first_seen = now;
            return g;
        }

        /* Evict stale entries (> 30 seconds old) */
        if (g->active && difftime(now, g->first_seen) > 30.0) {
            memset(g, 0, sizeof(*g));
            g->src_ip     = src;
            g->dst_ip     = dst;
            g->ip_id      = id;
            g->active     = 1;
            g->first_seen = now;
            return g;
        }
    }
    return NULL;
}

/* Print formatted timestamp */
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
 * Called periodically (and after each packet) to check
 * whether the attack has ended.
 */
static void check_cooldown(void)
{
    if (!g_det.attack_active) return;

    time_t now = time(NULL);
    if (difftime(now, g_det.last_alert) >= COOLDOWN_SEC) {
        print_time();
        printf("*** ATTACK ENDED — no oversized ICMP for %d s ***\n",
               COOLDOWN_SEC);
        g_det.attack_active = 0;
        memset(g_det.groups, 0, sizeof(g_det.groups));
    }
}

/*
 * libpcap callback.
 */
static void packet_handler(u_char *user,
                           const struct pcap_pkthdr *header,
                           const u_char *packet)
{
    (void)user;

    /* Ethernet + minimal IP */
    size_t min_len = sizeof(struct ether_header) + sizeof(struct iphdr);
    if (header->caplen < min_len) return;

    const struct ether_header *eth = (const struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const struct iphdr *iph =
        (const struct iphdr *)(packet + sizeof(struct ether_header));

    
    // Validate IP header length 
    unsigned ip_hdr_len = (unsigned)iph->ihl * 4;
    if (ip_hdr_len < 20) return;

    /*
     * We care about ICMP.  But fragments after the first one
     * do NOT have the protocol-level header; the protocol field
     * in the IP header still says ICMP, which is what we need.
     *
     * However, the first fragment of any IP datagram carries
     * the protocol field.  For non-first fragments, iph->protocol
     * is still set correctly by the sender.
     */
    if (iph->protocol != IPPROTO_ICMP) return;

    // get the values from ipv4 in proper ordering for CPU
    uint16_t total_len   = ntohs(iph->tot_len); // Total length of this particular fragment (IP header + payload)
    uint16_t frag_off_field = ntohs(iph->frag_off); // 3 bits of flags and 13 bits of fragment offset
    uint16_t offset      = (frag_off_field & IP_OFFMASK) * 8; // Extract the 13-bit offset using the mask. Multiply by 8 because offsets are stored in units of 8 bytes
    int      more_frags  = (frag_off_field & IP_MF) != 0; // 'more fragments coming' flag

    /* Payload bytes in this particular fragment */
    uint32_t payload_len = 0;
    if (total_len > ip_hdr_len) {
        payload_len = total_len - ip_hdr_len;
    }


    /*
     * For fragment reassembly size estimation:
     *   reassembled size >= fragment_offset + payload_len  (for the last frag)
     *   We track the maximum (offset + payload_len) across all fragments.
     */
    uint32_t frag_end = offset + payload_len;

    time_t now = time(NULL);
    frag_group_t *grp = find_group(iph->saddr, iph->daddr,
                                   ntohs(iph->id), now);
    if (!grp) return;

    /* Update for specific attacker estimated reassembled size only if bigger */
    if (frag_end > grp->total_bytes) {
        grp->total_bytes = frag_end;
    }

    /* Check threshold and detect POD attack */
    if (grp->total_bytes >= POD_SIZE_THRESHOLD && !grp->alerted) {
        grp->alerted = 1;

        struct in_addr sa, da;
        sa.s_addr = iph->saddr;
        da.s_addr = iph->daddr;

        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];
        /* Safe copy with proper NUL termination */
        strncpy(src_str, inet_ntoa(sa), sizeof(src_str) - 1);
        src_str[sizeof(src_str) - 1] = '\0';
        strncpy(dst_str, inet_ntoa(da), sizeof(dst_str) - 1);
        dst_str[sizeof(dst_str) - 1] = '\0';

        if (!g_det.attack_active) {
            g_det.attack_active = 1;
            g_det.attack_start  = now;
            print_time();
            printf("*** ATTACK DETECTED — Ping of Death ***\n");
        }

        g_det.last_alert = now;

        print_time();
        printf("    Oversized ICMP: %s -> %s  "
               "reassembled >= %u bytes  (IP ID %u)%s\n",
               src_str, dst_str, grp->total_bytes, ntohs(iph->id),
               more_frags ? " [more fragments]" : " [last fragment]");

        if (grp->total_bytes > 65535) {
            print_time();
            printf("    >> PING OF DEATH: exceeds 65535 byte limit!\n");
        }
    }

    check_cooldown();
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <interface>\n", prog);
    fprintf(stderr, "  interface - network interface to monitor (e.g. eth0)\n");
    fprintf(stderr, "\nDetection threshold: %d bytes "
                    "(normal ICMP: 64-1472 bytes)\n", POD_SIZE_THRESHOLD);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 100, errbuf);
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
    g_handle = handle;

    /* Filter: only IP (captures ICMP fragments too) */
    // compile filter and free
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    pcap_freecode(&fp);

    memset(&g_det, 0, sizeof(g_det));

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[*] Ping of Death Detector running on %s\n", iface);
    printf("[*] Size threshold: %d bytes | Cooldown: %d s\n",
           POD_SIZE_THRESHOLD, COOLDOWN_SEC);
    printf("[*] Press Ctrl+C to stop.\n\n");

    while (running) {
        int ret = pcap_dispatch(handle, 64, packet_handler, NULL);
        if (ret < 0) {
            if (ret == PCAP_ERROR_BREAK) break;
            fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(handle));
            break;
        }
        // when the packets stop coming the packet handler does not get called -> check_cooldown itself
        check_cooldown();
        usleep(100000);
    }

    printf("\n[*] Shutting down.\n");
    pcap_close(handle);
    return EXIT_SUCCESS;
}
