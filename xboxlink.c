
#include <net/ethernet.h>

#include <sys/capability.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "log.h"

typedef struct {
    char *interface;
    int idx;

    pthread_t thread;
    pcap_t *pcap;

    pthread_mutex_t stats_lock;
    uint64_t bytes_rcvd;
    uint64_t bytes_sent;
    uint32_t pkts_rcvd;
    uint32_t pkts_sent;
} xbl_interface_t;

typedef struct {
    uint8_t mac_addr[ETHER_ADDR_LEN];
    xbl_interface_t *interface;
    time_t last_seen;

    pthread_mutex_t stats_lock;
    uint64_t bytes_rcvd;
    uint64_t bytes_sent;
    uint32_t pkts_rcvd;
    uint32_t pkts_sent;
} xbl_host_t;

const uint8_t MAX_NUM_INTERFACES = 4;

struct bpf_program xbl_bpf_filter;
xbl_interface_t **xbl_interfaces;

int  log_to_stderr;
bool debug;

void usage(void)
{
    fputs("foobarbaz\n", stderr);
}

void update_host_recv_stats(xbl_host_t *xht, uint32_t pkt_len)
{
    pthread_mutex_lock(&xht->stats_lock);
    xht->bytes_rcvd += pkt_len;
    xht->pkts_rcvd++;
    pthread_mutex_unlock(&xht->stats_lock);
}

void update_host_send_stats(xbl_host_t *xht, uint32_t pkt_len)
{
    pthread_mutex_lock(&xht->stats_lock);
    xht->bytes_rcvd += pkt_len;
    xht->pkts_rcvd++;
    pthread_mutex_unlock(&xht->stats_lock);
}

void update_interface_recv_stats(xbl_interface_t *xit, uint32_t pkt_len)
{
    pthread_mutex_lock(&xit->stats_lock);
    xit->bytes_rcvd += pkt_len;
    xit->pkts_rcvd++;
    pthread_mutex_unlock(&xit->stats_lock);
}

void update_interface_send_stats(xbl_interface_t *xit, uint32_t pkt_len)
{
    pthread_mutex_lock(&xit->stats_lock);
    xit->bytes_sent += pkt_len;
    xit->pkts_sent++;
    pthread_mutex_unlock(&xit->stats_lock);
}

xbl_host_t *get_host_by_dest_addr(uint8_t *addr)
{
    return NULL;
}

xbl_host_t *get_host_by_source_addr(uint8_t *addr, xbl_interface_t *in)
{
    return NULL;
}

void handler(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *packet)
{
    xbl_interface_t *xit_in = (xbl_interface_t *)user;
    struct ether_header *eth_hdr = (struct ether_header *)packet;

    update_interface_recv_stats(xit_in, h->caplen);

    xbl_host_t *src_host = get_host_by_source_addr(eth_hdr->ether_shost, xit_in);
    if (src_host == NULL) {
        log_msg("Failed to lookup source host struct.");
        return;
    }
    update_host_recv_stats(src_host, h->caplen);

    if (memcmp(eth_hdr->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6) != 0) {
        /* Unicast packet */
        xbl_host_t *dst_host = get_host_by_dest_addr(eth_hdr->ether_dhost);
        if (dst_host == NULL) {
            log_msg("Failed to lookup destination host struct.");
            return;
        }
        xbl_interface_t *xit_out = dst_host->interface;
        if (xit_out == xit_in)
            return;
        int rv = pcap_inject(xit_out->pcap, packet, h->caplen);
        if (rv == -1) {
            log_msg("pcap_inject failed: %s", pcap_geterr(xit_out->pcap));
            return;
        }
        update_host_send_stats(dst_host, rv);
        update_interface_send_stats(xit_out, rv);
    } else {
        /* Broadcast packet */
        for(int i = 0; i < MAX_NUM_INTERFACES && xbl_interfaces[i] != NULL; i++) {
            xbl_interface_t *xit_out = xbl_interfaces[i];
            if (xit_out == xit_in)
                continue;
            int rv = pcap_inject(xit_out->pcap, packet, h->caplen);
            if (rv == -1) {
                log_msg("pcap_inject failed: %s", pcap_geterr(xit_out->pcap));
                return;
            }
            update_interface_send_stats(xit_out, rv);
        }
    }
}

bool xbl_pcap_init(xbl_interface_t *xit)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int rv;

    xit->pcap = pcap_open_live(xit->interface, 65535, 1, 0, errbuf);
    if (xit->pcap == NULL) {
        log_msg("pcap_open_live failed: %s", errbuf);
        return false;
    }

    rv = pcap_setfilter(xit->pcap, &xbl_bpf_filter);
    if (rv == -1) {
        log_msg("pcap_setfilter failed: %s", pcap_geterr(xit->pcap));
        pcap_close(xit->pcap);
        xit->pcap = NULL;
        return false;
    }

    rv = pcap_setdirection(xit->pcap, PCAP_D_IN);
    if (rv == -1) {
        log_msg("pcap_setdirection failed: %s", pcap_geterr(xit->pcap));
        pcap_close(xit->pcap);
        xit->pcap = NULL;
        return false;
    }

    return true;
}

void *pcap_runner(void *arg)
{
    xbl_interface_t *xit = (xbl_interface_t *)arg;

    if (!xbl_pcap_init(xit)) {
        pthread_exit(NULL);
    }

    pcap_loop(xit->pcap, 0, handler, (void *)xit);

    pcap_close(xit->pcap);
    xit->pcap = NULL;

    return NULL;
}

static
bool validate_interface_name(const char *int_name)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_live(int_name, 65535, 0, 0, errbuf);
    if (p == NULL) {
        log_msg("pcap_open_live() failed: %s", errbuf);
        return 1;
    }
    pcap_close(p);

    return 0;
}

static
bool check_capabilities(void)
{
    cap_flag_value_t cap_val;
    cap_t caps = cap_get_proc();
    if (caps == NULL)
        log_sys("cap_get_proc() failed");
    cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_val);
    cap_free(caps);

    return (cap_val == CAP_SET);
}

static
bool prepare_bpf_filter(void)
{
    pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
    int rv = pcap_compile(p, &xbl_bpf_filter, "host 0.0.0.1", 1, PCAP_NETMASK_UNKNOWN);
    if (rv < 0)
        log_msg("pcap_compile() failed: %s", pcap_geterr(p));
    pcap_close(p);

    return (rv == 0);
}

static
void daemonize(void)
{
    /* Fork into the background and detach from the controlling terminal */
    pid_t pid;
    if ((pid = fork()) < 0)
        log_sys("fork() failed the first time");
    if (pid > 0) /* parent */
        exit(0);
    setsid();
    if ((pid = fork()) < 0)
        log_sys("fork() failed the second time");
    if (pid > 0) /* parent */
        exit(0);

    /* Change current directory to root */
    if (chdir("/") < 0)
        log_sys("chdir() to / failed");

    /* Clear umask restrictions */
    umask(0);

    /* Redirect std{in,out,err} to /dev/null */
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
        log_sys("open() failed for /dev/null");

    dup2(fd, 0); /* stdin */
    dup2(fd, 1); /* stdout */
    dup2(fd, 2); /* stderr */
    close(fd);

    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    if (rl.rlim_max == RLIM_INFINITY)
        rl.rlim_max = 1024;
    for (int i = 3; i < rl.rlim_max; i++)
        close(i);
}

int main(int argc, char *argv[])
{
    if (!check_capabilities()) {
        fprintf(stderr, "This program must be run as root, or be granted the CAP_NET_RAW capability\n");
        exit(-1);
    }

    char *interfaces[MAX_NUM_INTERFACES];
    bzero(interfaces, sizeof(char *) * MAX_NUM_INTERFACES);
    uint8_t num_interfaces = 0;

    int ch;
    while((ch = getopt(argc, argv, "dhi:")) != -1) {
        switch(ch) {
            case 'd':
                debug = true;
                break;
            case 'i':
                if (num_interfaces >= MAX_NUM_INTERFACES)
                    err_quit("Too many interfaces specified, maximum is %d.", MAX_NUM_INTERFACES);
                if (validate_interface_name(optarg) != 0)
                    err_quit("%s does not appear to be a valid interface name.", optarg);
                interfaces[num_interfaces] = optarg;
                num_interfaces++;
                break;
            case 'h':
            default:
                usage();
                exit(-1);
        }
    }

    if (!debug)
        daemonize();

    log_open(NULL, LOG_NDELAY|LOG_PID, LOG_USER);

    if (!prepare_bpf_filter())
        log_quit("Failed to compile bpf filter.");

    xbl_interfaces = malloc(sizeof(xbl_interface_t *) * (num_interfaces + 1));
    if (xbl_interfaces == NULL)
        log_sys("malloc() failed while allocating interfaces array");
    bzero(xbl_interfaces, sizeof(xbl_interface_t *) * (num_interfaces + 1));
    for (int i = 0; i < num_interfaces; i++) {
        xbl_interfaces[i] = malloc(sizeof(xbl_interface_t));
        if (xbl_interfaces[i] == NULL)
            log_sys("malloc() failed while allocating xbl_interface struct");
        bzero(xbl_interfaces[i], sizeof(xbl_interface_t));

        xbl_interfaces[i]->interface = interfaces[i];
        xbl_interfaces[i]->idx = i;

        pthread_create(&xbl_interfaces[i]->thread, NULL, pcap_runner, xbl_interfaces[i]);
    }

    for (int i = 0; i < num_interfaces; i++) {
        pthread_join(xbl_interfaces[i]->thread, NULL);    
    }

    return 0;
}
