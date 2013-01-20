
#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <pthread.h>

#include <sys/capability.h>
#include <pcap/pcap.h>

typedef struct {
    char *interface;
    int idx;

    pthread_t thread;
    pcap_t *pcap;

    uint64_t bytes_rcvd;
    uint64_t bytes_sent;
    uint32_t pkts_rcvd;
    uint32_t pkts_sent;
} xbl_interface_t;

const uint8_t MAX_NUM_INTERFACES = 4;

struct bpf_program xbl_bpf_filter;
xbl_interface_t **xbl_interfaces;
bool debug;


void usage(void)
{
    fprintf(stderr, "foobarbaz\n");
}

void handler(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *packet)
{
    xbl_interface_t *xit = (xbl_interface_t *)user;

    xit->bytes_rcvd += h->caplen;
    xit->pkts_rcvd++;

    xbl_interface_t *xit_out = (xit->idx == 0) ? xbl_interfaces[1] : xbl_interfaces[0];
    int rv = pcap_inject(xit_out->pcap, packet, h->caplen);
    if (rv == -1) {
        fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(xit_out->pcap));
        return;
    }

    xit_out->bytes_sent += rv;
    xit_out->pkts_sent++;
}

bool xbl_pcap_init(xbl_interface_t *xit)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int rv;

    xit->pcap = pcap_open_live(xit->interface, 65535, 1, 0, errbuf);
    if (xit->pcap == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return false;
    }

    rv = pcap_setfilter(xit->pcap, &xbl_bpf_filter);
    if (rv == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(xit->pcap));
        pcap_close(xit->pcap);
        xit->pcap = NULL;
        return false;
    }

    rv = pcap_setdirection(xit->pcap, PCAP_D_IN);
    if (rv == -1) {
        fprintf(stderr, "pcap_setdirection failed: %s\n", pcap_geterr(xit->pcap));
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
    if (p == NULL)
        return 1;

    pcap_close(p);
    return 0;
}

static
bool check_capabilities(void)
{
    cap_flag_value_t cap_val;
    cap_t caps = cap_get_proc();
    cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_val);
    cap_free(caps);

    return (cap_val == CAP_SET);
}

static
bool prepare_bpf_filter(void)
{
    pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
    if (p == NULL) {
        fprintf(stderr, "pcap_open_dead() failed.");
        return false;
    }
    int rv = pcap_compile(p, &xbl_bpf_filter, "host 0.0.0.1", 1, PCAP_NETMASK_UNKNOWN);
    if (rv < 0) {
        fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(p));
    }
    pcap_close(p);

    return (rv == 0);
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
                if (num_interfaces >= MAX_NUM_INTERFACES) {
                    fprintf(stderr, "Too many interfaces specified, maximum is %d.\n", MAX_NUM_INTERFACES);
                    exit(-1);
                }
                if (validate_interface_name(optarg) != 0) {
                    fprintf(stderr, "%s does not appear to be a valid interface name.\n", optarg);
                    exit(-1);
                }
                interfaces[num_interfaces] = optarg;
                num_interfaces++;
                break;
            case 'h':
            default:
                usage();
                exit(-1);
        }
    }

    if (!prepare_bpf_filter()) {
        fprintf(stderr, "Failed to compile bpf filter.\n");
        exit(-1);
    }

    xbl_interfaces = malloc(sizeof(xbl_interface_t *) * (num_interfaces + 1));
    if (xbl_interfaces == NULL) {
        fprintf(stderr, "malloc() failed while allocating interfaces array: %s\n", strerror(errno));
        exit(-1);
    }
    bzero(xbl_interfaces, sizeof(xbl_interface_t *) * (num_interfaces + 1));
    for (int i = 0; i < num_interfaces; i++) {
        xbl_interfaces[i] = malloc(sizeof(xbl_interface_t));
        if (xbl_interfaces[i] == NULL) {
            fprintf(stderr, "malloc() failed while allocating xbl_interface struct: %s\n", strerror(errno));
            exit(-1);
        }
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
