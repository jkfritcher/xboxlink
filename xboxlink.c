
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <pthread.h>

#include <pcap/pcap.h>

typedef struct {
    char *interface;
    char *filter;
    int idx;
    char out;

    pthread_t thread;
    pcap_t *pcap;

    uint64_t bytes_rcvd;
    uint64_t bytes_sent;
    uint32_t pkts_rcvd;
    uint32_t pkts_sent;
} xbl_interface_t;

xbl_interface_t **interfaces;
pthread_mutex_t pcap_compile_lock = PTHREAD_MUTEX_INITIALIZER;

void handler(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *packet)
{
    xbl_interface_t *xit = (xbl_interface_t *)user;
    int rv;
    //putchar(xit->out);

    xit->pkts_rcvd += 1;
    xit->bytes_rcvd += h->caplen;

    xbl_interface_t *xit_out = (xit->idx == 0) ? interfaces[1] : interfaces[0];
    rv = pcap_inject(xit_out->pcap, packet, h->caplen);
    if (rv == -1) {
        fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(xit_out->pcap));
        return;
    }

    xit_out->pkts_sent += 1;
    xit_out->bytes_sent += rv;
}

int xbl_pcap_init(xbl_interface_t *xit)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    int rv;

    xit->pcap = pcap_open_live(xit->interface, 65535, 1, 1000, errbuf);
    if (xit->pcap == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 0;
    }

    pthread_mutex_lock(&pcap_compile_lock);
    rv = pcap_compile(xit->pcap, &fp, xit->filter, 1, PCAP_NETMASK_UNKNOWN);
    pthread_mutex_unlock(&pcap_compile_lock);
    if (rv == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(xit->pcap));
        pcap_close(xit->pcap);
        xit->pcap = NULL;
        return 0;
    }

    rv = pcap_setfilter(xit->pcap, &fp);
    if (rv == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(xit->pcap));
        pcap_close(xit->pcap);
        xit->pcap = NULL;
        return 0;
    }

    rv = pcap_setdirection(xit->pcap, PCAP_D_IN);
    if (rv == -1) {
        fprintf(stderr, "pcap_setdirection failed: %s\n", pcap_geterr(xit->pcap));
        pcap_close(xit->pcap);
        xit->pcap = NULL;
        return 0;
    }

    return 1;
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

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);

    interfaces = malloc(sizeof(xbl_interface_t*) * 3);
    bzero(interfaces, sizeof(xbl_interface_t*) * 3);
    interfaces[0] = malloc(sizeof(xbl_interface_t));
    interfaces[1] = malloc(sizeof(xbl_interface_t));
    bzero(interfaces[0], sizeof(xbl_interface_t));
    bzero(interfaces[1], sizeof(xbl_interface_t));

    xbl_interface_t *i1 = interfaces[0], *i2 = interfaces[1];
    i1->interface = "eth0";
    i1->filter = "host 0.0.0.1";
    i1->idx = 0;
    i1->out = '.';
    i2->interface = "eth2";
    i2->filter = "host 0.0.0.1";
    i2->idx = 1;
    i2->out = '*';

    pthread_create(&i1->thread, NULL, pcap_runner, i1);
    pthread_create(&i2->thread, NULL, pcap_runner, i2);

    pthread_join(i1->thread, NULL);    
    pthread_join(i2->thread, NULL);    

    return 0;
}
