#include "pcap.h"


void packet_handler(u_char* param,
                    const struct pcap_pkthdr* header, 
                    const u_char* pkt_data) 
{
    printf("caplen: %d\n", header->caplen);
	printf("len: %d\n\n", header->len);
}

int main(int argc, char** argv) 
{
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    int no;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d :  %s\n", ++i, (d->description) ? (d->description) : (d->name));
    }

    printf("number : ");
    scanf("%d", &no);

    for (d = alldevs, i = 0; d != NULL; d = d->next) {
        if (no == ++i) {
            break;
        }
    }

    if (d == NULL) {
        printf("there is no dev\n");
        pcap_freealldevs(alldevs);
    }
    else {
        // non-promiscous mode
        adhandle = pcap_open_live(d->name, 65535, 0, 1000, errbuf);
        if (adhandle == NULL) {
            printf("pcap_open_live error %s\n", errbuf);
            pcap_freealldevs(alldevs);
            return -1;
        }

        printf("Start: packet capture\n");

        pcap_freealldevs(alldevs);
        const int ret = pcap_loop(adhandle, 5, packet_handler, NULL);
		printf("return of pcap_loop: %d\n", ret);
        pcap_close(adhandle);
    }

    return 0;
}