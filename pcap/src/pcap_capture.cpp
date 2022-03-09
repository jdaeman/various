#include "pcap.h"

#include <cstdlib>
#include <cstring>

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
    const char* capture_types[] = { "pcap_dispatch", "pcap_loop", "pcap_next", "pcap_breakloop" };
    int i = 0;
    int no;
    int capture_type = -1;
    int capture_count = 0;
    int timeout = 0;

    if (argc < 4) {
        printf("Usage: %s [capture_type] [capture_count] [timeout(sec)]\n", argv[0]);
        printf("Capture types\n");
        for (int i = 0; i < sizeof(capture_types) / sizeof(const char*); i++) {
            printf("[%d]: %s\n", i, capture_types[i]);
        }
        return 1;
    }

    capture_type = atoi(argv[1]);
    capture_count = atoi(argv[2]);
    timeout = atoi(argv[3]) * 1000;

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
        // buffer size
        // promiscous mode
        // timeout (ms)
        adhandle = pcap_open_live(d->name, 65535, 1, timeout, errbuf);
        if (adhandle == NULL) {
            printf("pcap_open_live error %s\n", errbuf);
            pcap_freealldevs(alldevs);
            return 1;
        }
#if 0
        if (capture_type == 3) {
            // not working in multiprocess.
            printf("pcap_breakloop for %s\n", d->name);
            pcap_breakloop(adhandle);
            goto CLOSE_EXIT;
        }
#endif

        printf("Start: packet capture by %s\n", capture_types[capture_type]);
        printf("Capture count: %d\n", capture_count);

        pcap_freealldevs(alldevs);
        int ret = 999999999;

        switch (capture_type)
        {
        case 0:
            // pcap_dispatch
            ret = pcap_dispatch(adhandle, capture_count, packet_handler, NULL);
            break;
        case 1:
            // pcap_loop
            ret = pcap_loop(adhandle, capture_count, packet_handler, NULL);
            break;
        case 2:
        {
            struct pcap_pkthdr hdr;
            memset(&hdr, 0, sizeof(hdr));
            // pcap_next
            const u_char * pkt = pcap_next(adhandle, &hdr);
            ret = (pkt != NULL) ? 0 : -1;
            printf("%d %d\n", hdr.caplen, hdr.len);
            break;
        }
        default:
            printf("Unknown capture type\n");
            goto CLOSE_EXIT;
        }

		printf("return of %s: %d\n", capture_types[capture_type], ret);
 CLOSE_EXIT:
        pcap_close(adhandle);
    }

    return 0;
}
