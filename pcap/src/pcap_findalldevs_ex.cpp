// macro HAVE_REMOTE is inserted by cmake.
#include "pcap.h"

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list from the local machine */
    // New WinPcap functions
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        return 1;
    }
    
    /* Print the list */
    for(d= alldevs; d != NULL; d= d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");

        struct pcap_addr* cur_addr = NULL;
        if (d->addresses) {
            cur_addr = d->addresses;
            while (cur_addr != NULL)
            {
                const auto z = ((struct sockaddr_in*)cur_addr->addr)->sin_addr;
                printf("address %s\n", inet_ntoa(z));
                cur_addr = cur_addr->next;
            }
        }

        printf("flags: %d\n\n", d->flags);
    }
    
    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return 1;
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
	return 0;
}
