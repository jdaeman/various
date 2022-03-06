#include "pcap.h"

int main()
{
    char* dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* alldevs;
	pcap_if_t* d;
	
	// alldevs: array of struct pcap_if
	const int ret = pcap_findalldevs(&alldevs, errbuf);
	if (ret != 0) {
		// error
		printf("%s\n", errbuf);
	}

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next)
	{
		if (d->description) {
			printf("desc: %s\n", d->description);
		}
		if (d->name) {
			printf("name: %s\n", d->name);
		}

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

	// free resource
	pcap_freealldevs(alldevs);
	return 0;
}