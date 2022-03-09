#include "pcap.h"

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char* address;
	pcap_if_t* alldevs = nullptr;
	pcap_if_t* d = nullptr;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct in_addr addr;
	const char* titles[] = { "subnet", "netmask" };
	bpf_u_int32* ps[] = { &netp, &maskp };
	const int LEN = sizeof(ps) / sizeof(bpf_u_int32*);

	// alldevs: array of struct pcap_if
	int ret = pcap_findalldevs(&alldevs, errbuf);
	if (ret != 0) {
		printf("%s\n", errbuf);
		return 1;
	}

	int max_devs = 0;
	int sel_dev = -1;
	for (d = alldevs; d != NULL; d = d->next, max_devs++);

	printf("choice 0 ~ %d: ", max_devs-1);
	scanf("%d", &sel_dev);
	if (sel_dev >= max_devs) {
		printf("invalid choice\n");
		return 1;
	}

	d = alldevs;
	for (int offset = 0; offset < sel_dev; d = d->next, offset++);

	if (d == nullptr)
	{
		printf("could not get device\n");
		return 1;
	}

	printf("%s\n", d->name);
	ret = pcap_lookupnet(d->name, &netp, &maskp, errbuf);
	if (ret == -1)
	{
		printf("pcap_lookupnet: %s\n", errbuf);
		return 1;
	}

	for (int i = 0; i < LEN; i++) {
		addr.s_addr = *ps[i];
		address = inet_ntoa(addr);
		if (address == NULL) {
			perror("inet_ntoa");
			break;
		}

		printf("%s: %s\n", titles[i], address);
	}

	pcap_freealldevs(alldevs);
	return 0;
}
