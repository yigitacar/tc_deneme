#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <linux/if_link.h>

#include "tc_kern.skel.h"

#define BPF_PROG_PATH "tc_kern.o" // Path to compiled eBPF program

char** getnics(int* count);


int main(int argc, char **argv)
{
	struct tc_kern *skel;
	int err, key, map_fd;
	int count = 0;
	
	/* Get interface names */
	char** card_data = getnics(&count);
	
	/* Print extracted interface names */
    for (int i = 0; i < count; i++) {
        printf("%s\n", card_data[i]);
    }
    for (int i = 0; i < count; i++) { 
        free(card_data[i]);
    }

	/* Create and open BPF application */
    skel = tc_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
	
	/* Load and verify BPF programs */
    err = tc_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    //    goto cleanup;
    }	

	map_fd = bpf_map__fd(skel->maps.interface_map);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get file descriptor for 'interface_map'\n");
		return 1;
	}
	__u32 value = if_nametoindex(card_data[i]);
	
	/* Update interface map */
/*	key = 0;
	bpf_map_update_elem(bpf_map__fd(skel->interface_map), &key, card_data[0], BPF_ANY);
*/	
	/* Attach tracepoint */
    err = tc_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
    //    goto cleanup;
    }	

	/* Detach BPF program and free up used resources */	
	/*  
	tc_kern__destroy(skel);
	*/
	
    free(card_data);
	return 0;
}


char** getnics(int* count)
{
    struct ifaddrs *ifaddr, *ifa;
    char** details = NULL;
    int index = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        // Exclude loopback interface
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        // Check if interface is already in the list
        int duplicate = 0;
        for (int i = 0; i < index; i++) {
            if (strcmp(details[i], ifa->ifa_name) == 0) {
                duplicate = 1;
                break;
            }
        }

        // Add to list if not a duplicate
        if (!duplicate) {
            details = (char**) realloc(details, (index + 1) * sizeof(char*));
            details[index] = malloc(strlen(ifa->ifa_name) + 1);
            strcpy(details[index++], ifa->ifa_name);
        }
    }

    *count = index;
    freeifaddrs(ifaddr);
    return details;
}
