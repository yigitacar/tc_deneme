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

int main(int argc, char **argv)
{
	struct tc_kern *skel;
	int err;
	int count = 0;
	
	/* Get interface names */
	char** card_data = getnics(&count);
    for (int i = 0; i < count; i++) {
        printf("%s\n", card_data[i]);
    }
    for (int i = 0; i < count; i++) { 
        free(card_data[i]);
    }
    free(card_data);
    return 0;	
	
	/* Update interface map */
	
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
}

char** getnics(int* count)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    char** details = NULL;
    char* combined = NULL;
    int index = 0;
    

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST);
            combined = malloc((strlen(ifa->ifa_name) + strlen(host) + 1) * sizeof(char*));
            strcpy(combined, ifa->ifa_name);
            strcat(combined, ":");
            strcat(combined, host);
            details = (char**) realloc(details, (index + 1) * sizeof(char*));
            details[index] = malloc(strlen(combined) + 1);
            strcpy(details[index++], combined);
            free(combined);
        } 
    }
    *count = index;
    freeifaddrs(ifaddr);
    return details;
}