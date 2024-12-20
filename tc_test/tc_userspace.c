#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tc_kern.skel.h"

#define BPF_PROG_PATH "tc_kern.o" // Path to compiled eBPF program

int main(int argc, char **argv)
{
	struct tc_kern *skel;
	int err;
	
	/* Get interface names */
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