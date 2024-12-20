#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	struct tc_kern *skel;
	int err;
	
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