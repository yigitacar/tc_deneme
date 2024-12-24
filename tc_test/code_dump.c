#define EGRESS_HANDLE		0x1;
#define EGRESS_PRIORITY 	0xC02F;

int tc_attach_egress(struct user_config *cfg, struct tc_kern *skel);

struct user_config {
	int ifindex;
	char ifname[4];
	bool unload;
	bool flush_hook;
};

static int verbose = 1;

int tc_attach_egress(struct user_config *cfg, struct tc_kern *skel)
{
	int err = 0;
	int fd;
	
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress);

	fd = bpf_program__fd(skel->progs.tc_egress_multiplicate);
	if (fd < 0) {
		fprintf(stderr, "Couldn't find egress program\n");
		err = -ENOENT;
		goto out;
	}
	attach_egress.prog_fd = fd;
	
	hook.ifindex = cfg->ifindex;

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Couldn't create TC-BPF hook for "
			"ifindex %d (err:%d)\n", cfg->ifindex, err);
		goto out;
	}
	if (verbose && err == -EEXIST) {
		printf("Success: TC-BPF hook already existed "
		       "(Ignore: \"libbpf: Kernel error message\")\n");
	}

	hook.attach_point = BPF_TC_EGRESS;
	attach_egress.flags    = BPF_TC_F_REPLACE;
	attach_egress.handle   = EGRESS_HANDLE;
	attach_egress.priority = EGRESS_PRIORITY;
	err = bpf_tc_attach(&hook, &attach_egress);
	if (err) {
		fprintf(stderr, "Couldn't attach egress program to "
			"ifindex %d (err:%d)\n", hook.ifindex, err);
		goto out;
	}

	if (verbose) {
		printf("Attached TC-BPF program id:%d\n",
		       attach_egress.prog_id);
	}
out:
	return err;	
}

int tc_detach_egress(struct user_config *cfg)
{
	int err;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = cfg->ifindex,
			    .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_info);

	opts_info.handle   = EGRESS_HANDLE;
	opts_info.priority = EGRESS_PRIORITY;

	/* Check what program we are removing */
	err = bpf_tc_query(&hook, &opts_info);
	if (err) {
		fprintf(stderr, "No egress program to detach "
			"for ifindex %d (err:%d)\n", cfg->ifindex, err);
		return err;
	}
	if (verbose)
		printf("Detaching TC-BPF prog id:%d\n", opts_info.prog_id);

	/* Attempt to detach program */
	opts_info.prog_fd = 0;
	opts_info.prog_id = 0;
	opts_info.flags = 0;
	err = bpf_tc_detach(&hook, &opts_info);
	if (err) {
		fprintf(stderr, "Cannot detach TC-BPF program id:%d "
			"for ifindex %d (err:%d)\n", opts_info.prog_id,
			cfg->ifindex, err);
	}

	if (cfg->flush_hook)
		return teardown_hook(cfg);

	return err;
}

int teardown_hook(struct user_config *cfg)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .attach_point = BPF_TC_EGRESS,
			    .ifindex = cfg->ifindex);
	int err;

	/* When destroying the hook, any and ALL attached TC-BPF (filter)
	 * programs are also detached.
	 */
	err = bpf_tc_hook_destroy(&hook);
	if (err)
		fprintf(stderr, "Couldn't remove clsact qdisc on %s\n", cfg->ifname);

	if (verbose)
		printf("Flushed all TC-BPF egress programs (via destroy hook)\n");

	return err;
}