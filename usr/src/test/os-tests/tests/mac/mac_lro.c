/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Oxide Computer Compnay
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <libgen.h>

#include <libktest.h>

#include "mac_ktest_common.h"

static ktest_hdl_t *kthdl = NULL;
const char *mac_lro_cmd = "";

static void __NORETURN
mac_lro_usage(void)
{
	/* RPZ TODO
	 *
	 * Want flag to either generate an output cap file from the input,
	 * or to verify that the packets the LRO generates match the
	 * cap_file_out */
	(void) fprintf(stderr, "Usage: %s [flags] [opts] <cap_file_in> "
	    "<cap_file_out>\n\n"
	    "Flags:\n"
	    "Options:\n"
	    "Arguments:\n"
	    "\t<cap_file_in> snoop capture to perform LRO on\n"
	    "\t<cap_file_out> is a snoop capture of expected output packets.\n",
	    mac_lro_cmd);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	mac_lro_cmd = basename(argv[0]);
	argc--;
	argv++;

	if (argc != 2) {
		(void) fprintf(stderr,
		    "cap_file_in and cap_file_out are required arguments\n");
		mac_lro_usage();
	}

	int in_fd = open(argv[0], O_RDONLY);
	if (in_fd < 0) {
		err(EXIT_FAILURE, "could not open input cap file %s", argv[0]);
	}

	/* RPZ should I use fopen/fwrite instead? */
	int out_fd = open(argv[1], O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (out_fd < 0) {
		err(EXIT_FAILURE, "could not open output cap file %s", argv[0]);
	}

	pkt_cap_iter_t *in_iter = pkt_cap_open(in_fd);
	if (in_iter == NULL) {
		err(EXIT_FAILURE, "unrecognized cap file %s", argv[0]);
	}

	/* RPZ could I modify pkt iter to use uint8_t* instead of void*? */
	const void *pcap_buf = NULL;
	uint_t pcap_len = 0;

	if (!pkt_cap_next(in_iter, &pcap_buf, &pcap_len)) {
		err(EXIT_FAILURE, "no packets in input capture");
	}

	pkt_cap_reset(in_iter);
	void *in_buf = serialize_pkt_chain(in_iter, &pcap_len);


	/* The output pcap **should** be lte to the input pcap. */
	size_t out_len = pcap_len * 2;
	uint8_t *out_buf = malloc(pcap_len);

	if (out_buf == NULL) {
		err(EXIT_FAILURE, "could not allocate %zu bytes for output",
		    out_len);
	}

	/* RPZ I'm going to need something in-kernel that takes series of
	 * mblks and serializes into len+bytes format, and then something
	 * in here to deserialized that into a pcap. */


	if ((kthdl = ktest_init()) == NULL) {
		err(EXIT_FAILURE, "could not initialize libktest");
	}
	if (!ktest_mod_load("mac")) {
		err(EXIT_FAILURE, "could not load mac ktest module");
	}

	ktest_run_req_t req = {
		.krq_module = "mac",
		.krq_suite = "lro",
		.krq_test = "mac_sw_lro_test",
	};

	/*
	 * RPZ I may want to create an nvlist payload with options of how
	 * to run the lro test (like the lso test), like if the output
	 * buffer contains bytes to be verified or if it's an output sink.
	 * Right now I'm treating it as always an output sink, and if I
	 * want to verify I can do that here in userspace.
	 */
	req.krq_input = (uchar_t *)in_buf;
	req.krq_input_len = (uint_t)pcap_len;
	req.krq_output = out_buf;
	req.krq_output_len = out_len;

	ktest_run_result_t result = { 0 };
	if (!ktest_run(kthdl, &req, &result)) {
		err(EXIT_FAILURE, "failure while attempting ktest run");
	}

	const char *code_name = ktest_code_name(result.krr_code);
	printf("%s\n", code_name);
	if (result.krr_msg != NULL) {
		if (result.krr_code != KTEST_CODE_PASS) {
			(void) printf("MSG: %s\n", result.krr_msg);
		}
		free(result.krr_msg);
	}

	if (result.krr_code == KTEST_CODE_PASS) {
		ssize_t wlen = write(out_fd, out_buf, result.krr_output_used);

		if (wlen != result.krr_output_used) {
			err(EXIT_FAILURE, "failed to write output");
		}
	}

	pkt_cap_close(in_iter);
	free(in_buf);
	free(out_buf);
	ktest_fini(kthdl);

	return (result.krr_code == KTEST_CODE_PASS ? EXIT_SUCCESS :
	    EXIT_FAILURE);
}
