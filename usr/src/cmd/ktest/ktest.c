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
 * Copyright 2021 Oxide Computer Company
 */
#include <sys/ktest.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/list.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <err.h>
#include <stdarg.h>
#include <strings.h>
#include <libgen.h>
#include <libnvpair.h>
#include <assert.h>
#include <regex.h>
#include <libcmdutils.h>
#include <ofmt.h>
#include <zone.h>

#define	KTEST_CMD_SZ		24
#define	KTEST_READ_BUF_SZ	(1024 * 1024 * 4)

#define	EXIT_USAGE	2

#define	assert0(exp)	(assert((exp) == 0))

static const char *ktest_prog;

/* The default triple matches all tests. */
static nvlist_t *ktest_def_triple;

/*
 * The list of directories to search and load test modules from.
 */
static char *mod_dirs[] = {
	"/kernel/misc/ktest/amd64",
	"/usr/kernel/misc/ktest/amd64"
};

/* Print a horizontal rule. */
static void
print_hr(uint8_t cols) {
	for (uint8_t i = 0; i < cols; i++) {
		(void) putchar('-');
	}

	(void) putchar('\n');
}

/* An adapter to use errx with libofmt. */
void
ktest_ofmt_errx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
}

typedef enum ktest_fmt_mod_load_fields {
	KTEST_FMT_MOD_LOAD_PATH,
	KTEST_FMT_MOD_LOAD_NAME,
	KTEST_FMT_MOD_LOAD_STATUS,
} ktest_fmt_mod_load_fields_t;

typedef struct ktest_mod_load_ofmt {
	char *kmlof_name;
	char *kmlof_path;
	boolean_t kmlof_loaded;
} ktest_mod_load_ofmt_t;

static boolean_t
ktest_mod_load_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t len)
{
	ktest_mod_load_ofmt_t *kmlof = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_MOD_LOAD_PATH:
		if (snprintf(buf, len, "%s", kmlof->kmlof_path) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_MOD_LOAD_NAME:
		if (snprintf(buf, len, "%s", kmlof->kmlof_name) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_MOD_LOAD_STATUS: {
		char *status = kmlof->kmlof_loaded ? "loaded" : "unloaded";

		if (snprintf(buf, len, "%s", status) >= len) {
			return (B_FALSE);
		}
		break;
	}
	}

	return (B_TRUE);
}

#define	KTEST_MOD_LOAD_CMD_DEF_FIELDS	"name,status,path"

static const ofmt_field_t ktest_mod_load_ofmt[] = {
	{ "NAME", 20, KTEST_FMT_MOD_LOAD_NAME, ktest_mod_load_ofmt_cb },
	{ "STATUS", 9, KTEST_FMT_MOD_LOAD_STATUS, ktest_mod_load_ofmt_cb },
	{ "PATH", 40, KTEST_FMT_MOD_LOAD_PATH, ktest_mod_load_ofmt_cb },
	{ NULL, 0, 0, NULL },
};

typedef enum ktest_fmt_fields {
	KTEST_FMT_RESULT,
	KTEST_FMT_MODULE,
	KTEST_FMT_SUITE,
	KTEST_FMT_TEST,
	KTEST_FMT_INPUT_FLAG,
	KTEST_FMT_INPUT_PATH,
	KTEST_FMT_REASON,
} ktest_fmt_fields_t;

typedef struct ktest_list_ofmt {
	char *klof_module;
	char *klof_suite;
	char *klof_test;
	boolean_t klof_input;
} ktest_list_ofmt_t;

static boolean_t
ktest_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t len)
{
	ktest_list_ofmt_t *klof = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_MODULE:
		if (snprintf(buf, len, "%s", klof->klof_module) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_SUITE:
		if (snprintf(buf, len, "%s", klof->klof_suite) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_TEST:
		if (snprintf(buf, len, "%s", klof->klof_test) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_INPUT_FLAG: {
		const char *flag = klof->klof_input ? "Y" : "N";

		if (snprintf(buf, len, "%s", flag) >= len) {
			return (B_FALSE);
		}
	}
	}

	return (B_TRUE);
}

#define	KTEST_LIST_CMD_DEF_FIELDS	"module,suite,test,input"

static const ofmt_field_t ktest_list_ofmt[] = {
	{ "MODULE", 12, KTEST_FMT_MODULE, ktest_list_ofmt_cb },
	{ "SUITE", 16, KTEST_FMT_SUITE, ktest_list_ofmt_cb },
	{ "TEST", 45, KTEST_FMT_TEST, ktest_list_ofmt_cb },
	{ "INPUT", 7, KTEST_FMT_INPUT_FLAG, ktest_list_ofmt_cb },
	{ NULL, 0, 0, NULL },
};

static const char *
ktest_result_str(ktest_msg_t *msg)
{
	ktest_msg_result_t *result;

	assert(msg->km_type == KTEST_MSG_RESULT);
	result = &msg->km_u.km_result;
	assert(result->kmr_type != KTEST_UNINIT);

	switch (result->kmr_type) {
	case KTEST_PASS:
		return ("PASS");
	case KTEST_FAIL:
		return ("FAIL");
	case KTEST_SKIP:
		return ("SKIP");
	case KTEST_ERROR:
		return ("ERROR");
	default:
		break;
	}

	/*
	 * A result can only be one of the four above, this is here to
	 * appease the compiler.
	 */
	return ("--");
}

static boolean_t
ktest_run_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t len)
{
	ktest_msg_t *msg = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_RESULT:
		if (snprintf(buf, len, "%s", ktest_result_str(msg)) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_MODULE:
		if (snprintf(buf, len, "%s", msg->km_module) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_SUITE:
		if (snprintf(buf, len, "%s", msg->km_suite) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_TEST:
		if (snprintf(buf, len, "%s", msg->km_test) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_INPUT_PATH: {
		ktest_msg_result_t *res;

		assert(msg->km_type == KTEST_MSG_RESULT);
		res = &msg->km_u.km_result;
		if (snprintf(buf, len, "%s", res->kmr_input_path) >= len) {
			return (B_FALSE);
		}
		break;
	}

	case KTEST_FMT_REASON: {
		ktest_msg_result_t *res;

		assert(msg->km_type == KTEST_MSG_RESULT);
		res = &msg->km_u.km_result;
		if (snprintf(buf, len, "%s%s", res->kmr_msg_prepend,
		    res->kmr_msg) >= len) {
			return (B_FALSE);
		}
		break;
	}
	}

	return (B_TRUE);
}

#define	KTEST_RUN_CMD_DEF_FIELDS	"result,module,suite,test"

/*
 * The input column for the run command is for displaying the path to
 * the input file, as opposed to the list command which indicates if
 * the test rqequires input or not.
 */
static const ofmt_field_t ktest_run_ofmt[] = {
	{ "RESULT", 7, KTEST_FMT_RESULT, ktest_run_ofmt_cb },
	{ "MODULE", 12, KTEST_FMT_MODULE, ktest_run_ofmt_cb },
	{ "SUITE", 16, KTEST_FMT_SUITE, ktest_run_ofmt_cb },
	{ "TEST", 45, KTEST_FMT_TEST, ktest_run_ofmt_cb },
	{ "INPUT", 48, KTEST_FMT_INPUT_PATH, ktest_run_ofmt_cb },
	{ "REASON", 256, KTEST_FMT_REASON, ktest_run_ofmt_cb },
	{ NULL, 0, 0, NULL },
};

typedef enum ktest_stat_type {
	KTEST_STAT_MOD,
	KTEST_STAT_SUITE,
} ktest_stat_type_t;

typedef struct ktest_stats {
	list_node_t		ks_node;
	ktest_stat_type_t	ks_type;
	char			*ks_name;
	uint32_t		ks_total;
	uint32_t		ks_pass;
	uint32_t		ks_fail;
	uint32_t		ks_err;
	uint32_t		ks_skip;
} ktest_stats_t;

static ktest_stats_t *
ktest_stats_new(ktest_stat_type_t type, const char *name)
{
	ktest_stats_t *stats;

	if ((stats = malloc(sizeof (ktest_stats_t))) == NULL) {
		err(EXIT_FAILURE, "failed to allocate stats structure");
	}

	stats->ks_type = type;
	stats->ks_name = strdup(name);
	stats->ks_total = 0;
	stats->ks_pass = 0;
	stats->ks_fail = 0;
	stats->ks_err = 0;
	stats->ks_skip = 0;
	return (stats);
}

static void
ktest_record_stat(ktest_stats_t *mod, ktest_stats_t *suite,
    const ktest_msg_t *msg)
{
	mod->ks_total++;
	suite->ks_total++;

	switch (msg->km_u.km_result.kmr_type) {
	case KTEST_PASS:
		mod->ks_pass++;
		suite->ks_pass++;
		break;

	case KTEST_FAIL:
		mod->ks_fail++;
		suite->ks_fail++;
		break;

	case KTEST_SKIP:
		mod->ks_skip++;
		suite->ks_skip++;
		break;

	case KTEST_ERROR:
		mod->ks_err++;
		suite->ks_err++;
		break;

	case KTEST_UNINIT:
		errx(EXIT_FAILURE, "received UNINIT result, this is a bug");
		break;
	}
}

typedef enum ktest_fmt_stats {
	KTEST_FMT_STATS_MS,
	KTEST_FMT_STATS_TOTAL,
	KTEST_FMT_STATS_PASS,
	KTEST_FMT_STATS_FAIL,
	KTEST_FMT_STATS_ERR,
	KTEST_FMT_STATS_SKIP,
} ktest_fmt_stats_t;

static boolean_t
ktest_stats_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t len)
{
	ktest_stats_t *stats = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_STATS_MS: {
		char *pre = (stats->ks_type == KTEST_STAT_MOD) ? "" : "  ";

		if (snprintf(buf, len, "%s%s", pre, stats->ks_name) >= len) {
			return (B_FALSE);
		}
		break;
	}

	case KTEST_FMT_STATS_TOTAL:
		if (snprintf(buf, len, "%u", stats->ks_total) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_PASS:
		if (snprintf(buf, len, "%u", stats->ks_pass) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_FAIL:
		if (snprintf(buf, len, "%u", stats->ks_fail) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_ERR:
		if (snprintf(buf, len, "%u", stats->ks_err) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_SKIP:
		if (snprintf(buf, len, "%u", stats->ks_skip) >= len) {
			return (B_FALSE);
		}
		break;
	}

	return (B_TRUE);
}

#define	KTEST_STATS_FIELDS	"module/suite,total,pass,fail,err,skip"

static const ofmt_field_t ktest_stats_ofmt[] = {
	{ "MODULE/SUITE", 40, KTEST_FMT_STATS_MS, ktest_stats_ofmt_cb },
	{ "TOTAL", 6, KTEST_FMT_STATS_TOTAL, ktest_stats_ofmt_cb },
	{ "PASS", 6, KTEST_FMT_STATS_PASS, ktest_stats_ofmt_cb },
	{ "FAIL", 6, KTEST_FMT_STATS_FAIL, ktest_stats_ofmt_cb },
	{ "ERR", 6, KTEST_FMT_STATS_ERR, ktest_stats_ofmt_cb },
	{ "SKIP", 6, KTEST_FMT_STATS_SKIP, ktest_stats_ofmt_cb },
};

static void
ktest_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	/* TODO Update usage */
	(void) fprintf(stderr,
	    "Usage: %s <cmd> [<module>[:<suite>[:<test>]] ...]\n\n"
	    "\tmod-load: load test modules\n"
	    "\tmod-list: list test modules\n"
	    "\tlist: list registered tests\n"
	    "\trun: run registered tests\n"
	    "\n"
	    "Run %s <cmd> help for help with a specific command\n",
	    ktest_prog, ktest_prog);
}

/*
 * Get a list of tests from the in-kernel ktest registry. Return all
 * tests that match at least one of the triples.
 */
static void
ktest_list_tests(int dev, nvlist_t *triples, nvlist_t **response)
{
	int ret = 0;
	boolean_t retry = B_FALSE;
	ktest_list_op_t klo;
	size_t resp_len = 1 * 1024 * 1024;
	char *resp = NULL;

	*response = NULL;
	klo.klo_triples_len = fnvlist_size(triples);
	klo.klo_triples_buf = malloc(klo.klo_triples_len);

	if (klo.klo_triples_buf == NULL) {
		err(EXIT_FAILURE, "failed to allocate triples buffer");
	}

	ret = nvlist_pack(triples, &klo.klo_triples_buf, &klo.klo_triples_len,
	    NV_ENCODE_NATIVE, 0);
	if (ret != 0) {
		errx(EXIT_FAILURE, "failed to pack triples: %s", strerror(ret));
	}

	if ((resp = malloc(resp_len)) == NULL) {
		err(EXIT_FAILURE, "failed to allocate response buffer");
	}

	bzero(resp, resp_len);
	klo.klo_resp = resp;
	klo.klo_resp_len = resp_len;

retry:
	ret = ioctl(dev, KTEST_IOCTL_LIST_TESTS, &klo);
	if (ret == -1 && errno == ENOBUFS && !retry) {
		free(resp);
		resp_len = klo.klo_resp_len;
		if ((resp = malloc(resp_len)) == NULL) {
			err(EXIT_FAILURE, "failed to allocate response buffer");
		}

		bzero(resp, resp_len);
		retry = B_TRUE;
		goto retry;
	} else if (ret == -1) {
		err(EXIT_FAILURE, "list ioctl failed");
	}

	resp_len = klo.klo_resp_len;
	if ((ret = nvlist_unpack(resp, resp_len, response, 0)) != 0) {
		errx(EXIT_FAILURE, "failed to unpack nvlist from response: %s",
		    strerror(ret));
	}

	if (resp != NULL)
		free(resp);

	if (klo.klo_triples_buf != NULL)
		free(klo.klo_triples_buf);
}

/*
 * Print test list. Any test list passed must be well formed
 * as this function assumes all necessary fields are present.
 */
static void
ktest_print_tests(nvlist_t *list, ofmt_handle_t ofmt)
{
	nvpair_t *ser_fmt_vsn = nvlist_next_nvpair(list, NULL);
	uint64_t vsn;

	if (ser_fmt_vsn == NULL) {
		errx(EXIT_FAILURE, "invalid list response, missing %s key\n",
		    KTEST_SER_FMT_KEY);
	}

	if (strcmp(nvpair_name(ser_fmt_vsn), KTEST_SER_FMT_KEY) != 0) {
		errx(EXIT_FAILURE, "invalid list response, missing %s key\n",
		    KTEST_SER_FMT_KEY);
	}

	vsn = fnvpair_value_uint64(ser_fmt_vsn);
	if (vsn != KTEST_SER_FMT_VSN) {
		errx(EXIT_FAILURE, "invalid serialization format version: %lu",
		    vsn);
	}

	for (nvpair_t *mod = nvlist_next_nvpair(list, ser_fmt_vsn);
	    mod != NULL;
	    mod = nvlist_next_nvpair(list, mod)) {
		nvlist_t *moddesc;
		nvlist_t *suites;
		char *module_name;

		moddesc = fnvpair_value_nvlist(mod);
		assert0(nvlist_lookup_pairs(moddesc, 0,
		    "name", DATA_TYPE_STRING, &module_name,
		    "suites", DATA_TYPE_NVLIST, &suites,
		    NULL));

		for (nvpair_t *suite = nvlist_next_nvpair(suites, NULL);
		    suite != NULL;
		    suite = nvlist_next_nvpair(suites, suite)) {
			nvlist_t *suitedesc;
			nvlist_t *tests;
			char *suite_name;
			char *suite_desc;
			char *suite_init;
			char *suite_fini;

			suitedesc = fnvpair_value_nvlist(suite);
			assert0(nvlist_lookup_pairs(suitedesc, 0,
			    "name", DATA_TYPE_STRING, &suite_name,
			    "description", DATA_TYPE_STRING, &suite_desc,
			    KTEST_SUITE_INIT_KEY, DATA_TYPE_STRING, &suite_init,
			    KTEST_SUITE_FINI_KEY, DATA_TYPE_STRING, &suite_fini,
			    "tests", DATA_TYPE_NVLIST, &tests,
			    NULL));

			for (nvpair_t *test = nvlist_next_nvpair(tests, NULL);
			    test != NULL;
			    test = nvlist_next_nvpair(tests, test)) {
				nvlist_t *testdesc;
				char *test_name;
				boolean_t test_input;
				ktest_list_ofmt_t klof;

				testdesc = fnvpair_value_nvlist(test);
				assert0(nvlist_lookup_pairs(testdesc, 0,
				    "name", DATA_TYPE_STRING, &test_name,
				    "input_required", DATA_TYPE_BOOLEAN_VALUE,
				    &test_input,
				    NULL));

				klof.klof_module = module_name;
				klof.klof_suite = suite_name;
				klof.klof_test = test_name;
				klof.klof_input = test_input;
				ofmt_print(ofmt, &klof);
			}
		}
	}
}

/*
 * Load all ktest modules under dir, printing status information.
 */
static void
ktest_load_dir(const char *dir, DIR *dirp, ofmt_handle_t ofmt)
{
	struct dirent *dp;

	errno = 0;
	while ((dp = readdir(dirp)) != NULL) {
		int id;
		size_t sz;
		char path[PATH_MAX];
		ktest_mod_load_ofmt_t kmlof;

		bzero(&kmlof, sizeof (kmlof));

		if (strcmp(".", dp->d_name) == 0 ||
		    strcmp("..", dp->d_name) == 0) {
			continue;
		}

		sz = snprintf(path, sizeof (path), "%s/%s", dir, dp->d_name);
		if (sz >= sizeof (path)) {
			warn("path is too long %s/%s", dir, dp->d_name);
		}

		kmlof.kmlof_path = path;
		kmlof.kmlof_name = dp->d_name;

		/*
		 * The second argument is zero to indicate to modctl
		 * that this is an absolute path. If the module is
		 * already loaded this will have no effect and report
		 * success.
		 */
		if (modctl(MODLOAD, 0, path, &id) != 0) {
			char *errfmt = "failed to load %s: %s";

			kmlof.kmlof_loaded = B_FALSE;

			/* if (parsable) */
			/* 	errfmt = "failed:%s:%s"; */

			warnx(errfmt, path, strerror(errno));
			ofmt_print(ofmt, &kmlof);
			continue;
		}

		kmlof.kmlof_loaded = B_TRUE;

		/* if (parsable) */
		/* 	fmt = "loaded:%s\n"; */

		/* printf(fmt, dp->d_name); */

		ofmt_print(ofmt, &kmlof);
	}

	if (errno != 0) {
		err(EXIT_FAILURE, "failed to read dir %s", dir);
	}
}

/* Determine if a given test module is already loaded. */
static boolean_t
ktest_is_tmod_loaded(const char *tmod_name)
{
	struct modinfo modinfo;
	int id = -1;

	modinfo.mi_id = modinfo.mi_nextid = id;
	modinfo.mi_info = MI_INFO_ALL;

	while (modctl(MODINFO, id, &modinfo) == 0) {
		if (strncmp(tmod_name, modinfo.mi_name, MODMAXNAMELEN) == 0)
			return (B_TRUE);

		id = modinfo.mi_id;
	};

	return (B_FALSE);
}

/*
 * List the set of test modules under dir, printing their current
 * status: loaded or unloaded. If parsable is true, then print the
 * status in a parsable-friendly manner.
 */
static void
ktest_list_dir(const char *dir, DIR *dirp, ofmt_handle_t ofmt)
{
	struct dirent *dp;

	errno = 0;
	while ((dp = readdir(dirp)) != NULL) {
		size_t sz;
		char path[PATH_MAX];
		ktest_mod_load_ofmt_t kmlof;

		bzero(&kmlof, sizeof (kmlof));

		if (strcmp(".", dp->d_name) == 0 ||
		    strcmp("..", dp->d_name) == 0) {
			continue;
		}

		sz = snprintf(path, sizeof (path), "%s/%s", dir, dp->d_name);
		if (sz >= sizeof (path)) {
			errx(EXIT_FAILURE, "path is too long %s/%s", dir,
			    dp->d_name);
		}

		kmlof.kmlof_name = dp->d_name;
		kmlof.kmlof_path = path;
		kmlof.kmlof_loaded = ktest_is_tmod_loaded(dp->d_name);
		ofmt_print(ofmt, &kmlof);
	}

	if (errno != 0) {
		err(EXIT_FAILURE, "failed to read dir %s", dir);
	}
}

/*
 * Load and register all ktest modules found under the following
 * paths.
 *
 *     /kernel/misc/ktest/amd64/
 *     /usr/kernel/misc/ktest/
 *
 * TODO Implement explicit name/glob.
 * TODO Implement -u for unload.
 */
static void
ktest_mod_load_cmd(int argc, char *argv[], ofmt_handle_t ofmt)
{
	char c;
	DIR *dirp;
	boolean_t list_only = B_FALSE;

	/* Peel off cmd. */
	argc -= 1;
	argv += 1;
	optind = 0;

	while ((c = getopt(argc, argv, ":l")) != -1) {
		switch (c) {
		case 'l':
			list_only = B_TRUE;
			break;

		case '?':
			ktest_usage("unknown mod-load option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	for (uint_t i = 0; i < (sizeof (mod_dirs) / sizeof (char *)); i++) {
		char *dir = mod_dirs[i];

		/*
		 * If a directory doesn't exist we ignore it and move on.
		 */
		if ((dirp = opendir(dir)) == NULL) {
			continue;
		}

		if (list_only) {
			ktest_list_dir(dir, dirp, ofmt);
		} else {
			ktest_load_dir(dir, dirp, ofmt);
		}

		(void) closedir(dirp);
	}
}

static void
ktest_print_stats(list_t *stats)
{
	ktest_stats_t *stat;
	ofmt_handle_t stats_ofmt;
	ofmt_status_t oferr;
	boolean_t first = B_FALSE;

	oferr = ofmt_open(KTEST_STATS_FIELDS, ktest_stats_ofmt, 0, 0,
	    &stats_ofmt);
	ofmt_check(oferr, B_FALSE, stats_ofmt, ktest_ofmt_errx, warnx);

	while ((stat = list_remove_head(stats)) != NULL) {
		if (!first && stat->ks_type == KTEST_STAT_MOD) {
			printf("\n");
		}

		ofmt_print(stats_ofmt, stat);

		if (stat->ks_type == KTEST_STAT_MOD) {
			first = B_FALSE;
			print_hr(68);
		}

		free(stat);
	}

	ofmt_close(stats_ofmt);
}

/*
 * Run all tests specified in the triples list, printing the result of
 * each test. The results are output in a parsable-friendly manner
 * when parsable is set.
 */
static void
ktest_run_tests(int dev, nvlist_t *triples, ofmt_handle_t ofmt,
    boolean_t print_stats)
{
	int ret = 0;
	ktest_run_op_t kro;
	ktest_read_msgs_op_t krm;
	ktest_stats_t *mod_stats = NULL, *suite_stats = NULL;
	list_t stats;

	bzero(&krm, sizeof (krm));
	kro.kro_triples_len = fnvlist_size(triples);
	kro.kro_triples_buf = malloc(kro.kro_triples_len);
	list_create(&stats, sizeof (ktest_stats_t), offsetof(ktest_stats_t,
		ks_node));

	if (kro.kro_triples_buf == NULL) {
		err(EXIT_FAILURE, "failed to allocate triples buffer");
	}

	ret = nvlist_pack(triples, &kro.kro_triples_buf, &kro.kro_triples_len,
	    NV_ENCODE_NATIVE, 0);

	if (ret != 0) {
		errx(EXIT_FAILURE, "failed to pack triples: %s", strerror(ret));
	}

	if ((ret = ioctl(dev, KTEST_IOCTL_RUN_TESTS, &kro)) == -1) {
		err(EXIT_FAILURE, "run test ioctl failed");
	}

	while ((ret = ioctl(dev, KTEST_IOCTL_READ_MSGS, &krm)) == 0) {
		for (uint_t i = 0; i < krm.krmo_count; i++) {
			ktest_msg_t *msg = &krm.krmo_msgs[i];

			if (msg->km_type != KTEST_MSG_RESULT) {
				continue;
			}

			if (suite_stats == NULL) {
				suite_stats = ktest_stats_new(KTEST_STAT_SUITE,
				    msg->km_suite);
			}

			if (mod_stats == NULL) {
				mod_stats = ktest_stats_new(KTEST_STAT_MOD,
				    msg->km_module);
			}

			if (strcmp(msg->km_suite, suite_stats->ks_name) != 0) {
				list_insert_head(&stats, suite_stats);
				suite_stats = ktest_stats_new(KTEST_STAT_SUITE,
				    msg->km_suite);
			}

			if (strcmp(msg->km_module, mod_stats->ks_name) != 0) {
				list_insert_head(&stats, mod_stats);
				mod_stats = ktest_stats_new(KTEST_STAT_MOD,
				    msg->km_module);
			}

			ktest_record_stat(mod_stats, suite_stats, msg);
			ofmt_print(ofmt, msg);
		}

		if (!krm.krmo_more) {
			if (suite_stats != NULL) {
				list_insert_head(&stats, suite_stats);
			}

			if (mod_stats != NULL) {
				list_insert_head(&stats, mod_stats);
			}

			break;
		}
	}

	if (ret != 0) {
		err(EXIT_FAILURE, "read messages ioctl failed");
	}

	/* Print the stats if enabled, otherwise just drain the list. */
	if (print_stats) {
		printf("\n");
		ktest_print_stats(&stats);
	} else {
		ktest_stats_t *stat;

		while ((stat = list_remove_head(&stats)) != NULL) {
			free(stat);
		}
	}

	list_destroy(&stats);

	if (kro.kro_triples_buf != NULL) {
		free(kro.kro_triples_buf);
	}
}

/*
 * Read file at path into a byte array. The byte array is allocated as
 * part of this function and ownership is handed over to the caller
 * via the bytes argument.
 */
static boolean_t
ktest_read_file_byte_array(const char *path, uchar_t **bytes, uint_t *len)
{
	FILE *f;
	struct stat stats;
	uchar_t *tmp_bytes;
	uint_t tmp_len;

	*bytes = NULL;
	*len = 0;

	if ((f = fopen(path, "r")) == NULL) {
		warn("failed to open input file %s", path);
		return (B_FALSE);
	}

	if (fstat(fileno(f), &stats) == -1) {
		warn("failed to stat input file %s", path);
		return (B_FALSE);
	}

	tmp_len = stats.st_size;

	if ((tmp_bytes = malloc(tmp_len)) == NULL) {
		warn("failed to allocate byte array of size %u", tmp_len);
		return (B_FALSE);
	}

	if (fread(tmp_bytes, sizeof (*tmp_bytes), tmp_len, f) != tmp_len) {
		warn("failed to read %u bytes from %s", tmp_len, path);
		return (B_FALSE);
	}

	(void) close(fileno(f));
	*bytes = tmp_bytes;
	*len = tmp_len;
	return (B_TRUE);
}

/*
 * Attempt to read the input file specified and attach its bytes to
 * the triple.
 *
 * TODO Replace this with kobj_{open,read}_file() in the ktest module
 * to avoid needless shuffling of bytes between user/kernel (e.g., see
 * devcache which uses these private APIs for the purpose of reading
 * serialized nvlists).
 */
static boolean_t
ktest_add_input(nvlist_t *triple, const char *path)
{
	uchar_t *bytes;
	uint_t len;

	if (!ktest_read_file_byte_array(path, &bytes, &len)) {
		return (B_FALSE);
	}

	fnvlist_add_string(triple, KTEST_INPUT_PATH_KEY, path);
	fnvlist_add_byte_array(triple, KTEST_INPUT_KEY, bytes, len);
	free(bytes);
	return (B_TRUE);
}

/*
 * Attempt to parse the test triple string, returning the resulting
 * nvlist triple representation via nv. This leaves the original
 * triple string untouched.
 */
static nvlist_t *
ktest_parse_triple(const char *tstr)
{
	char *cp = NULL, *orig = NULL;
	char *module = NULL;
	char *suite = NULL;
	char *test = NULL;
	nvlist_t *t;

	t = fnvlist_alloc();

	if ((cp = strdup(tstr)) == NULL) {
		perror("failed to dup triple string");
		return (NULL);
	}

	orig = cp;
	module = strsep(&cp, KTEST_SEPARATOR);

	if (*module == '\0')
		module = "*";

	if (cp == NULL) {
		suite = "*";
		test = "*";
		goto copy;
	}

	suite = strsep(&cp, KTEST_SEPARATOR);

	if (*suite == '\0')
		suite = "*";

	if (cp == NULL) {
		test = "*";
		goto copy;
	}

	if (strstr(cp, KTEST_SEPARATOR) != NULL) {
		perror("malformed test pattern, unexpected ':'");
		free(orig);
		return (NULL);
	}

	test = cp;

	if (*test == '\0')
		test = "*";

copy:
	fnvlist_add_string(t, KTEST_MODULE_KEY, module);
	fnvlist_add_string(t, KTEST_SUITE_KEY, suite);
	fnvlist_add_string(t, KTEST_TEST_KEY, test);
	free(orig);
	assert(t != NULL);
	return (t);
}

static void
ktest_add_triple(nvlist_t *list, nvlist_t *triple, uint32_t lineno)
{
	fnvlist_add_uint32(triple, KTEST_LINENO_KEY, lineno);
	fnvlist_add_nvlist(list, KTEST_TRIPLE_KEY, triple);

	if (triple != ktest_def_triple) {
		fnvlist_free(triple);
	}
}

/*
 * Attempt to load the run file specified and decode it into a run
 * list. Upon error print a message to stderr and return false.
 * Otherwise, return true. If path is "-", then treat stdin as the run
 * file.
 *
 * TODO Perhaps could eventually use something like glob(3C) to
 * perform tilde expansion (but only tilde expansion, not wildcards)
 * for input files. For now, the input file either needs to be in the
 * PWD, path relative to PWD, or an absolute path. Another thing to
 * possibly add is a search path list for input files.
 */
static void
ktest_load_run_file(const char *path, nvlist_t *run_list)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	uint32_t lineno = 0;
	boolean_t use_stdin = B_FALSE;
	boolean_t one_line = B_FALSE; /* At least one valid line? */

	if (strncmp("-", path, 1) == 0) {
		use_stdin = B_TRUE;
		f = stdin;
	} else {
		if ((f = fopen(path, "r")) == NULL) {
			err(EXIT_FAILURE, "failed to open run file %s", path);
		}
	}

	while ((len = getline(&line, &cap, f)) != -1) {
		char *input, *lasts, *tstr;
		nvlist_t *triple;

		lineno++;
		/* A line is always at least one character: newline. */
		assert(len >= 1);
		/* Stip the newline. */
		line[len - 1] = '\0';

		/* Skip empty lines. */
		if (line[0] == '\0') {
			continue;
		}

		/*
		 * A valid line consists of either a test triple on
		 * its own or a test triple and an input file
		 * separated by whitespace.
		 */
		tstr = strtok_r(line, " \t", &lasts);
		triple = ktest_parse_triple(tstr);

		if (triple == NULL) {
			errx(EXIT_FAILURE, "failed to parse triple %s at line "
			    "%u", tstr, lineno);
		}

		input = strtok_r(NULL, " \t", &lasts);

		if (input != NULL) {
			if (!ktest_add_input(triple, input)) {
				errx(EXIT_FAILURE, "failed to add input file "
				    "%s at line %u", input, lineno);
			}
		}

		ktest_add_triple(run_list, triple, lineno);
		one_line = B_TRUE;
	}

	if (!use_stdin) {
		(void) close(fileno(f));
	}

	free(line);

	if (!one_line) {
		errx(EXIT_FAILURE, "no tests specified in: %s", path);
	}
}

/*
 * Is this test triple fully-qualified?
 */
static boolean_t
ktest_is_fqt(nvlist_t *triple)
{
	char *module_name;
	char *suite_name;
	char *test_name;

	/*
	 * At this point we already know the triple contains the
	 * required fields, our job here is make sure there are no
	 * globs.
	 */
	assert0(nvlist_lookup_pairs(triple, 0,
	    KTEST_MODULE_KEY, DATA_TYPE_STRING, &module_name,
	    KTEST_SUITE_KEY, DATA_TYPE_STRING, &suite_name,
	    KTEST_TEST_KEY, DATA_TYPE_STRING, &test_name,
	    NULL));

	if (strpbrk(module_name, KTEST_GMATCH_CHARS) != NULL ||
	    strpbrk(suite_name, KTEST_GMATCH_CHARS) != NULL ||
	    strpbrk(test_name, KTEST_GMATCH_CHARS) != NULL) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Based on the passed in test list, does this fully-qualified triple
 * refer to a test which requires input?
 *
 * Any input to this function is known to contain all the required
 * fields for a test specification.
 */
static boolean_t
ktest_requires_input(nvlist_t *triple, nvlist_t *list)
{
	char *t_module_name;
	char *t_suite_name;
	char *t_test_name;
	nvpair_t *ser_fmt_vsn = nvlist_next_nvpair(list, NULL);
	uint64_t vsn;

	assert(ktest_is_fqt(triple));
	assert0(nvlist_lookup_pairs(triple, 0,
	    KTEST_MODULE_KEY, DATA_TYPE_STRING, &t_module_name,
	    KTEST_SUITE_KEY, DATA_TYPE_STRING, &t_suite_name,
	    KTEST_TEST_KEY, DATA_TYPE_STRING, &t_test_name,
	    NULL));

	/* TODO I need to put this into common function that verifies
	 * fmt and then returns first nvpair to start iterating on. */
	if (ser_fmt_vsn == NULL) {
		fprintf(stderr, "invalid list response, missing %s key\n",
		    KTEST_SER_FMT_KEY);
		return (B_FALSE);
	}

	if (strcmp(nvpair_name(ser_fmt_vsn), KTEST_SER_FMT_KEY) != 0) {
		fprintf(stderr, "invalid list response, missing %s key\n",
		    KTEST_SER_FMT_KEY);
		return (B_FALSE);
	}

	vsn = fnvpair_value_uint64(ser_fmt_vsn);
	if (vsn != KTEST_SER_FMT_VSN) {
		fprintf(stderr, "invalid serialization format version: %lu",
		    vsn);
		return (B_FALSE);
	}

	for (nvpair_t *mod = nvlist_next_nvpair(list, ser_fmt_vsn);
	    mod != NULL;
	    mod = nvlist_next_nvpair(list, mod)) {
		nvlist_t *moddesc;
		nvlist_t *suites;
		char *module_name;

		moddesc = fnvpair_value_nvlist(mod);
		assert0(nvlist_lookup_pairs(moddesc, 0,
		    "name", DATA_TYPE_STRING, &module_name,
		    "suites", DATA_TYPE_NVLIST, &suites,
		    NULL));

		for (nvpair_t *suite = nvlist_next_nvpair(suites, NULL);
		    suite != NULL;
		    suite = nvlist_next_nvpair(suites, suite)) {
			nvlist_t *suitedesc;
			nvlist_t *tests;
			char *suite_name;

			suitedesc = fnvpair_value_nvlist(suite);
			assert0(nvlist_lookup_pairs(suitedesc, 0,
			    "name", DATA_TYPE_STRING, &suite_name,
			    "tests", DATA_TYPE_NVLIST, &tests,
			    NULL));

			for (nvpair_t *test = nvlist_next_nvpair(tests, NULL);
			    test != NULL;
			    test = nvlist_next_nvpair(tests, test)) {
				nvlist_t *testdesc;
				char *test_name;
				boolean_t input_required;

				testdesc = fnvpair_value_nvlist(test);
				assert0(nvlist_lookup_pairs(testdesc, 0,
				    "name", DATA_TYPE_STRING, &test_name,
				    "input_required", DATA_TYPE_BOOLEAN_VALUE,
				    &input_required,
				    NULL));

				if (strcmp(module_name, t_module_name) == 0 &&
				    strcmp(suite_name, t_suite_name) == 0 &&
				    strcmp(test_name, t_test_name) == 0 &&
				    input_required) {
					return (B_TRUE);
				}
			}
		}
	}

	return (B_FALSE);
}

/*
 * When a triple is fully-qualified the assumption is that it _might_
 * be for the purpose of specifying an input file. If a triple is
 * fully-qualified, and it refers to a test which requires input, but
 * there is no associated input file, we let the user know with an
 * explicit message. We do not return error on the first test, but
 * instead print a warning for each test missing input and then exit
 * with an error.
 */
static void
ktest_check_missing_input(nvlist_t *run_list, nvlist_t *all_tests)
{
	boolean_t missing = B_FALSE;

	for (nvpair_t *p = nvlist_next_nvpair(run_list, NULL);
	    p != NULL;
	    p = nvlist_next_nvpair(run_list, p)) {
		nvlist_t *triple;
		char *module_name;
		char *suite_name;
		char *test_name;
		uint32_t lineno;

		triple = fnvpair_value_nvlist(p);
		assert0(nvlist_lookup_pairs(triple, 0,
		    KTEST_MODULE_KEY, DATA_TYPE_STRING, &module_name,
		    KTEST_SUITE_KEY, DATA_TYPE_STRING, &suite_name,
		    KTEST_TEST_KEY, DATA_TYPE_STRING, &test_name,
		    KTEST_LINENO_KEY, DATA_TYPE_UINT32, &lineno,
		    NULL));

		if (ktest_is_fqt(triple) &&
		    ktest_requires_input(triple, all_tests) &&
		    !nvlist_exists(triple, KTEST_INPUT_KEY)) {
			warnx("missing input for test (lineno: %u): %s:%s:%s",
			    lineno, module_name, suite_name, test_name);
			missing = B_TRUE;
		}
	}

	if (missing) {
		errx(EXIT_FAILURE, "one or more tests were found to be missing "
		    "input");
	}
}

/*
 * Verify that the run list is acceptable before sending the run op
 * down to the kernel.
 */
static void
ktest_verify_run_list(int dev, nvlist_t *run_list)
{
	int ret;
	nvlist_t *all, *response;

	if ((ret = nvlist_alloc(&all, 0, 0)) != 0) {
		errx(EXIT_FAILURE, "failed to alloc nvlist: %s", ret,
		    strerror(ret));
	}

	ktest_add_triple(all, ktest_def_triple, 0);
	ktest_list_tests(dev, all, &response);
	ktest_check_missing_input(run_list, response);
}

static void
ktest_run_cmd(int argc, char *argv[], int ktdev, ofmt_handle_t ofmt)
{
	char c;
	nvlist_t *run_list;
	char *run_file = NULL;
	char *input_file = NULL;
	int ret = 0;
	boolean_t print_stats = B_TRUE;
	extern char *optarg;

	/*
	 * We don't run all tests by default. We assume that as the
	 * library of test modules grows we want to be sure the user
	 * actually wants to run all tests by forcing them to at least
	 * specify the `*` filter.
	 */
	if (argc == 1) {
		ktest_usage("must specify at least one test");
		exit(EXIT_USAGE);
	}

	/* Peel off cmd. */
	argc -= 1;
	argv += 1;
	optind = 0;

	while ((c = getopt(argc, argv, ":f:i:N")) != -1) {
		switch (c) {
		case 'f':
			if (run_file != NULL) {
				ktest_usage("cannot specify -f more than once");
				exit(EXIT_USAGE);
			}

			run_file = optarg;
			break;

		case 'i':
			if (input_file != NULL) {
				ktest_usage("cannot specify -i more than once");
				exit(EXIT_USAGE);
			}

			input_file = optarg;
			break;

		case 'N':
			print_stats = B_FALSE;
			break;

		case '?':
			ktest_usage("unknown run option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (run_file != NULL && input_file != NULL) {
		ktest_usage("cannot specify both -f and -i");
		exit(EXIT_USAGE);
	}

	if ((ret = nvlist_alloc(&run_list, 0, 0)) != 0) {
		errx(EXIT_FAILURE, "failed to allocate run list: %s",
		    strerror(ret));
	}

	if (run_file) {
		ktest_load_run_file(run_file, run_list);
	} else {
		for (uint_t i = 0; i < argc; i++) {
			nvlist_t *triple = ktest_parse_triple(argv[i]);

			if (triple == NULL) {
				errx(EXIT_FAILURE, "failed to parse triple: %s",
				    argv[i]);
			}

			if (input_file != NULL) {
				if (!ktest_add_input(triple, input_file)) {
					exit(EXIT_FAILURE);
				}
			}

			ktest_add_triple(run_list, triple, 0);
		}
	}

	ktest_verify_run_list(ktdev, run_list);
	ktest_run_tests(ktdev, run_list, ofmt, print_stats);
	nvlist_free(run_list);
}

static void
ktest_list_cmd(int argc, char *argv[], int dev, ofmt_handle_t ofmt)
{
	int ret;
	nvlist_t *tlist = NULL;
	nvlist_t *response = NULL;

	if ((ret = nvlist_alloc(&tlist, 0, 0)) != 0) {
		errx(EXIT_FAILURE, "failed to allocate nvlist: %s",
		    strerror(ret));
	}

	if (argc == 1) {
		ktest_add_triple(tlist, ktest_def_triple, 0);
	} else {
		for (uint_t i = 1; i < argc; i++) {
			nvlist_t *triple = ktest_parse_triple(argv[i]);

			if (triple == NULL) {
				errx(EXIT_FAILURE, "failed to parse triple: %s",
				    argv[i]);
			}

			ktest_add_triple(tlist, triple, 0);
		}
	}

	ktest_list_tests(dev, tlist, &response);
	ktest_print_tests(response, ofmt);
	nvlist_free(response);
	nvlist_free(tlist);
}

static void
ktest_alloc_def_triple()
{
	ktest_def_triple = ktest_parse_triple(KTEST_DEF_TRIPLE);

	if (ktest_def_triple == NULL)
		err(EXIT_FAILURE, "failed to initialize default triple");
}

int
main(int argc, char *argv[])
{
	int fd;
	const char *cmd;
	int ret = 0;
	char c;
	extern int optind, optopt;
	extern char *optarg;
	boolean_t parsable = B_FALSE;
	char *fields = NULL;
	uint_t oflags = 0;
	ofmt_handle_t ofmt = NULL;
	ofmt_status_t oferr;

	ktest_prog = basename(argv[0]);

	if (getzoneid() != GLOBAL_ZONEID || getuid() != 0) {
		errx(EXIT_FAILURE, "can only be used by root from"
		    " the global zone");
	}

	while ((c = getopt(argc, argv, ":Ho:p")) != -1) {
		switch (c) {
		case 'H':
			oflags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'p':
			parsable = B_TRUE;
			oflags |= OFMT_PARSABLE;
			break;
		case '?':
			ktest_usage("Unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		ktest_usage("no command specified");
		exit(EXIT_USAGE);
	}

	cmd = argv[0];

	if ((fd = open("/dev/ktest", O_RDONLY, 0)) == -1) {
		err(EXIT_FAILURE, "failed to open /dev/ktest");
	}

	ktest_alloc_def_triple();

	if (strncasecmp("list", cmd, KTEST_CMD_SZ) == 0) {
		if (fields == NULL) {
			fields = KTEST_LIST_CMD_DEF_FIELDS;
		}

		oferr = ofmt_open(fields, ktest_list_ofmt, oflags, 0, &ofmt);
		ofmt_check(oferr, parsable, ofmt, ktest_ofmt_errx, warnx);
		ktest_list_cmd(argc, argv, fd, ofmt);
		ofmt_close(ofmt);
	} else if (strncasecmp("mod-load", cmd, KTEST_CMD_SZ) == 0) {
		if (fields == NULL) {
			fields = KTEST_MOD_LOAD_CMD_DEF_FIELDS;
		}

		oferr = ofmt_open(fields, ktest_mod_load_ofmt, oflags, 0,
		    &ofmt);
		ofmt_check(oferr, parsable, ofmt, ktest_ofmt_errx, warnx);
		ktest_mod_load_cmd(argc, argv, ofmt);
		ofmt_close(ofmt);
	} else if (strncasecmp("run", cmd, KTEST_CMD_SZ) == 0) {
		if (fields == NULL) {
			fields = KTEST_RUN_CMD_DEF_FIELDS;
		}

		assert(fields != NULL);
		oferr = ofmt_open(fields, ktest_run_ofmt, oflags, 0, &ofmt);
		ofmt_check(oferr, parsable, ofmt, ktest_ofmt_errx, warnx);
		ktest_run_cmd(argc, argv, fd, ofmt);
		ofmt_close(ofmt);
	} else if (strncasecmp("help", cmd, KTEST_CMD_SZ) == 0) {
		ktest_usage(NULL);
	} else {
		ktest_usage("unknown command: %s", argv[1]);
		ret = EXIT_USAGE;
	}

	(void) close(fd);
	return (ret);
}
