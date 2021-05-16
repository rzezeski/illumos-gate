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

/*
 * The kernel test driver.
 *
 * TODO Big theory statement on how the various bits of ktest fit
 * together.
 */
#include <sys/stddef.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ktest_impl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	KTEST_CTL_MINOR	0

dev_info_t	*ktest_dip;
ddi_taskq_t	*ktest_runner;

/*
 * The ktest_lock protects the test module list, running flag, and
 * events queue.
 *
 * The ktest_running_cv notifies when the running flag has changed to
 * B_FALSE. It is used to make sure we don't register/unregister tests
 * while the test runner task is currently iterating the list.
 *
 * The ktest_events_cv notifies when a new event is available for
 * reading or when tests have finished running in which case any
 * events that are going to be generated have been.
 */
kmutex_t	ktest_lock;
boolean_t	ktest_running;
kcondvar_t	ktest_running_cv;
list_t		ktest_events;
kcondvar_t	ktest_events_cv;

/*
 * The global list of registered ktest modules. A module must call
 * ktest_register_module() to register itself with the ktest framework.
 *
 * Protected by ktest_lock.
 */
list_t ktest_modules;

void
ktest_add_event(ktest_event_t *event)
{
	mutex_enter(&ktest_lock);
	list_insert_tail(&ktest_events, event);
	cv_signal(&ktest_events_cv);
	mutex_exit(&ktest_lock);
}

static ktest_msg_t *
ktest_event_to_msg(ktest_event_t *event)
{
	const ktest_test_t *test = event->ke_test;
	ktest_msg_t *msg = kmem_zalloc(sizeof (ktest_msg_t), KM_SLEEP);

	/*
	 * An error in the test runner itself has no associated test.
	 * However, the most likely cause for this type of failure
	 * would be a failed suite init/fini callback. In the future
	 * it might be beneficial to extend this data structure to
	 * more clearly distinguish exactly what failed, but for now we
	 * simply return an error code.
	 */
	if (event->ke_type == KTEST_EVENT_ERROR) {
		(void) strcpy(msg->km_module, "n/a");
		(void) strcpy(msg->km_suite, "n/a");
		(void) strcpy(msg->km_test, "n/a");
		msg->km_type = KTEST_MSG_ERROR;
		msg->km_u.km_err = event->ke_event.ke_err;
		return (msg);
	}

	CTASSERT(sizeof (msg->km_module) >=
	    sizeof (test->kt_suite->ks_module->km_name));
	(void) strcpy(msg->km_module, test->kt_suite->ks_module->km_name);
	CTASSERT(sizeof (msg->km_suite) >= sizeof (test->kt_suite->ks_name));
	(void) strcpy(msg->km_suite, test->kt_suite->ks_name);
	CTASSERT(sizeof (msg->km_test) >= sizeof (test->kt_name));
	(void) strcpy(msg->km_test, test->kt_name);

	switch (event->ke_type) {

	case KTEST_EVENT_RESULT:
		msg->km_type = KTEST_MSG_RESULT;
		CTASSERT(sizeof (msg->km_u.km_result.kmr_msg) >=
		    sizeof(event->ke_event.ke_result->kr_msg));
		(void) strcpy(msg->km_u.km_result.kmr_msg,
		    event->ke_event.ke_result->kr_msg);
		CTASSERT(sizeof (msg->km_u.km_result.kmr_msg_prepend) >=
		    sizeof(event->ke_event.ke_result->kr_msg_prepend));
		(void) strcpy(msg->km_u.km_result.kmr_msg_prepend,
		    event->ke_event.ke_result->kr_msg_prepend);
		CTASSERT(sizeof (msg->km_u.km_result.kmr_input_path) >=
		    sizeof(event->ke_event.ke_result->kr_input_path));
		(void) strcpy(msg->km_u.km_result.kmr_input_path,
		    event->ke_event.ke_result->kr_input_path);
		msg->km_u.km_result.kmr_type =
		    event->ke_event.ke_result->kr_type;
		msg->km_u.km_result.kmr_errno =
		    event->ke_event.ke_result->kr_errno;
		break;

	case KTEST_EVENT_ERROR:
		break;
	}

	return (msg);
}

static void
ktest_free_result(ktest_result_t *result)
{
	kmem_free(result, sizeof (*result));
}

static void
ktest_free_event(ktest_event_t *event)
{
	switch (event->ke_type) {
	case KTEST_EVENT_RESULT:
		ktest_free_result(event->ke_event.ke_result);
		break;

	case KTEST_EVENT_ERROR:
		break;
	}

	kmem_free(event, sizeof (*event));
}

/*
 * Make sure the module, suite, or test name contains no invalid
 * characters: namely any of the glob characters used by gmatch().
 */
static boolean_t
ktest_valid_name(const char *name)
{
	if (strpbrk(name, KTEST_GMATCH_CHARS) != NULL)
		return (B_FALSE);

	return (B_TRUE);
}

int
ktest_create_module(const char *name, const char *mod, ktest_module_hdl_t **km_hdl_out)
{
	ktest_module_t *km;

	if (!ktest_valid_name(name)) {
		return (EINVAL);
	}

	if (strnlen(name, sizeof (km->km_name)) == sizeof (km->km_name) ||
	    strnlen(mod, sizeof (km->km_name)) == sizeof (km->km_mod)) {
		return (EOVERFLOW);
	}

	if ((km = kmem_alloc(sizeof (*km), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	list_create(&km->km_suites, sizeof (ktest_suite_t),
	    offsetof(ktest_suite_t, ks_node));
	(void) strlcpy(km->km_name, name, sizeof (km->km_name));
	(void) strlcpy(km->km_mod, mod, sizeof (km->km_mod));
	*km_hdl_out = (ktest_module_hdl_t *)km;
	return (0);
}

int
ktest_create_suite(const char *name, ktest_suite_hdl_t **ks_hdl_out,
    ktest_init_fn init, ktest_fini_fn fini)
{
	ktest_suite_t *ks;
	ulong_t offset;

	if (!ktest_valid_name(name)) {
		return (EINVAL);
	}

	if (strnlen(name, sizeof (ks->ks_name)) == sizeof (ks->ks_name)) {
		return (EOVERFLOW);
	}

	if ((ks = kmem_alloc(sizeof (ktest_suite_t), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	list_create(&ks->ks_tests, sizeof (ktest_test_t),
	    offsetof(ktest_test_t, kt_node));

	(void) strlcpy(ks->ks_name, name, sizeof (ks->ks_name));
	ks->ks_init = init;
	ks->ks_fini = fini;

	if (init == NULL) {
		ks->ks_init_str = "NULL";
	} else {
		ks->ks_init_str = modgetsymname((uintptr_t)init, &offset);
	}

	VERIFY3P(ks->ks_init_str, !=, NULL);

	if (fini == NULL) {
		ks->ks_fini_str = "NULL";
	} else {
		ks->ks_fini_str = modgetsymname((uintptr_t)init, &offset);
	}

	VERIFY3P(ks->ks_init_str, !=, NULL);

	*ks_hdl_out = (ktest_suite_hdl_t *)ks;
	return (0);
}

void
ktest_add_suite(ktest_module_hdl_t *km_hdl, ktest_suite_hdl_t *ks_hdl)
{
	ktest_module_t *km = (ktest_module_t *)km_hdl;
	ktest_suite_t *ks = (ktest_suite_t *)ks_hdl;

	ks->ks_module = (ktest_module_t *)km_hdl;
	list_insert_tail(&km->km_suites, ks);
}

static int
ktest_create_test(ktest_test_t **test_out, ktest_suite_t *ks, const char *name,
    ktest_fn_t fn, ktest_test_flags_t flags)
{
	ktest_test_t *kt;
	boolean_t input = B_FALSE;

	if (!ktest_valid_name(name)) {
		return (EINVAL);
	}

	if (strnlen(name, sizeof (kt->kt_name)) == sizeof (kt->kt_name)) {
		return (EOVERFLOW);
	}

	if ((kt = kmem_alloc(sizeof (ktest_test_t), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	if ((flags & KTF_INPUT) != 0) {
		input = B_TRUE;
	}

	(void) strlcpy(kt->kt_name, name, sizeof (kt->kt_name));
	kt->kt_fn = fn;
	kt->kt_suite = ks;
	kt->kt_input = input;
	*test_out = kt;
	return (0);
}

/*
 * TODO Error if name contains ':' or ' '. In fact, perhaps just have
 * a list to verify test names are made up of alphanumeric plus some
 * special chars like '_'.
 */
int
ktest_add_test(ktest_suite_hdl_t *ks_hdl, const char *name, ktest_fn_t fn,
    ktest_test_flags_t flags)
{
	ktest_suite_t *ks = (ktest_suite_t *)ks_hdl;
	ktest_test_t *test;
	int ret;

	if ((ret = ktest_create_test(&test, ks, name, fn, flags)) != 0) {
		return (ret);
	}

	list_insert_tail(&ks->ks_tests, test);
	return (0);
}

void
ktest_register_module(ktest_module_hdl_t *km_hdl)
{
	ktest_module_t *km = (ktest_module_t *)km_hdl;

	mutex_enter(&ktest_lock);

	if (ktest_running) {
		cv_wait(&ktest_running_cv, &ktest_lock);
	}

	list_insert_tail(&ktest_modules, km);
	cv_signal(&ktest_running_cv);
	mutex_exit(&ktest_lock);
}

static void
ktest_free_test(ktest_test_t *test)
{
	kmem_free(test, sizeof (*test));
}

static void
ktest_free_suite(ktest_suite_t *ks)
{
	ktest_test_t *kt;

	while ((kt = list_remove_head(&ks->ks_tests)) != NULL) {
		ktest_free_test(kt);
	}

	list_destroy(&ks->ks_tests);
	kmem_free(ks, sizeof (*ks));
}

static void
ktest_free_module(ktest_module_t *km)
{
	ktest_suite_t *ks;

	while ((ks = list_remove_head(&km->km_suites)) != NULL) {
		ktest_free_suite(ks);
	}

	list_destroy(&km->km_suites);
	kmem_free(km, sizeof (*km));
}

void
ktest_unregister_module(const char *name)
{
	mutex_enter(&ktest_lock);

	if (ktest_running)
		cv_wait(&ktest_running_cv, &ktest_lock);

	for (ktest_module_t *km = list_head(&ktest_modules);
	    km != NULL;
	    km = list_next(&ktest_modules, km)) {
		if (strncmp(name, km->km_name, KTEST_MAX_NAME_LEN) == 0) {
			list_remove(&ktest_modules, km);
			ktest_free_module(km);
			break;
		}
	}

	cv_signal(&ktest_running_cv);
	mutex_exit(&ktest_lock);
}

/*
 * Unregister all test modules. It is up to the caller to make sure
 * all running tests have finished executing.
 */
static void
ktest_unregister_all()
{
	mutex_enter(&ktest_lock);
	VERIFY(!ktest_running);

	for (ktest_module_t *km = list_head(&ktest_modules);
	    km != NULL;
	    km = list_next(&ktest_modules, km)) {
		list_remove(&ktest_modules, km);
		ktest_free_module(km);
	}

	mutex_exit(&ktest_lock);
}

/*
 * TODO Is there a way to link the static functions of the
 * module-under-test to the test module? It would be nice to avoid
 * this dynamic loading.
 */
int
ktest_get_fn(ddi_modhandle_t hdl, const char *fn_name, void **fn)
{
	int err;

	if ((*fn = ddi_modsym(hdl, fn_name, &err)) == NULL)
		return (err);

	return (0);
}

/*
 * Get the input stream for this test. The contract for this API
 * guarantees that if it is called, then there MUST be an input
 * stream. It does this by VERIFYing that a) the test's kt_input flag
 * is set, and b) that the ktc_input is non-NULL. This means that
 * failure to set an input stream on a test which requires it will
 * result in a kernel panic. That may seem extreme, however, consider
 * that this is meant to be discovered at development time, and that
 * the ktest cmd also takes steps to ensure that any test which
 * requires input has an input stream specified. The impetus for this
 * contract is to avoid checking for valid input in every test -- it
 * allows the test to assume the input is there and categorically
 * catch any case where it is not.
 *
 * This contract does not preclude the possibility of a 0-byte stream,
 * which may be a valid test case for some tests. It only precludes a
 * non-existent stream.
 */
void
ktest_get_input(const ktest_ctx_hdl_t *hdl, uchar_t **input, size_t *len)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	VERIFY(ctx->ktc_test->kt_input == B_TRUE);
	VERIFY3P(ctx->ktc_input, !=, NULL);
	*len = ctx->ktc_input_len;
	*input = ctx->ktc_input;
}

/*
 * Remember, ddi_modhandle_t is a pointer, so hdl is pointer to pointer.
 */
int
ktest_hold_mod(const char *module, ddi_modhandle_t *hdl)
{
	int err;

	if ((*hdl = ddi_modopen(module, KRTLD_MODE_FIRST, &err)) == NULL) {
		return (err);
	}

	return (0);
}

void
ktest_release_mod(ddi_modhandle_t hdl)
{
	(void) ddi_modclose(hdl);
}

void
ktest_result_skip(ktest_ctx_hdl_t *hdl, const char *format, ...)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	char *msg = ctx->ktc_res->kr_msg;
	size_t written;
	va_list adx;

	ctx->ktc_res->kr_type = KTEST_SKIP;

	va_start(adx, format);
	written = vsnprintf(msg, KTEST_MAX_LOG_LEN, format, adx);

	/* Subtract one to account for the implicit NULL byte. */
	if (written > (KTEST_MAX_LOG_LEN - 1)) {
		cmn_err(CE_WARN, "test result message truncated");
	}

	va_end(adx);
}

void
ktest_result_fail(ktest_ctx_hdl_t *hdl, const char *format, ...)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	char *msg = ctx->ktc_res->kr_msg;
	size_t written;
	va_list adx;

	ctx->ktc_res->kr_type = KTEST_FAIL;

	va_start(adx, format);
	written = vsnprintf(msg, KTEST_MAX_LOG_LEN, format, adx);
	/* Subtract one to account for the implicit NULL byte. */
	if (written > (KTEST_MAX_LOG_LEN - 1)) {
		cmn_err(CE_WARN, "test result message truncated");
	}
	va_end(adx);
}

void
ktest_result_error(ktest_ctx_hdl_t *hdl, const char *format, ...)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	char *msg = ctx->ktc_res->kr_msg;
	size_t written;
	va_list adx;

	ctx->ktc_res->kr_type = KTEST_ERROR;

	va_start(adx, format);
	written = vsnprintf(msg, KTEST_MAX_LOG_LEN, format, adx);
	/* Subtract one to account for the implicit NULL byte. */
	if (written > (KTEST_MAX_LOG_LEN - 1)) {
		cmn_err(CE_WARN, "test result message truncated");
	}
	va_end(adx);
}

void
ktest_result_pass(ktest_ctx_hdl_t *hdl)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	ctx->ktc_res->kr_type = KTEST_PASS;
}

/*
 * Clear the prepend message, undoing any message set by ktest_msg_prepend().
 */
void
ktest_msg_clear(ktest_ctx_hdl_t *hdl)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	ctx->ktc_res->kr_msg_prepend[0] = '\0';
}

/*
 * Prepend formatted text to the result message. This is useful in
 * cases where the KT_ASSERT macro's generated message doesn't convey
 * enough context to determine the precise cause of the error. By
 * prepending the formatted text you can add additional context while
 * still using the KT_ASSERT macros (and not having to remiplement
 * them yourself). This overwrites any existing prepend text.
 */
void
ktest_msg_prepend(ktest_ctx_hdl_t *hdl, const char *format, ...)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	char *msg = ctx->ktc_res->kr_msg_prepend;
	size_t written;
	va_list adx;

	va_start(adx, format);
	written = vsnprintf(msg, KTEST_MAX_LOG_LEN, format, adx);
	/* Subtract one to account for the implicit NULL byte. */
	if (written > (KTEST_MAX_LOG_LEN - 1)) {
		cmn_err(CE_WARN, "test result message truncated");
	}
	va_end(adx);
}

/*
 * Given a module, suite, or test value, determine if it matches any
 * of the triples.
 */
static boolean_t
ktest_match(const ktest_match_t key, const char *value, nvlist_t *triples)
{
	nvpair_t *p;

	for (p = nvlist_next_nvpair(triples, NULL);
	     p != NULL;
	     p = nvlist_next_nvpair(triples, p)) {
		char *name = nvpair_name(p);
		char *mod = NULL;
		char *suite = NULL;
		char *test = NULL;
		char *match = NULL;
		nvlist_t *triple = NULL;

		/*
		 * Let's just make sure no unexpected nvlists are
		 * making their way in here.
		 */
		VERIFY3S(strcmp(name, KTEST_TRIPLE_KEY), ==, 0);
		VERIFY0(nvpair_value_nvlist(p, &triple));
		VERIFY0(nvlist_lookup_pairs(triple, 0,
			KTEST_MODULE_KEY, DATA_TYPE_STRING, &mod,
			KTEST_SUITE_KEY, DATA_TYPE_STRING, &suite,
			KTEST_TEST_KEY, DATA_TYPE_STRING, &test,
			NULL));

		switch (key) {
		case KTEST_MATCH_MODULE:
			match = mod;
			break;

		case KTEST_MATCH_SUITE:
			match = suite;
			break;

		case KTEST_MATCH_TEST:
			match = test;
			break;
		}

		ASSERT3P(match, !=, NULL);
		if (gmatch(value, match) != 0)
			return (B_TRUE);

	}

	return (B_FALSE);
}

static boolean_t
ktest_match_mod(const ktest_module_t *km, nvlist_t *triples)
{
	return (ktest_match(KTEST_MATCH_MODULE, km->km_name, triples));
}

static boolean_t
ktest_match_suite(const ktest_suite_t *ks, nvlist_t *triples)
{
	return (ktest_match(KTEST_MATCH_SUITE, ks->ks_name, triples));
}

static boolean_t
ktest_match_test(const ktest_test_t *kt, nvlist_t *triples)
{
	return (ktest_match(KTEST_MATCH_TEST, kt->kt_name, triples));
}

/*
 * Each `{:}` represnts an nvpair, each `[,]` represents an nvlist.
 *
 * Test nvlist
 * -----------
 *
 * [{"name":"<test_name>"},
 *  {"input_required":boolean_t}]
 *
 * Tests nvlist
 * ------------
 *
 * [{"test1":<test1_nvlist>},
 *  {"test2":<test2_nvlist>"},
 *  ...]
 *
 * Suite nvlist
 * ------------
 *
 * [{"name":"<ks->ks_name>"},
 *  {"init":"<ks->ks_init>"},
 *  {"fini":"<ks->ks_fini>"},
 *  {"tests":<tests_nvlist>}]
 *
 * Suites nvlist
 * -------------
 *
 * [{"suite1":<suite1_nvlist>},
 *  {"suite2":<suite2_nvlist>},
 *  ...]
 *
 * Module nvlist
 * -------------
 *
 * [{"name":"<km->km_name>"},
 *  {"suites":<suites_nvlist>}]
 *
 * Modules nvlist
 * --------------
 *
 * [{"ser_fmt_version":1},
 *  {"module1":<module1_nvlist>},
 *  {"module2":<module2_nvlist>},
 *  ...]
 */
int
ktest_list_tests(ktest_list_op_t *klo, nvlist_t *triples)
{
	nvlist_t *modules;
	char *buf = NULL;
	size_t len = 0;

	/*
	 * The first thing we add is a uint64_t ser_fmt_version field.
	 * This field allows any consumer of this nvlist (namely the
	 * ktest(1) cmd) to know which serialization format it is in.
	 * Specifically, the format version tells the consumer which
	 * fields to expect and how they are laid out. Given that the
	 * ktest kernel facility and its user command are welded to
	 * the system, this should never be needed. However, including
	 * a versioned format now keeps the future flexible, and
	 * costs us nothing.
	 */
	modules = fnvlist_alloc();
	fnvlist_add_uint64(modules, "ser_fmt_version", 1ULL);

	for (ktest_module_t *km = list_head(&ktest_modules);
	    km != NULL;
	    km = list_next(&ktest_modules, km)) {
		nvlist_t *module;
		nvlist_t *suites;

		if (!ktest_match_mod(km, triples))
			continue;

		module = fnvlist_alloc();
		suites = fnvlist_alloc();

		for (ktest_suite_t *ks = list_head(&km->km_suites);
		    ks != NULL;
		    ks = list_next(&km->km_suites, ks)) {
			nvlist_t *suite;
			nvlist_t *tests;

			if (!ktest_match_suite(ks, triples))
				continue;

			suite = fnvlist_alloc();
			tests = fnvlist_alloc();

			for (ktest_test_t *kt = list_head(&ks->ks_tests);
			    kt != NULL;
			    kt = list_next(&ks->ks_tests, kt)) {
				nvlist_t *test;

				if (!ktest_match_test(kt, triples))
					continue;

				test = fnvlist_alloc();
				fnvlist_add_string(test, "name", kt->kt_name);
				fnvlist_add_boolean_value(test,
				    "input_required", kt->kt_input);
				fnvlist_add_nvlist(tests, kt->kt_name, test);
				nvlist_free(test);
			}

			if (nvlist_empty(tests)) {
				nvlist_free(tests);
				nvlist_free(suite);
				continue;
			}

			fnvlist_add_string(suite, "name", ks->ks_name);
			fnvlist_add_string(suite, KTEST_SUITE_INIT_KEY,
			    ks->ks_init_str);
			fnvlist_add_string(suite, KTEST_SUITE_FINI_KEY,
			    ks->ks_fini_str);
			fnvlist_add_nvlist(suite, "tests", tests);
			fnvlist_add_nvlist(suites, ks->ks_name, suite);
			nvlist_free(tests);
			nvlist_free(suite);
		}

		if (nvlist_empty(suites)) {
			nvlist_free(suites);
			nvlist_free(module);
			continue;
		}

		fnvlist_add_string(module, "name", km->km_name);
		fnvlist_add_nvlist(module, "suites", suites);
		fnvlist_add_nvlist(modules, km->km_name, module);
		nvlist_free(suites);
		nvlist_free(module);
	}

	buf = fnvlist_pack(modules, &len);

	if (klo->klo_resp_len < len) {
		nvlist_free(modules);
		return (ENOBUFS);
	}

	nvlist_free(modules);

	if (copyout(buf, klo->klo_resp, len) != 0) {
		kmem_free(buf, len);
		return (EFAULT);
	}

	klo->klo_resp_len = len;
	kmem_free(buf, len);
	return (0);
}

static void
ktest_run_test(const ktest_test_t *kt, char *path, uchar_t *input,
    uint_t input_len)
{
	ktest_ctx_t ctx;
	ktest_result_t *res = kmem_zalloc(sizeof (ktest_result_t), KM_SLEEP);
	ktest_event_t *result = kmem_zalloc(sizeof (ktest_event_t), KM_SLEEP);

	res->kr_type = KTEST_UNINIT;
	res->kr_test = kt;
	/*
	 * The nvlist may go away before the result is converted to a
	 * message to be returned to the user, so we copy here.
	 */
	res->kr_input_path = strdup(path);
	ctx.ktc_test = kt;
	ctx.ktc_res = res;
	ctx.ktc_input = input;
	ctx.ktc_input_len = input_len;

	kt->kt_fn((ktest_ctx_hdl_t *)&ctx);

	VERIFY3S(ctx.ktc_res->kr_type, !=, KTEST_UNINIT);
	result->ke_test = kt;
	result->ke_type = KTEST_EVENT_RESULT;
	result->ke_event.ke_result = res;
	ktest_add_event(result);
}

static int
ktest_init_suite(ktest_suite_t *ks)
{
	if (ks->ks_init == NULL || ks->ks_initialized)
		return (0);

	return (ks->ks_init());
}

static int
ktest_fini_suite(ktest_suite_t *ks)
{
	if (ks->ks_fini == NULL || !ks->ks_initialized)
		return (0);

	return (ks->ks_fini());
}

/*
 * Run this test if any triples match. A test with no input ony has
 * one unique way to run, and thus only needs to run once. A test that
 * requires input will run once for each matching triple with an
 * attached input stream.
 */
static int
ktest_run_matches(ktest_test_t *kt, nvlist_t *triples)
{
	for (nvpair_t *p = nvlist_next_nvpair(triples, NULL);
	     p != NULL;
	     p = nvlist_next_nvpair(triples, p)) {
		char *name = nvpair_name(p);
		char *mod = NULL;
		char *suite = NULL;
		char *test = NULL;
		nvlist_t *triple = NULL;
		char *input_path;
		uchar_t *bytes;
		uint_t len;
		int ret;

		/*
		 * Let's just make sure no unexpected nvlists are
		 * making their way in here.
		 */
		VERIFY3S(strcmp(name, KTEST_TRIPLE_KEY), ==, 0);
		VERIFY0(nvpair_value_nvlist(p, &triple));
		VERIFY0(nvlist_lookup_pairs(triple, 0,
		    KTEST_MODULE_KEY, DATA_TYPE_STRING, &mod,
		    KTEST_SUITE_KEY, DATA_TYPE_STRING, &suite,
		    KTEST_TEST_KEY, DATA_TYPE_STRING, &test,
		    NULL));

		/* Skip this triple if it is not a match. */
		if (gmatch(kt->kt_suite->ks_module->km_name, mod) == 0 ||
		    gmatch(kt->kt_suite->ks_name, suite) == 0 ||
		    gmatch(kt->kt_name, test) == 0) {
			continue;
		}

		/*
		 * If this test does not require input, then there is
		 * only one unique way to run it.
		 */
		if (!kt->kt_input) {
			if ((ret = ktest_init_suite(kt->kt_suite)) != 0)
					return (ret);

			ktest_run_test(kt, "", NULL, 0);
			return (0);
		}

		/*
		 * This test requires input but this triple does not
		 * have one attached -- ignore and move on.
		 */
		if (!nvlist_exists(triple, KTEST_INPUT_KEY) ||
		    !nvlist_exists(triple, KTEST_INPUT_PATH_KEY)) {
			continue;
		}

		VERIFY0(nvlist_lookup_byte_array(triple, KTEST_INPUT_KEY,
			&bytes, &len));
		input_path = fnvlist_lookup_string(triple,
		    KTEST_INPUT_PATH_KEY);
		ktest_run_test(kt, input_path, bytes, len);
	}

	return (0);
}

/*
 * Run all tests in the suite with a matching triple.
 *
 * A test that does not require input (kt_input == B_FALSE) is
 * executed as long as there exists one matching triple.
 *
 * A test that requires input is executed if and only if there is a
 * matching triple with an input attached. That is, the test is run
 * regardless if the triple is partially or fully-qualified, so long
 * as there is an input stream attached to the triple. This behavior
 * allows a user to run many tests against the same input stream
 * without fully qualifying each triple.
 *
 * Before a test is executed, we first call the ktest_init_suite()
 * function to make sure that the suite has been initialized. After
 * all matching tests in a suite have executed, we make sure to call
 * ktest_fini_suite() to run any suite-level cleanup. These functions
 * make sure that initilization is only run once and that cleanup is
 * only run if initilization was run.
 */
static int
ktest_run_suite(ktest_suite_t *ks, nvlist_t *triples) {
	for (ktest_test_t *kt = list_head(&ks->ks_tests); kt != NULL;
	    kt = list_next(&ks->ks_tests, kt)) {
		int ret;

		if ((ret = ktest_run_matches(kt, triples)) != 0) {
			(void) ktest_fini_suite(ks);
			return (ret);
		}
	}

	return (ktest_fini_suite(ks));
}

static int
ktest_run_module(ktest_module_t *km, nvlist_t *triples)
{
	for (ktest_suite_t *ks = list_head(&km->km_suites); ks != NULL;
	    ks = list_next(&km->km_suites, ks)) {
		int ret;

		ret = ktest_run_suite(ks, triples);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

/*
 * Iterate through all registered tests, running all tests specified
 * via the triples argument. This may result in the same test being
 * run multiple times, once for each run op that matches. The intent
 * behind this is to allow a user to execute the same test with
 * multiple different input streams.
 *
 * This function always runs in the context of a taskq thread.
 */
static void
ktest_run_tests(void *arg)
{
	nvlist_t *triples = arg;
	ktest_module_t *km;
	int ret = 0;

	for (km = list_head(&ktest_modules); km != NULL;
	    km = list_next(&ktest_modules, km)) {
		if ((ret = ktest_run_module(km, triples)) != 0)
			break;
	}

	if (ret != 0) {
		ktest_event_t *err = kmem_zalloc(sizeof (ktest_event_t),
		    KM_SLEEP);
		err->ke_test = NULL;
		err->ke_type = KTEST_EVENT_ERROR;
		err->ke_event.ke_err = ret;
		ktest_add_event(err);
	}

	mutex_enter(&ktest_lock);
	/*
	 * Notify any threads waiting for the tests to stop
	 * running.
	 */
	ktest_running = B_FALSE;
	cv_signal(&ktest_running_cv);

	/*
	 * Notify the the thread waiting for events that it can
	 * resume. At this point the tests have finished running and
	 * all remaining events are waiting on the event queue.
	 */
	cv_signal(&ktest_events_cv);
	mutex_exit(&ktest_lock);
	nvlist_free(triples);
}

static int
ktest_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = ktest_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)0;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
ktest_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd == DDI_RESUME) {
		ddi_taskq_resume(ktest_runner);
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "ktest", S_IFCHR, KTEST_CTL_MINOR,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	ktest_runner = ddi_taskq_create(dip, "ktest_taskq", 1, TASKQ_DEFAULTPRI,
	    0);
	if (ktest_runner == NULL) {
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	ktest_dip = dip;
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
ktest_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ktest_event_t *event;
	VERIFY(!ktest_running);

	if (cmd == DDI_SUSPEND) {
		ddi_taskq_suspend(ktest_runner);
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	ddi_taskq_destroy(ktest_runner);

	/*
	 * It may be that the user application did not read all events
	 * before closing the device. Make sure to cleanup any
	 * orphaned events.
	 */
	while ((event = list_remove_head(&ktest_events)) != NULL) {
		ktest_free_event(event);
	}

	ddi_remove_minor_node(dip, NULL);
	ktest_dip = NULL;
	return (DDI_SUCCESS);
}

static int
ktest_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	/* Make sure attach(9E) has completed. */
	if (ktest_dip == NULL) {
		return (ENXIO);
	}

	if (getminor(*devp) != KTEST_CTL_MINOR) {
		return (ENXIO);
	}

	if (flag & FWRITE) {
		return (EACCES);
	}

	if (flag & FEXCL) {
		return (ENOTSUP);
	}

	/*
	 * Access to the ktest facility requires the utmost respect:
	 * test modules have full access to the kernel address space
	 * and the user executing ktest can pipe in any arbitrary
	 * stream of bytes to any test which takes an input stream.
	 * Given this liability, and the fact the test facility should
	 * mostly be used for development quality assurance or
	 * production pre-flight checklists or healtchecks, it makes
	 * sense to restrict the loading, listing, and execution of
	 * tests to those with the highest of privilege: the root
	 * role/user in the Global Zone.
	 */
	if (drv_priv(credp) != 0 || crgetzoneid(credp) != GLOBAL_ZONEID) {
		return (EPERM);
	}

	return (0);
}

static int
ktest_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	return (0);
}

static int
ktest_read_msgs(ktest_read_msgs_op_t *krm)
{
	ktest_event_t *event;

	krm->krmo_more = B_TRUE;
	krm->krmo_count = 0;
	mutex_enter(&ktest_lock);

	/*
	 * We've reached the end of the events stream, indicate the
	 * end of stream and return.
	 */
	if (!ktest_running && list_is_empty(&ktest_events)) {
		mutex_exit(&ktest_lock);
		krm->krmo_more = B_FALSE;
		return (0);
	}

	/*
	 * We know that tests are running, so wait for a new event.
	 */
	if (list_is_empty(&ktest_events) &&
	    cv_wait_sig(&ktest_events_cv, &ktest_lock) == 0) {
		mutex_exit(&ktest_lock);
		return (EINTR);
	}

	/*
	 * There's a chance the user could have input a triples list
	 * that matches no tests, and in that case there are no events
	 * to read.
	 */
	if (!ktest_running && list_is_empty(&ktest_events)) {
		mutex_exit(&ktest_lock);
		krm->krmo_more = B_FALSE;
		return (0);
	}

	VERIFY(!list_is_empty(&ktest_events));

	while (krm->krmo_count < KTEST_READ_MSG_COUNT &&
	    (event = list_remove_head(&ktest_events)) != NULL) {
		ktest_msg_t *msg;

		mutex_exit(&ktest_lock);
		msg = ktest_event_to_msg(event);
		bcopy(msg, &krm->krmo_msgs[krm->krmo_count], sizeof (*msg));
		krm->krmo_count++;
		kmem_free(msg, sizeof (*msg));
		mutex_enter(&ktest_lock);
	}

	mutex_exit(&ktest_lock);
	VERIFY3U(krm->krmo_count, >, 0);
	return (0);
}

static int
ktest_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	/*
	 * For now we make two assumptions.
	 *
	 *  1. That only the ktest command interacts with the ktest driver.
	 *
	 *  2. The the ktest command is 64-bit.
	 */
	if (ddi_model_convert_from(mode) != DDI_MODEL_NONE)
		return (ENOSYS);

	switch (cmd) {
	case KTEST_IOCTL_READ_MSGS: {
		int ret = 0;
		ktest_read_msgs_op_t *krm;

		krm = kmem_zalloc(sizeof (*krm), KM_SLEEP);

		if (ddi_copyin((void *)arg, krm, sizeof (*krm), mode) != 0)
			return (EFAULT);

		if ((ret = ktest_read_msgs(krm)) != 0)
			return (ret);

		if (ddi_copyout(krm, (void *)arg, sizeof (*krm), mode) != 0)
			return (EFAULT);

		break;
	}

	case KTEST_IOCTL_RUN_TESTS: {
		ktest_run_op_t kro;
		char *tmp = NULL;
		nvlist_t *triples;
		int ret = 0;

		mutex_enter(&ktest_lock);
		if (ktest_running)
			return (EBUSY);

		ktest_running = B_TRUE;
		mutex_exit(&ktest_lock);

		bzero(&kro, sizeof (kro));
		if (ddi_copyin((void *)arg, &kro, sizeof (kro), mode) != 0) {
			ret = EFAULT;
			goto run_error;
		}

		tmp = kmem_alloc(kro.kro_triples_len, KM_SLEEP);

		if (ddi_copyin((void *)kro.kro_triples_buf, tmp,
			kro.kro_triples_len, mode) != 0) {
			ret = EFAULT;
			kmem_free(tmp, kro.kro_triples_len);
			goto run_error;
		}

		ret = nvlist_unpack(tmp, kro.kro_triples_len, &triples, 0);
		if (ret != 0) {
			kmem_free(tmp, kro.kro_triples_len);
			ret = EINVAL;
			goto run_error;
		}

		kmem_free(tmp, kro.kro_triples_len);

		/*
		 * In the case of successful dispatch it is up to
		 * the task callback to free the triples list.
		 */
		if (ddi_taskq_dispatch(ktest_runner, ktest_run_tests, triples,
		    DDI_SLEEP) != DDI_SUCCESS) {
			ret = EFAULT;
			goto run_error;
		}

		break;

run_error:
		mutex_enter(&ktest_lock);
		ktest_running = B_FALSE;
		cv_signal(&ktest_running_cv);
		cv_signal(&ktest_events_cv);
		mutex_exit(&ktest_lock);
		return (ret);
	}

	case KTEST_IOCTL_LIST_TESTS: {
		int ret = 0;
		ktest_list_op_t klo;
		char *tmp = NULL;
		nvlist_t *triples;

		bzero(&klo, sizeof (klo));
		if (ddi_copyin((void *)arg, &klo, sizeof (klo), mode) != 0) {
			return (EFAULT);
		}

		tmp = kmem_alloc(klo.klo_triples_len, KM_SLEEP);

		if (ddi_copyin((void *)klo.klo_triples_buf, tmp,
			klo.klo_triples_len, mode) != 0) {
			kmem_free(tmp, klo.klo_triples_len);
			return (EFAULT);
		}

		ret = nvlist_unpack(tmp, klo.klo_triples_len, &triples, 0);

		if (ret != 0) {
			kmem_free(tmp, klo.klo_triples_len);
			return (EINVAL);
		}

		kmem_free(tmp, klo.klo_triples_len);

		if ((ret = ktest_list_tests(&klo, triples)) == 0) {
			if (ddi_copyout(&klo, (void *)arg, sizeof (klo),
			    mode) != 0)
				ret = EFAULT;
		}

		nvlist_free(triples);
		return (ret);
	}

	default:
		return (EINVAL);
	}

	return (0);
}

static struct cb_ops ktest_cb_ops = {
	.cb_open = ktest_open,
	.cb_close = ktest_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = ktest_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP | D_64BIT,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev,
	.cb_str = NULL
};

static struct dev_ops ktest_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = ktest_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ktest_attach,
	.devo_detach = ktest_detach,
	.devo_reset = nodev,
	.devo_power = NULL,
	.devo_quiesce = ddi_quiesce_not_supported,
	.devo_cb_ops = &ktest_cb_ops,
	.devo_bus_ops = NULL
};

static struct modldrv ktest_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Kernel Test Driver v1",
	.drv_dev_ops = &ktest_dev_ops
};

static struct modlinkage ktest_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ktest_modldrv, NULL }
};

static void
ktest_fini()
{
	/*
	 * By this point no tests are running, the taskq is destroyed,
	 * and all events have been freed. The only thing left is to
	 * unregister the tests and teardown the global structures.
	 */
	VERIFY(!ktest_running);
	ktest_unregister_all();
	cv_destroy(&ktest_events_cv);
	list_destroy(&ktest_events);
	cv_destroy(&ktest_running_cv);
	list_destroy(&ktest_modules);
	mutex_destroy(&ktest_lock);
}

/*
 * This is a pseudo device driver with a single instance, therefore
 * all state is allocated/freed during init/fini. We delay the
 * creation of the taskq until attach, since tests cannot be executed
 * until the driver is attached.
 */
int
_init(void)
{
	int ret;

	mutex_init(&ktest_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&ktest_modules, sizeof (ktest_module_t),
	    offsetof(ktest_module_t, km_node));

	ktest_running = B_FALSE;
	cv_init(&ktest_running_cv, NULL, CV_DRIVER, NULL);

	list_create(&ktest_events, sizeof (ktest_event_t),
	    offsetof(ktest_event_t, ke_node));
	cv_init(&ktest_events_cv, NULL, CV_DRIVER, NULL);

	ret = mod_install(&ktest_modlinkage);

	if (ret != DDI_SUCCESS)
		ktest_fini();

	return (ret);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&ktest_modlinkage);

	if (ret == DDI_SUCCESS)
		ktest_fini();

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ktest_modlinkage, modinfop));
}
