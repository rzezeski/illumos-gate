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
 * This file contains the private implementation details of the ktest
 * facility -- which is limited strictly to the kernel. Neither
 * userspace nor ktest modules should include this file or rely on any
 * definitions inside it. Rather, userspace programs and ktest modules
 * should include sys/ktest.h for access to the appropriate APIs.
 */
#ifndef	_SYS_KTEST_IMPL_H
#define	_SYS_KTEST_IMPL_H

#include <sys/ktest.h>
#include <sys/list.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

typedef enum ktest_match {
	KTEST_MATCH_MODULE,
	KTEST_MATCH_SUITE,
	KTEST_MATCH_TEST
} ktest_match_t;

/*
 * TODO: Explain how the structures fit together and probably add some
 * ASCII art to visually show relationship.
 */
typedef struct ktest_module {
	list_node_t	km_node;
	char		km_name[KTEST_MAX_NAME_LEN];
	char		km_mod[KTEST_MAX_NAME_LEN];
	list_t		km_suites;
} ktest_module_t;

typedef struct ktest_suite {
	list_node_t	ks_node;
	ktest_module_t	*ks_module;
	char		ks_name[KTEST_MAX_NAME_LEN];
	ktest_init_fn	ks_init;
	char		*ks_init_str;
	ktest_fini_fn	ks_fini;
	char		*ks_fini_str;
	boolean_t	ks_initialized;
	list_t		ks_tests;
} ktest_suite_t;

typedef struct ktest_test {
	list_node_t	kt_node;
	ktest_suite_t	*kt_suite;
	char		kt_name[KTEST_MAX_NAME_LEN];
	ktest_fn_t	kt_fn;
	boolean_t	kt_input; /* Input required? */
} ktest_test_t;

typedef struct ktest_result {
	list_node_t		kr_node;
	ktest_result_type_t	kr_type;
	int			kr_errno;
	const ktest_test_t	*kr_test;
	char			*kr_input_path;
	char			kr_msg_prepend[KTEST_MAX_LOG_LEN];
	char			kr_msg[KTEST_MAX_LOG_LEN];
} ktest_result_t;

typedef struct ktest_ctx {
	const ktest_test_t	*ktc_test;
	ktest_result_t		*ktc_res;
	uchar_t			*ktc_input;
	uint_t			ktc_input_len;
} ktest_ctx_t;

typedef enum ktest_event_type {
	KTEST_EVENT_RESULT,
	KTEST_EVENT_ERROR,	/* error in test runner itself */
} ktest_event_type_t;

typedef struct ktest_event {
	list_node_t		ke_node;
	const ktest_test_t	*ke_test;
	ktest_event_type_t	ke_type;
	union {
		ktest_result_t	*ke_result;
		int		ke_err;
	} ke_event;
} ktest_event_t;

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KTEST_IMPL_H */
