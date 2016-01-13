/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2015 Ryan Zezeski
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * pbind - bind a process to a processor (non-exclusively)
 */

#include <sys/types.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <procfs.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <locale.h>
#include <libproc.h>
#include <stdarg.h>

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN 	"SYS_TEST"	/* Use this only if it weren't */
#endif

#define	ERR_OK		0		/* exit status for success */
#define	ERR_FAIL	1		/* exit status for errors */
#define	ERR_USAGE	2		/* exit status for usage errors */

static char	*progname;
static char	bflag;
static char	eflag;
static char	qflag;
static char	Qflag;
static char	uflag;
static char	Uflag;
static int	errors;

#define	MAX_PROCFS_PATH	80

/*PRINTFLIKE1*/
static void
warn(char *format, ...)
{
	int err = errno;
	va_list alist;

	(void) fprintf(stderr, "%s: ", progname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(err));
}

/*PRINTFLIKE1*/
static void
die(char *format, ...)
{
	int err = errno;
	va_list alist;

	(void) fprintf(stderr, "%s: ", progname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(err));
	exit(ERR_FAIL);
}

/*
 * Convert an array of CPUs into a string.
 *
 * TODO: normalize output to make use of ranges, e.g. turn 1,2,3,4
 * into 1-4.
 *
 * TODO: eliminate trailing comma.
 */
static char *
cpu_string(size_t ncpus, processorid_t *cpus)
{
	/*
	 * TODO: assume 1024 is enough for now. Later, grow string as
	 * needed.
	 */
	size_t pos = 0;
	int n;
	char *s = malloc(1024);
	if (s == NULL)
		die(gettext("failed to malloc\n"));

	for (int i = 0; i < ncpus; i++) {
		if ((n = snprintf(&s[pos], 1022 - pos, "%u", cpus[i])) < 1)
			die(gettext("failed to convert cpu to string\n"));
		/*
		 * At this point pos will point to the null byte
		 * because pos is 0-based and snprintf doesn't include
		 * the null byte in the return count.
		 */
		pos += n;
		s[pos++] = ',';
	}

	return (s);
}

/*
 * Output for query.
 */
static void
query_out(id_t pid, id_t lwpid, size_t ncpus, processorid_t *cpus)
{
	char *proclwp;
	char pidstr[21];
	char *cpustr;

	if (lwpid == -1) {
		(void) snprintf(pidstr, 20, "%d", (int)pid);
		proclwp = "process";
	} else {
		(void) snprintf(pidstr, 20, "%d/%d", (int)pid, (int)lwpid);
		proclwp = "lwp";
	}

	if (ncpus == 0) {
		(void) printf(gettext("%s id %s: not bound\n"),
		    proclwp, pidstr);
	} else {
		cpustr = cpu_string(ncpus, cpus);
		(void) printf(gettext("%s id %s: %s\n"),
		    proclwp, pidstr, cpustr);
		free(cpustr);
	}
}

/*
 * Binding error.
 */
static void
bind_err(pbind2_op_t op, id_t pid, id_t lwpid, int err)
{
	char *msg;

	switch (op) {
	case PBIND2_OP_CLEAR:
		msg = gettext("unbind");
		break;
	case PBIND2_OP_QUERY:
		msg = gettext("query");
		break;
	default:
		msg = gettext("bind");
		break;
	}
	if (lwpid == -1)
		warn(gettext("cannot %s pid %d: %s\n"), msg,
		    (int)pid, strerror(err));
	else
		warn(gettext("cannot %s lwpid %d/%d: %s\n"), msg,
		    (int)pid, (int)lwpid, strerror(err));
}

/*
 * Output for bind.
 */
static void
bind_out(id_t pid, id_t lwpid, size_t old_ncpus, processorid_t *old_cpus,
    size_t new_ncpus, processorid_t *new_cpus)
{
	char *proclwp;
	char pidstr[21];
	char *ncpustr, *ocpustr;

	if (lwpid == -1) {
		(void) snprintf(pidstr, 20, "%d", (int)pid);
		proclwp = "process";
	} else {
		(void) snprintf(pidstr, 20, "%d/%d", (int)pid, (int)lwpid);
		proclwp = "lwp";
	}

	if (old_ncpus == 0) {
		if (new_ncpus == 0) {
			(void) printf(gettext("%s id %s: was not bound, "
			    "now not bound\n"), proclwp, pidstr);
		} else {
			ncpustr = cpu_string(new_ncpus, new_cpus);
			(void) printf(gettext("%s id %s: was not bound, "
			    "now %d\n"), proclwp, pidstr, ncpustr);
			free(ncpustr);
		}
	} else {
		if (new_ncpus == 0) {
			ocpustr = cpu_string(old_ncpus, old_cpus);
			(void) printf(gettext("%s id %s: was %d, "
			    "now not bound\n"), proclwp, pidstr, ocpustr);
			free(ocpustr);
		} else {
			ocpustr = cpu_string(old_ncpus, old_cpus);
			ncpustr = cpu_string(new_ncpus, new_cpus);
			(void) printf(gettext("%s id %s: was %d, "
			    "now %d\n"), proclwp, pidstr, ocpustr, ncpustr);
			free(ocpustr);
			free(ncpustr);
		}
	}
}

static struct ps_prochandle *
grab_proc(id_t pid)
{
	int ret;
	struct ps_prochandle *Pr;

	if ((Pr = Pgrab(pid, 0, &ret)) == NULL) {
		warn(gettext("cannot control process %d: %s\n"),
		    (int)pid, Pgrab_error(ret));
		errors = ERR_FAIL;
		return (NULL);
	}

	/*
	 * Set run-on-last-close flag so the controlled process
	 * runs even if we die on a signal, and create an agent LWP.
	 */
	if (Psetflags(Pr, PR_RLC) != 0 || Pcreate_agent(Pr) != 0) {
		warn(gettext("cannot control process %d\n"), (int)pid);
		errors = ERR_FAIL;
		Prelease(Pr, 0);
		return (NULL);
	}
	return (Pr);
}

static void
rele_proc(struct ps_prochandle *Pr)
{
	if (Pr == NULL)
		return;
	Pdestroy_agent(Pr);
	Prelease(Pr, 0);
}

static void
bind_lwp(struct ps_prochandle *Pr, pbind2_op_t op, id_t pid, id_t lwpid,
    size_t ncpus, processorid_t *cpus)
{
	if (pr_processor_bind2(Pr, op, P_LWPID, lwpid, &ncpus, cpus,
	    NULL) < 0) {
		bind_err(op, pid, lwpid, errno);
		errors = ERR_FAIL;
	} else {
		if (qflag)
			query_out(pid, lwpid, ncpus, cpus);
		else
			bind_out(pid, lwpid, 0, NULL, ncpus, cpus);
	}
}

/*
 * Query, set, or clear bindings for the range of LWPs in the given process.
 */
static int
do_lwps(id_t pid, const char *range, pbind2_op_t op, size_t ncpus,
    processorid_t *cpus)
{
	char procfile[MAX_PROCFS_PATH];
	struct ps_prochandle *Pr;
	struct prheader header;
	size_t bindnum;
	processorid_t *binding;
	struct lwpsinfo *lwp;
	char *lpsinfo, *ptr;
	int nent, size;
	int i, fd, found;

	/*
	 * Report bindings for LWPs in process 'pid'.
	 */
	(void) snprintf(procfile, MAX_PROCFS_PATH,
	    "/proc/%d/lpsinfo", (int)pid);
	if ((fd = open(procfile, O_RDONLY)) < 0) {
		if (errno == ENOENT)
			errno = ESRCH;
		bind_err(op, pid, -1, errno);
		return (ERR_FAIL);
	}
	if (pread(fd, &header, sizeof (header), 0) != sizeof (header)) {
		(void) close(fd);
		bind_err(op, pid, -1, errno);
		return (ERR_FAIL);
	}
	nent = header.pr_nent;
	size = header.pr_entsize * nent;
	ptr = lpsinfo = malloc(size);
	if (lpsinfo == NULL) {
		bind_err(op, pid, -1, errno);
		return (ERR_FAIL);
	}
	if (pread(fd, lpsinfo, size, sizeof (header)) != size) {
		bind_err(op, pid, -1, errno);
		free(lpsinfo);
		(void) close(fd);
		return (ERR_FAIL);
	}

	if ((bflag || uflag) && (Pr = grab_proc(pid)) == NULL) {
		free(lpsinfo);
		(void) close(fd);
		return (ERR_FAIL);
	}
	found = 0;
	for (i = 0; i < nent; i++, ptr += header.pr_entsize) {
		/*LINTED ALIGNMENT*/
		lwp = (lwpsinfo_t *)ptr;
		bindnum = lwp->pr_bindnum;
		binding = lwp->pr_bindpro2;
		if (!proc_lwp_in_set(range, lwp->pr_lwpid))
			continue;
		found++;
		if (bflag || uflag)
			bind_lwp(Pr, op, pid, lwp->pr_lwpid, ncpus, cpus);
		else if (bindnum != 0)
			query_out(pid, lwp->pr_lwpid, bindnum, binding);
	}
	if (bflag || uflag)
		rele_proc(Pr);
	free(lpsinfo);
	(void) close(fd);
	if (found == 0) {
		warn(gettext("cannot %s lwpid %d/%s: "
		    "No matching LWPs found\n"),
		    bflag ? "bind" : "query", pid, range);
		return (ERR_FAIL);
	}
	return (ERR_OK);
}

/*ARGSUSED*/
static int
query_all_proc(psinfo_t *psinfo, lwpsinfo_t *lwpsinfo, void *arg)
{
	id_t pid = psinfo->pr_pid;
	size_t ncpus;
	processorid_t *cpus;

	if (processor_bind2(PBIND2_OP_QUERY, P_PID, pid, &ncpus, cpus,
	    NULL) < 0) {
		/*
		 * Ignore search errors.  The process may have exited
		 * since we read the directory.
		 */
		if (errno == ESRCH)
			return (0);
		bind_err(PBIND2_OP_QUERY, pid, -1, errno);
		errors = ERR_FAIL;
		return (0);
	}
	if (ncpus != 0)
		query_out(pid, -1, ncpus, cpus);
	return (0);
}

static int
query_all_lwp(psinfo_t *psinfo, lwpsinfo_t *lwpsinfo, void *arg)
{
	id_t pid = psinfo->pr_pid;
	id_t lwpid = lwpsinfo->pr_lwpid;
	processorid_t *cpuid = arg;
	size_t ncpus = lwpsinfo->pr_bindnum;
	processorid_t *cpus = lwpsinfo->pr_bindpro2;

	if (psinfo->pr_nlwp == 1)
		lwpid = -1;	/* report process bindings if only 1 lwp */

	for (int i = 0; i < ncpus; i++) {
		if ((cpuid != NULL && *cpuid == cpus[i]) ||
		    (cpuid == NULL && ncpus != 0))
			query_out(pid, lwpid, ncpus, cpus);
	}
	return (0);
}

/*
 * Execute the cmd with args while bound to cpu. Does not return:
 * either executes cmd successfully or dies trying.
 */
static void
exec_cmd(size_t ncpus, processorid_t *cpus, char *cmd, char **args)
{
	if (processor_bind2(PBIND2_OP_SET, P_PID, P_MYID,
		&ncpus, cpus, NULL) == -1) {
		bind_err(PBIND2_OP_SET, getpid(), -1, errno);
		exit(ERR_FAIL);
	}

	if (execvp(cmd, args) == -1)
		die(gettext("failed to exec %s\n"), cmd);
}

/*
 * Attempt to parse str as a CPU identifier. Return the identifier or
 * die.
 */
static processorid_t
parse_cpu(char *str)
{
	processorid_t cpu;
	char *endstr;

	cpu = strtol(str, &endstr, 10);
	if (endstr != NULL && *endstr != '\0' || cpu < 0)
		die(gettext("invalid processor ID %s\n"), str);

	return (cpu);
}

static void
parse_cpus(char *str, size_t *oncpus, processorid_t **ocpus)
{
	processorid_t *cpus;
	size_t ncpus = 0;
	char *pos;
	char *token;

	/*
	 * TODO: Just making it big enough for now. Eventualy, create
	 * list and convert to array at the end.
	 */
	if ((cpus = malloc(512 * sizeof (processorid_t))) == NULL)
		die(gettext("failed to malloc\n"));

	/*
	 * TODO: allow range specification, e.g. 1-3,6-9.
	 */
	token = strtok_r(str, ",", &pos);
	while (token != NULL) {
		cpus[ncpus++] = parse_cpu(token);
		token = strtok_r(NULL, ",", &pos);
	}

	*oncpus = ncpus;
	*ocpus = cpus;
}

static int
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: \n\t%1$s -b processor_id pid[/lwpids] ...\n"
	    "\t%1$s -e processor_id cmd [args...]\n"
	    "\t%1$s -U [processor_id] ...\n"
	    "\t%1$s -Q [processor_id] ...\n"
	    "\t%1$s -u pid[/lwpids] ...\n"
	    "\t%1$s [-q] [pid[/lwpids] ...]\n"),
	    progname);
	return (ERR_USAGE);
}

int
main(int argc, char *argv[])
{
	int c;
	int ret;
	id_t pid;
	pbind2_op_t op;
	size_t ncpus, old_ncpus;
	processorid_t cpu, *cpus, *old_cpus;
	uchar_t flags = PBIND2_HARD;
	char *endstr;

	progname = argv[0];	/* put actual command name in messages */

	(void) setlocale(LC_ALL, "");	/* setup localization */
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "b:e:qQuU")) != EOF) {
		switch (c) {

		case 'b':
			bflag = 1;
			parse_cpus(optarg, &ncpus, &cpus);
			break;

		case 'e':
			eflag = 1;
			parse_cpus(optarg, &ncpus, &cpus);
			break;

		case 'q':
			qflag = 1;
			op = PBIND2_OP_QUERY;
			break;

		case 'Q':
			Qflag = 1;
			op = PBIND2_OP_QUERY;
			break;

		case 'u':
			uflag = 1;
			op = PBIND2_OP_CLEAR;
			break;

		case 'U':
			Uflag = 1;
			break;

		default:
			return (usage());
		}
	}


	/*
	 * Make sure that at most one of the options b, e, q, Q, u, or
	 * U was specified.
	 */
	c = bflag + eflag + qflag + Qflag + uflag + Uflag;
	if (c < 1) {				/* nothing specified */
		qflag = 1;			/* default to query */
	} else if (c > 1) {
		warn(gettext("options -b, -e, -q, -Q, -u and -U "
		    "are mutually exclusive\n"));
		return (usage());
	}

	errors = 0;
	argc -= optind;
	argv += optind;

	/*
	 * Handle query of all processes.
	 */
	if (argc == 0) {
		if (bflag || uflag) {
			warn(gettext("must specify at least one pid\n"));
			return (usage());
		}
		if (eflag) {
			warn(gettext("must specify command\n"));
			return (usage());
		}
		if (Uflag) {
			if (processor_bind2(PBIND2_OP_CLEAR, P_ALL, 0, NULL,
				NULL, NULL) != 0)
				die(gettext("failed to unbind some LWPs"));
		}
		if (Qflag) {
			(void) proc_walk(query_all_lwp, NULL, PR_WALK_LWP);
			return (errors);
		} else {
			(void) proc_walk(query_all_proc, NULL, PR_WALK_PROC);
			return (errors);
		}
	}

	if (eflag)
		exec_cmd(ncpus, cpus, argv[0], argv);

	if (Qflag || Uflag) {
		/*
		 * Go through listed processor IDs.
		 */
		for (; argc > 0; argv++, argc--) {
			errno = 0;
			cpu = (id_t)strtol(*argv, &endstr, 10);
			if (errno != 0 || (endstr != NULL && *endstr != '\0') ||
			    p_online(cpu, P_STATUS) == -1) {
				warn(gettext("invalid processor ID\n"));
				continue;
			}
			if (Qflag) {
				(void) proc_walk(query_all_lwp,
				    &cpu, PR_WALK_LWP);
				continue;
			}
			if (Uflag) {
				if (processor_bind(P_CPUID, cpu,
				    PBIND_NONE, NULL) != 0) {
					warn(gettext("failed to unbind from "
					    "processor %d"), (int)cpu);
					errors = ERR_FAIL;
				}
				continue;
			}
		}
		return (errors);
	}

	/*
	 * Go through listed process[/lwp_ranges].
	 */
	for (; argc > 0; argv++, argc--) {
		errno = 0;
		pid = (id_t)strtol(*argv, &endstr, 10);
		if (errno != 0 ||
		    (endstr != NULL && *endstr != '\0' && *endstr != '/')) {
			warn(gettext("invalid process ID: %s\n"), *argv);
			continue;
		}
		if (endstr != NULL && *endstr == '/') {
			/*
			 * Handle lwp range case
			 */
			const char *lwps = (const char *)(++endstr);
			if (*lwps == '\0' ||
			    proc_lwp_range_valid(lwps) != 0) {
				warn(gettext("invalid lwp range "
				    "for pid %d\n"), (int)pid);
				errors = ERR_FAIL;
				continue;
			}
			if (!qflag)
				(void) proc_initstdio();
			ret = do_lwps(pid, lwps,
			    qflag ? PBIND2_OP_QUERY : PBIND2_OP_SET,
			    ncpus, cpus);
			if (!qflag)
				(void) proc_finistdio();
			if (ret != ERR_OK)
				errors = ret;
		} else {
			/*
			 * Handle whole process case.
			 */
			/*
			 * TODO: hardcoded.
			 */
			old_ncpus = 256;
			old_cpus = malloc(old_ncpus * sizeof (processorid_t));
			if (old_cpus == NULL)
				die(gettext("failed to malloc\n"));

			if (processor_bind2(PBIND2_OP_QUERY, P_PID, pid,
			    &old_ncpus, old_cpus, NULL) < 0) {
				bind_err(PBIND2_OP_QUERY, pid, -1, errno);
				errors = ERR_FAIL;
				continue;
			}

			if (bflag && processor_bind2(PBIND2_OP_SET, P_PID, pid,
				&ncpus, cpus, &flags) < 0) {
				bind_err(PBIND2_OP_SET, pid, -1, errno);
				errors = ERR_FAIL;
				continue;
			}
			if (qflag)
				query_out(pid, -1, old_ncpus, old_cpus);
			else
				bind_out(pid, -1, old_ncpus, old_cpus, ncpus, cpus);

			free(old_cpus);
		}
	}
	return (errors);
}
