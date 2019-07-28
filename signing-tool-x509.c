#include "cache.h"
#include "config.h"
#include "run-command.h"
#include "strbuf.h"
#include "signing-interface.h"
#include "signing-tool.h"
#include "sigchain.h"
#include "tempfile.h"

static int x509_sign(const char *payload, size_t size,
		struct signature **sig, const char *key);
static size_t x509_parse(const char *payload, size_t size,
		struct signature **sig);
static int x509_verify(const char *payload, size_t size,
		struct signature *sig);
static void x509_print(const struct signature *sig, unsigned flags);
static int x509_config(const char *, const char *, void *);
static void x509_set_key(const char *);
static const char *x509_get_key(void);
static void x509_set_program(const char *);
static const char *x509_get_program(void);

const struct signing_tool x509_tool = {
	.st = X509_SIGNATURE,
	.name = "x509",
	.sign = &x509_sign,
	.parse = &x509_parse,
	.verify = &x509_verify,
	.print = &x509_print,
	.config = &x509_config,
	.set_key = &x509_set_key,
	.get_key = &x509_get_key,
	.set_program = &x509_set_program,
	.get_program = &x509_get_program
};

static const char *program = "gpgsm";
static const char *signing_key = NULL;
struct regex_pattern {
	const char * begin;
	const char * end;
};
static struct regex_pattern pattern = {
	"^-----BEGIN SIGNED MESSAGE-----\n",
	"^-----END SIGNED MESSAGE-----\n"
};

static int x509_sign(const char *payload, size_t size,
		struct signature **sig, const char *key)
{
	struct child_process gpgsm = CHILD_PROCESS_INIT;
	struct signature *psig;
	struct strbuf *psignature, *pstatus;
	int ret;
	size_t i, j;
	const char *skey = (!key || !*key) ? signing_key : key;

	/*
	 * Create the signature.
	 */
	if (sig) {
		psig = *sig;
		strbuf_init(&(psig->sig), 0);
		strbuf_init(&(psig->output), 0);
		strbuf_init(&(psig->status), 0);
		psig->st = X509_SIGNATURE;
		psig->result = 0;
		psig->signer = NULL;
		psig->key = NULL;
		psignature = &(psig->sig);
		pstatus = &(psig->status);
	} else {
		psignature = NULL;
		pstatus = NULL;
	}

	argv_array_pushl(&gpgsm.args,
			program,
			"--status-fd=2",
			"-bsau", skey,
			NULL);

	/*
	 * When the username signingkey is bad, program could be terminated
	 * because gpgsm exits without reading and then write gets SIGPIPE.
	 */
	sigchain_push(SIGPIPE, SIG_IGN);
	ret = pipe_command(&gpgsm, payload, size,
			psignature, 1024, pstatus, 0);
	sigchain_pop(SIGPIPE);

	if (!sig)
		return !!ret;

	ret |= !strstr(pstatus->buf, "\n[GNUPG:] SIG_CREATED ");
	if (ret)
		return error(_("gpgsm failed to sign the data"));

	/* Mark the signature as good. */
	psig->result = 'G';

	/* Strip CR from the line endings, in case we are on Windows. */
	for (i = j = 0; i < psig->sig.len; i++)
		if (psig->sig.buf[i] != '\r') {
			if (i != j)
				psig->sig.buf[j] = psig->sig.buf[i];
			j++;
		}
	strbuf_setlen(&(psig->sig), j);

	/* Store the key we used */
	psig->key = xstrdup(skey);

	return 0;
}

static size_t x509_parse(const char *payload, size_t size,
		struct signature **sig)
{
	int ret;
	regex_t rbegin;
	regex_t rend;
	regmatch_t bmatch;
	regmatch_t ematch;
	size_t begin, end;
	struct signature *psig;
	static char errbuf[1024];

	if (size == 0)
		return size;

	/*
	 * Find the first x509 signature in the payload and copy it into the
	 * signature struct.
	 */
	if ((ret = regcomp(&rbegin, pattern.begin, REG_EXTENDED|REG_NEWLINE))) {
		regerror(ret, &rbegin, errbuf, 1024);
		BUG("Failed to compile regex: %s\n", errbuf);

		return size;
	}
	if ((ret = regcomp(&rend, pattern.end, REG_EXTENDED|REG_NEWLINE))) {
		regerror(ret, &rend, errbuf, 1024);
		BUG("Failed to compile regex: %s\n", errbuf);

		return size;
	}

	begin = end = 0;
	if (regexec(&rbegin, payload, 1, &bmatch, 0) ||
		regexec(&rend, payload, 1, &ematch, 0)) {
		begin = size;
	}
	if (begin == size)
		goto next;

	begin = bmatch.rm_so;
	end = ematch.rm_eo;

	/*
	 * Create the signature.
	 */
	if (sig) {
		psig = *sig;
		psig = xmalloc(sizeof(struct signature));
		strbuf_init(&(psig->sig), end - begin);
		strbuf_add(&(psig->sig), payload + begin, end - begin);
		strbuf_init(&(psig->output), 0);
		strbuf_init(&(psig->status), 0);
		psig->st = X509_SIGNATURE;
		psig->result = 0;
		psig->signer = NULL;
		psig->key = NULL;
	}

	next:
		regfree(&rbegin);
		regfree(&rend);

	return begin;
}

/* An exclusive status -- only one of them can appear in output */
#define GPG_STATUS_EXCLUSIVE	(1<<0)
/* The status includes key identifier */
#define GPG_STATUS_KEYID	(1<<1)
/* The status includes user identifier */
#define GPG_STATUS_UID		(1<<2)
/* The status includes key fingerprints */
#define GPG_STATUS_FINGERPRINT	(1<<3)

/* Short-hand for standard exclusive *SIG status with keyid & UID */
#define GPG_STATUS_STDSIG	(GPG_STATUS_EXCLUSIVE|GPG_STATUS_KEYID|GPG_STATUS_UID)

static struct {
	char result;
	const char *check;
	unsigned int flags;
} sigcheck_gpg_status[] = {
	{ 'G', "GOODSIG ", GPG_STATUS_STDSIG },
	{ 'B', "BADSIG ", GPG_STATUS_STDSIG },
	{ 'U', "TRUST_NEVER", 0 },
	{ 'U', "TRUST_UNDEFINED", 0 },
	{ 'E', "ERRSIG ", GPG_STATUS_EXCLUSIVE|GPG_STATUS_KEYID },
	{ 'X', "EXPSIG ", GPG_STATUS_STDSIG },
	{ 'Y', "EXPKEYSIG ", GPG_STATUS_STDSIG },
	{ 'R', "REVKEYSIG ", GPG_STATUS_STDSIG },
	{ 0, "VALIDSIG ", GPG_STATUS_FINGERPRINT },
};

static void parse_output(struct signature *sigc)
{
	const char *buf = sigc->status.buf;
	const char *line, *next;
	int i, j;
	int seen_exclusive_status = 0;

	/* Iterate over all lines */
	for (line = buf; *line; line = strchrnul(line+1, '\n')) {
		while (*line == '\n')
			line++;
		/* Skip lines that don't start with GNUPG status */
		if (!skip_prefix(line, "[GNUPG:] ", &line))
			continue;

		/* Iterate over all search strings */
		for (i = 0; i < ARRAY_SIZE(sigcheck_gpg_status); i++) {
			if (skip_prefix(line, sigcheck_gpg_status[i].check, &line)) {
				if (sigcheck_gpg_status[i].flags & GPG_STATUS_EXCLUSIVE) {
					if (seen_exclusive_status++)
						goto found_duplicate_status;
				}

				if (sigcheck_gpg_status[i].result)
					sigc->result = sigcheck_gpg_status[i].result;
				/* Do we have key information? */
				if (sigcheck_gpg_status[i].flags & GPG_STATUS_KEYID) {
					next = strchrnul(line, ' ');
					free(sigc->key);
					sigc->key = xmemdupz(line, next - line);
					/* Do we have signer information? */
					if (*next && (sigcheck_gpg_status[i].flags & GPG_STATUS_UID)) {
						line = next + 1;
						next = strchrnul(line, '\n');
						free(sigc->signer);
						sigc->signer = xmemdupz(line, next - line);
					}
				}
				/* Do we have fingerprint? */
				if (sigcheck_gpg_status[i].flags & GPG_STATUS_FINGERPRINT) {
					next = strchrnul(line, ' ');
					free(sigc->fingerprint);
					sigc->fingerprint = xmemdupz(line, next - line);

					/* Skip interim fields */
					for (j = 9; j > 0; j--) {
						if (!*next)
							break;
						line = next + 1;
						next = strchrnul(line, ' ');
					}

					next = strchrnul(line, '\n');
					free(sigc->primary_key_fingerprint);
					sigc->primary_key_fingerprint = xmemdupz(line, next - line);
				}

				break;
			}
		}
	}
	return;

found_duplicate_status:
	/*
	 * GOODSIG, BADSIG etc. can occur only once for each signature.
	 * Therefore, if we had more than one then we're dealing with multiple
	 * signatures.  We don't support them currently, and they're rather
	 * hard to create, so something is likely fishy and we should reject
	 * them altogether.
	 */
	sigc->result = 'E';
	/* Clear partial data to avoid confusion */
	FREE_AND_NULL(sigc->primary_key_fingerprint);
	FREE_AND_NULL(sigc->fingerprint);
	FREE_AND_NULL(sigc->signer);
	FREE_AND_NULL(sigc->key);
}

static int x509_verify(const char *payload, size_t size,
		struct signature *sig)
{
	struct child_process gpgsm = CHILD_PROCESS_INIT;
	struct tempfile *temp;
	int ret;

	temp = mks_tempfile_t(".git_vtag_tmpXXXXXX");
	if (!temp)
		return error_errno(_("could not create temporary file"));
	if (write_in_full(temp->fd, sig->sig.buf, sig->sig.len) < 0 ||
	    close_tempfile_gently(temp) < 0) {
		error_errno(_("failed writing detached signature to '%s'"),
				temp->filename.buf);
		delete_tempfile(&temp);
		return -1;
	}

	argv_array_push(&gpgsm.args, program);
	argv_array_pushl(&gpgsm.args,
			"--status-fd=1",
			"--verify", temp->filename.buf, "-",
			NULL);

	strbuf_reset(&(sig->status));
	strbuf_reset(&(sig->output));

	sigchain_push(SIGPIPE, SIG_IGN);
	ret = pipe_command(&gpgsm, payload, size,
			&(sig->status), 0, &(sig->output), 0);
	sigchain_pop(SIGPIPE);

	delete_tempfile(&temp);

	ret |= !strstr(sig->status.buf, "\n[GNUPG:] GOODSIG ");

	if (ret && !sig->output.len)
		return !!ret;

	parse_output(sig);

	ret |= sig->result != 'G' && sig->result != 'U';

	return !!ret;
}

static void x509_print(const struct signature *sig, unsigned flags)
{
	const char *output = flags & OUTPUT_RAW ?
		sig->status.buf : sig->output.buf;

	if (flags & OUTPUT_VERBOSE && sig->sig.buf)
		fputs(sig->sig.buf, stdout);

	if (output)
		fputs(output, stderr);
}

static int x509_config(const char *var, const char *value, void *cb)
{
	if (!strcmp(var, "program"))
		return git_config_string(&program, var, value);

	if (!strcmp(var, "key"))
		return git_config_string(&signing_key, var, value);

	return 0;
}

static void x509_set_key(const char *key)
{
	free((void*)signing_key);
	signing_key = xstrdup(key);
}

static const char *x509_get_key(void)
{
	if (signing_key)
		return signing_key;
	return git_committer_info(IDENT_STRICT|IDENT_NO_DATE);
}

static void x509_set_program(const char *signing_program)
{
	free((void*)program);
	program = xstrdup(signing_program);
}

static const char *x509_get_program(void)
{
	if (program)
		return program;
	return git_committer_info(IDENT_STRICT|IDENT_NO_DATE);
}