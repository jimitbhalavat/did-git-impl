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

const struct signing_tool x509_tool = {
	.st = X509_SIGNATURE,
	.name = "x509",
	.sign = &x509_sign,
	.parse = &x509_parse,
	.verify = &x509_verify,
	.print = &x509_print,
	.config = &x509_config,
	.set_key = &x509_set_key,
	.get_key = &x509_get_key
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
		psig = xmalloc(sizeof(struct signature));
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
	regmatch_t match;
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
	if (regexec(&rbegin, payload, 1, &match, 0) ||
		regexec(&rend, payload, 1, &match, 0)) {
		begin = size;
		goto next;
	}
	begin = match.rm_so;
	end = match.rm_eo;

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

static struct {
	char result;
	const char *check;
} sigcheck_gpg_status[] = {
	{ 'G', "\n[GNUPG:] GOODSIG " },
	{ 'B', "\n[GNUPG:] BADSIG " },
	{ 'U', "\n[GNUPG:] TRUST_NEVER" },
	{ 'U', "\n[GNUPG:] TRUST_UNDEFINED" },
	{ 'E', "\n[GNUPG:] ERRSIG "},
	{ 'X', "\n[GNUPG:] EXPSIG "},
	{ 'Y', "\n[GNUPG:] EXPKEYSIG "},
	{ 'R', "\n[GNUPG:] REVKEYSIG "},
};

static void parse_output(struct signature *sig)
{
	const char *buf = sig->status.buf;
	int i;

	/* Iterate over all search strings */
	for (i = 0; i < ARRAY_SIZE(sigcheck_gpg_status); i++) {
		const char *found, *next;

		if (!skip_prefix(buf, sigcheck_gpg_status[i].check + 1, &found)) {
			found = strstr(buf, sigcheck_gpg_status[i].check);
			if (!found)
				continue;
			found += strlen(sigcheck_gpg_status[i].check);
		}
		sig->result = sigcheck_gpg_status[i].result;

		/* The trust messages are not followed by key/signer information */
		if (sig->result != 'U') {
			next = strchrnul(found, ' ');
			sig->key = xmemdupz(found, next - found);

			/* The ERRSIG message is not followed by signer information */
			if (*next && sig->result != 'E') {
				found = next + 1;
				next = strchrnul(found, '\n');
				sig->signer = xmemdupz(found, next - found);
			}
		}
	}
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
			"--keyid-format=long",
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
	if (flags & OUTPUT_RAW)
		write_in_full(fileno(stderr), sig->status.buf, sig->status.len);
	else
		write_in_full(fileno(stderr), sig->output.buf, sig->output.len);
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

