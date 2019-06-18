#include "cache.h"
#include "config.h"
#include "run-command.h"
#include "strbuf.h"
#include "signing-interface.h"
#include "signing-tool.h"
#include "sigchain.h"
#include "tempfile.h"

static int openpgp_sign(const char *payload, size_t size,
		struct signature **sig, const char *key);
static size_t openpgp_parse(const char *payload, size_t size,
		struct signature **sig);
static int openpgp_verify(const char *payload, size_t size,
		struct signature *sig);
static void openpgp_print(const struct signature *sig, unsigned flags);
static int openpgp_config(const char *, const char *, void *);
static void openpgp_set_key(const char *);
static const char *openpgp_get_key(void);

const struct signing_tool openpgp_tool = {
	.st = OPENPGP_SIGNATURE,
	.name = "openpgp",
	.sign = &openpgp_sign,
	.parse = &openpgp_parse,
	.verify = &openpgp_verify,
	.print = &openpgp_print,
	.config = &openpgp_config,
	.set_key = &openpgp_set_key,
	.get_key = &openpgp_get_key
};

static const char *program = "gpg";
static const char *signing_key = NULL;
static const char *keyring = NULL;
static int no_default_keyring = 0;
struct regex_pattern {
	const char * begin;
	const char * end;
};
static struct regex_pattern patterns[2] = {
	{ "^-----BEGIN PGP SIGNATURE-----\n", "-----END PGP SIGNATURE-----\n" },
	{ "^-----BEGIN PGP MESSAGE-----\n", "-----END PGP MESSAGE-----\n" }
};

static int openpgp_sign(const char *payload, size_t size,
		struct signature **sig, const char *key)
{
	struct child_process gpg = CHILD_PROCESS_INIT;
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
		psig->st = OPENPGP_SIGNATURE;
		psig->result = 0;
		psig->signer = NULL;
		psig->key = NULL;
		psignature = &(psig->sig);
		pstatus = &(psig->status);
	} else {
		psignature = NULL;
		pstatus = NULL;
	}

	argv_array_pushl(&gpg.args,
			program,
			"--status-fd=2",
			"-bsau", skey,
			NULL);

	/*
	 * When the username signingkey is bad, program could be terminated
	 * because gpg exits without reading and then write gets SIGPIPE.
	 */
	sigchain_push(SIGPIPE, SIG_IGN);
	ret = pipe_command(&gpg, payload, size,
			psignature, 1024, pstatus, 0);
	sigchain_pop(SIGPIPE);

	if (!sig)
		return !!ret;

	/* Check for success status from gpg */
	ret |= !strstr(pstatus->buf, "\n[GNUPG:] SIG_CREATED ");
	if (ret)
		return error(_("gpg failed to sign the data"));

	/* Mark the signature as good */
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

/*
 * To get all OpenPGP signatures in a payload, repeatedly call this function
 * giving it the remainder of the payload as the payload pointer. The return
 * value is the index of the first char of the signature in the payload. If
 * no signature is found, size is returned.
 */
static size_t openpgp_parse(const char *payload, size_t size,
		struct signature **sig)
{
	int i, ret;
	regex_t rbegin;
	regex_t rend;
	regmatch_t match;
	size_t first, begin, end;
	struct regex_pattern *pattern;
	struct signature *psig;
	static char errbuf[1024];

	if (size == 0)
		return size;

	/*
	 * Figure out if any OpenPGP signatures are in the payload and which
	 * begin pattern matches the first signature in the payload.
	 */
	first = size;
	pattern = NULL;
	for (i = 0; i < ARRAY_SIZE(patterns); i++) {
		if ((ret = regcomp(&rbegin, patterns[i].begin, REG_EXTENDED))) {
			regerror(ret, &rbegin, errbuf, 1024);
			BUG("Failed to compile regex: %s\n", errbuf);
			return size;
		}
		if (!regexec(&rbegin, payload, 1, &match, 0))
			if (match.rm_so < first) {
				pattern = &patterns[i];
				first = match.rm_so;
			}

		regfree(&rbegin);
	}

	if (!pattern)
		return size;

	/*
	 * Find the first OpenPGP signature in the payload and copy it into the
	 * signature struct.
	 */
	if ((ret = regcomp(&rbegin, pattern->begin, REG_EXTENDED))) {
		regerror(ret, &rbegin, errbuf, 1024);
		BUG("Failed to compile regex: %s\n", errbuf);
		return size;
	}
	if ((ret = regcomp(&rend, pattern->end, REG_EXTENDED))) {
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
		psig->st = OPENPGP_SIGNATURE;
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

extern FILE *thelog;
extern int indent;
extern int dolog;
extern struct strbuf strlog;
extern const char *logpath;

#define IN(...) { \
	strbuf_addchars(&strlog, ' ', indent * 2); \
	strbuf_addf(&strlog, __VA_ARGS__); \
	indent++; \
	if(thelog == NULL) { \
		thelog = fopen(logpath, "a"); \
	} \
} while(0)

#define OUT(...) { \
	indent--; \
	strbuf_addchars(&strlog, ' ', indent * 2); \
	strbuf_addf(&strlog, __VA_ARGS__); \
} while(0)

#define OFF { \
	if(thelog != NULL) { \
		if(dolog) { \
			strbuf_write(&strlog, thelog); \
			strbuf_release(&strlog); \
		} \
		fclose(thelog); \
		thelog = NULL; \
	} \
	dolog = 0; \
} while(0)

#define LOG(...) { \
	strbuf_addchars(&strlog, ' ', indent * 2); \
	strbuf_addf(&strlog, __VA_ARGS__); \
	dolog = 1; \
} while(0)

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

static int openpgp_verify(const char *payload, size_t size,
		struct signature *sig)
{
	struct child_process gpg = CHILD_PROCESS_INIT;
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

	argv_array_push(&gpg.args, program);
	if (keyring)
		argv_array_pushl(&gpg.args, "--keyring", keyring, NULL);
	if (no_default_keyring)
		argv_array_push(&gpg.args, "--no-default-keyring");
	argv_array_pushl(&gpg.args,
			"--keyid-format=long",
			"--status-fd=1",
			"--verify", temp->filename.buf, "-",
			NULL);

	strbuf_reset(&(sig->status));
	strbuf_reset(&(sig->output));

	sigchain_push(SIGPIPE, SIG_IGN);
	ret = pipe_command(&gpg, payload, size,
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

static void openpgp_print(const struct signature *sig, unsigned flags)
{
	if (flags & OUTPUT_RAW)
		write_in_full(fileno(stderr), sig->status.buf, sig->status.len);
	else
		write_in_full(fileno(stderr), sig->output.buf, sig->output.len);
}

static int openpgp_config(const char *var, const char *value, void *cb)
{
	IN("openpgp_config(%s, %s, %p)\n", var, value, cb);
	if (!strcmp(var, "program")) {
		LOG("ok: looking up git_config_string(%s, %s, %p)\n", program, var, value);
		OUT("}\n");
		return git_config_string(&program, var, value);
	}

	if (!strcmp(var, "key")) {
		LOG("ok: looking up git_config_string(%s, %s, %p)\n", signing_key, var, value);
		OUT("}\n");
		return git_config_string(&signing_key, var, value);
	}

	if (!strcmp(var, "keyring")) {
		LOG("ok: looking up git_config_string(%s, %s, %p)\n", keyring, var, value);
		OUT("}\n");
		return git_config_string(&keyring, var, value);
	}

	if (!strcmp(var, "nodefaultkeyring")) {
		LOG("ok: looking up git_config_bool(%s, %p)\n", var, value);
		OUT("}\n");
		no_default_keyring = git_config_bool(var, value);
		return 0;
	}
	OUT("}\n");
	return 0;
}

static void openpgp_set_key(const char *key)
{
	free((void*)signing_key);
	signing_key = xstrdup(key);
}

static const char *openpgp_get_key(void)
{
	if (signing_key)
		return signing_key;
	return git_committer_info(IDENT_STRICT|IDENT_NO_DATE);
}

