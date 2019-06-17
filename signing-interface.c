#include <sys/types.h>
#include <unistd.h>
#include "cache.h"
#include "config.h"
#include "run-command.h"
#include "strbuf.h"
#include "signing-interface.h"
#include "signing-tool.h"
#include "sigchain.h"
#include "tempfile.h"

extern const struct signing_tool openpgp_tool;
extern const struct signing_tool x509_tool;

static const struct signing_tool *signing_tools[SIGNATURE_TYPE_COUNT] = {
	&openpgp_tool,
	&x509_tool,
};

static enum signature_type default_type = SIGNATURE_TYPE_DEFAULT;
static const char* unknown_signature_type = "unknown signature type";
static char* default_signing_key = NULL;

#if 0
static void add_signature(struct signatures *sigs, struct signature *sig) {
	if (!sigs || !sig)
		return;
	ALLOC_GROW(sigs->sigs, sigs->nsigs + 1, sigs->alloc);
	sigs->sigs[sigs->nsigs++] = sig;
}

void signatures_clear(struct signatures *sigs)
{
	size_t i;
	struct signature *psig;

	if (!sigs) return;
	
	for (i = 0; i < sigs->nsigs; i++) {
		psig = sigs->sigs[i];
		strbuf_release(&(psig->sig));
		strbuf_release(&(psig->output));
		strbuf_release(&(psig->status));
		FREE_AND_NULL(psig->signer);
		FREE_AND_NULL(psig->key);
		FREE_AND_NULL(psig);
	}
	FREE_AND_NULL(sigs->sigs);
	sigs->nsigs = 0;
	sigs->alloc = 0;
}

int sign_buffer(const char *payload, size_t size, struct signatures *sigs,
		enum signature_type st, const char *signing_key)
{
	const struct signing_tool *tool;
	struct signature *psig = NULL;

	printf("process %u\nwaiting 5 minutes\n", getpid());
	fflush(stdout);
	sleep(300);

	if (!sigs)
		error("invalid signatures passed to sign function");

	if (!VALID_SIGNATURE_TYPE(st))
		return error("unsupported signature type: %d", st);

	tool = signing_tools[st];

	if (!tool || !tool->sign)
		BUG("signing tool %s undefined", signature_type_name(st));
		
	if (tool->sign(payload, size, &psig, signing_key))
		add_signature(sigs, psig);
	else 
		error("signing operation failed");

	return 0;
}

size_t parse_signatures(const char *payload, size_t size, 
		struct signatures *sigs)
{
	enum signature_type st;
	size_t first;
	ssize_t begin = 0;
	const struct signing_tool *tool;
	struct signature *psig = NULL;

	first = size;
	for (st = SIGNATURE_TYPE_FIRST; st < SIGNATURE_TYPE_LAST; st++) {
		tool = signing_tools[st];

		if (!tool || !tool->parse)
			BUG("signing tool %s undefined", signature_type_name(st));

		while ((begin = tool->parse(payload + begin, size - begin, &psig)) >= 0) {

			if (sigs)
				add_signature(sigs, psig);
			else
				FREE_AND_NULL(psig);

			if (begin < first)
				first = begin;
			begin++;
		}
	}

	return first;
}

int verify_signed_buffer(const char *payload, size_t size,
		const struct signatures *sigs)
{
	int ret = 0;
	size_t i;
	const struct signing_tool *tool;
	struct signature *psig;

	if (!sigs)
		error("invalid signatures passed to verify function");

	for (i = 0; i < sigs->nsigs; i++) {
		psig = sigs->sigs[i];
		tool = signing_tools[psig->st];

		if (!tool || !tool->verify)
			BUG("signing tool %s undefined", signature_type_name(psig->st));

		ret |= tool->verify(payload, size, psig);
	}

	return ret;
}

void print_signatures(const struct signatures *sigs, unsigned flags)
{
	size_t i;
	const struct signing_tool *tool;
	const struct signature *psig;

	if (!sigs)
		error("invalid signatures passed to verify function");

	for (i = 0; i < sigs->nsigs; i++) {
		psig = sigs->sigs[i];
		tool = signing_tools[psig->st];

		if (!tool || !tool->print)
			BUG("signing tool %s undefined", signature_type_name(psig->st));

		tool->print(psig, flags);
	}
}

size_t strbuf_append_signatures(struct strbuf *buf, const struct signatures *sigs)
{
	size_t i;
	struct signature *psig;

	if (!buf)
		BUG("invalid strbuf passed to signature append function");

	if (!sigs)
		return 0;

	for (i = 0; i < sigs->nsigs; i++) {
		psig = sigs->sigs[i];
		strbuf_addbuf(buf, &(psig->sig));
	}

	return sigs->nsigs;
}
#endif

enum signature_type signature_type_by_name(const char *name)
{
	enum signature_type st;

	if (!name)
		return default_type;

	for (st = SIGNATURE_TYPE_FIRST; st < SIGNATURE_TYPE_LAST; st++)
		if (!strcmp(signing_tools[st]->name, name))
			return st;

	return error("unknown signature type: %s", name);
}

const char *signature_type_name(enum signature_type st)
{
	if (!VALID_SIGNATURE_TYPE(st))
		return unknown_signature_type;

	return signing_tools[st]->name;
}

int git_signing_config(const char *var, const char *value, void *cb)
{
	int ret = 0;
	char *t1, *t2, *t3, *buf;
	enum signature_type st;
	const struct signing_tool *tool;

	printf("%s = %s\n", var, value);

	/* user.signingkey is a deprecated alias for signing.<signing.default>.key */
	if (!strcmp(var, "user.signingkey")) {
		if (!value)
			return config_error_nonbool(var);
		
		set_signing_key(value, default_type);

		return 0;
	}

	/* gpg.format is a deprecated alias for signing.default */
	if (!strcmp(var, "gpg.format") || !strcmp(var, "signing.default")) {
		if (!value)
			return config_error_nonbool(var);

		if (!VALID_SIGNATURE_TYPE((st = signature_type_by_name(value))))
			return config_error_nonbool(var);

		set_signature_type(st);

		return 0;
	}

	/* gpg.program is a deprecated alias for signing.openpgp.program */
	if (!strcmp(var, "gpg.program")) {
		if (!value)
			return config_error_nonbool(var);
		return (*(signing_tools[OPENPGP_SIGNATURE]->config))(
				"program", value, cb);
	}

	buf = xstrdup(var);
	t1 = strtok(buf, ".");
	t2 = strtok(NULL, ".");
	t3 = strtok(NULL, ".");

	/* gpg.<format>.* is a deprecated alias for signing.<format>.* */
	if (!strcmp(t1, "gpg") || !strcmp(t1, "signing")) {
		if (!VALID_SIGNATURE_TYPE((st = signature_type_by_name(t2)))) {
			free(buf);
			return error("unsupported variable: %s", var);
		}

		tool = signing_tools[st];
		if (!tool || !tool->config) {
			free(buf);
			BUG("signing tool %s undefined", signature_type_name(tool->st));
		}

		ret = tool->config(t3, value, cb);
	}

	free(buf);
	return ret;
}

void set_signing_key(const char *key, enum signature_type st)
{
	/*
	 * Make sure we track the latest default signing key so that if the
	 * default signing format changes after this, we can make sure the
	 * default signing tool knows the key to use.
	 */
	free(default_signing_key);
	default_signing_key = xstrdup(key);

	if (!VALID_SIGNATURE_TYPE(st))
		signing_tools[default_type]->set_key(key);
	else
		signing_tools[st]->set_key(key);
}

const char *get_signing_key(enum signature_type st)
{
	if (!VALID_SIGNATURE_TYPE(st))
		return signing_tools[default_type]->get_key();

	return signing_tools[default_type]->get_key();
}

void set_signature_type(enum signature_type st)
{
	if (!VALID_SIGNATURE_TYPE(st)) {
		error("unsupported signature type: %d", st);
		return;
	}

	default_type = st;

	/* 
	 * If the signing key has been set, then make sure the new default
	 * signing tool knows about it. this fixes the order of operations
	 * error of parsing the default signing key and default signing
	 * format in arbitrary order.
	 */
	if (default_signing_key)
		set_signing_key(default_signing_key, default_type);
}

enum signature_type get_signature_type(void)
{
	return default_type;
}


