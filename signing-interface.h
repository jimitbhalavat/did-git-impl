#ifndef SIGNING_INTERFACE_H
#define SIGNING_INTERFACE_H

struct strbuf;

#define OUTPUT_VERBOSE		1
#define OUTPUT_RAW			2
#define OUTPUT_OMIT_STATUS	4

enum signature_type {
	OPENPGP_SIGNATURE,
	X509_SIGNATURE,

	SIGNATURE_TYPE_LAST,
	SIGNATURE_TYPE_FIRST = OPENPGP_SIGNATURE,
	SIGNATURE_TYPE_COUNT = SIGNATURE_TYPE_LAST - SIGNATURE_TYPE_FIRST,
	SIGNATURE_TYPE_DEFAULT = OPENPGP_SIGNATURE,
	SIGNATURE_TYPE_UNKNOWN = -1
};
enum signature_type default_type;

#define VALID_SIGNATURE_TYPE(x) \
	((x >= SIGNATURE_TYPE_FIRST) && (x < SIGNATURE_TYPE_LAST))

struct signature {
	struct strbuf sig;
	struct strbuf output;
	struct strbuf status;
	enum signature_type st;

	/*
	 * possible "result":
	 * 0 (not checked)
	 * N (checked but no further result)
	 * U (untrusted good)
	 * G (good)
	 * B (bad)
	 */
	char result;
	char *signer;
	char *key;
	char *fingerprint;
	char *primary_key_fingerprint;
};

struct signatures {
	size_t nsigs;
	size_t alloc;
	struct signature **sigs;
};

#define SIGNATURES_INIT  { .nsigs = 0, .alloc = 0, .sigs = NULL }
#define SIGNATURE_INIT  { .sig = STRBUF_INIT, .output = STRBUF_INIT, .status = STRBUF_INIT, .st = OPENPGP_SIGNATURE, .result = '0', .signer = NULL, .key = NULL }

void signatures_clear(struct signatures *sigs);
void signature_clear(struct signature *sig);

/*
 * Create a detached signature for the contents of "payload" and append
 * it to the list of signatures in "sigs". The signature type determines which
 * type of signature to create and the optional "signing_key" specifies
 * the key. If no signing key is specified the default key from the
 * config will be used. If no default is found, then an error is
 * returned. If the signing operation fails an error is returned.
 */
int sign_payload(const char *payload, size_t size, struct signatures *sigs,
		enum signature_type st, const char *signing_key);

/*
 * Bridge function to be called by the git code for buffer signature
 */
int sign_buffer(struct strbuf *buffer, struct strbuf *signature, const char *signing_key);

/* 
 * Look at the signed content (e.g. a signed tag object), whose payload
 * is followed by one or more detached signatures. Return the offset of
 * the first signature, or the size of the buf when there are no 
 * signatures. If a valid signatures struct is passed in, the signatures 
 * will be parsed and copied into its array of sigs.
 */
size_t parse_signatures(const char *payload, size_t size,
		struct signatures *sigs);

/*
 * Bridge function to be called by the git code for parsing signatures in a buffer
 */
size_t parse_signature(const char *buf, size_t size);

/*
 * Run the signature verification tools to see if the payload matches
 * the detached signatures. The output and status of the of the checks
 * is recorded in the signatures struct. The caller must use
 * parse_signatures or sign_buffer to initialize the signatures struct
 * before calling this function.
 */
int verify_signed_buffer(const char *payload, size_t payload_size,
			 const char *signature, size_t signature_size,
			 struct strbuf *output, struct strbuf *status);

/*
 * Verify multiple signatures in a single buffer
 */
int verify_buffer_signatures(const char *payload, size_t size,
		struct signatures *sigs);

/*
 * Bridge function to be called by the git code to verify a signed payload
 */
int check_signature(const char *payload, size_t plen, const char *signature,
	size_t slen, struct signature *sigc);

/*
 * Prints the results of either signing or verifying the payload in the
 * signatures struct. If the OUTPUT_VERBOSE flag is specified, then the
 * payload is printed to stdout. If the OUTPUT_RAW flag is specified, 
 * the raw status output from the signing tool is printed to stderr, 
 * otherwise, the nice results from the tool is printed to stderr.
 */
void print_signatures(const struct signatures *sigs, unsigned flags);

/*
 * Bridge function to be called by the git code to print a signature
 */
void print_signature_buffer(const struct signature *sigc, unsigned flags);

/*
 * Appends each of the detached signatures to the end of the strbuf
 * passed in. Returns the number of signatures appended to the buffer.
 */
size_t strbuf_append_signatures(struct strbuf *buf, const struct signatures *sigs);

/*
 * Translate the name of the signature tool into the enumerated value
 * for the signature type.
 */
enum signature_type signature_type_by_name(const char *name);
const char *signature_type_name(enum signature_type st);

/*
 * Config related functions
 */
int git_signing_config(const char *var, const char *value, void *cb);
void set_signing_key(const char *key, enum signature_type st);
const char *get_signing_key(enum signature_type st);
void set_signing_program(const char *program, enum signature_type st);
const char *get_signing_program(enum signature_type st);
void set_signature_type(enum signature_type st);
enum signature_type get_signature_type(void);

#endif

