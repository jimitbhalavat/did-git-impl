#ifndef SIGNING_TOOL_H
#define SIGNING_TOOL_H

struct strbuf;
struct signature;

typedef int (*sign_fn)(const char *payload, size_t size,
	struct signature **sig, const char *key);
typedef size_t (*parse_fn)(const char *payload, size_t size,
	struct signature **sig);
typedef int (*verify_fn)(const char *payload, size_t size,
	struct signature *sig);
typedef void (*print_fn)(const struct signature *sig, unsigned flags);
typedef int (*config_fn)(const char *var, const char *value, void *cb);
typedef void (*set_key_fn)(const char *key);
typedef const char *(*get_key_fn)(void);
typedef void (*set_program_fn)(const char *signing_program);
typedef const char *(*get_program_fn)(void);

struct signing_tool {
	const enum signature_type st;
	const char* name;
	sign_fn sign;
	parse_fn parse;
	verify_fn verify;
	print_fn print;
	config_fn config;
	set_key_fn set_key;
	get_key_fn get_key;
	set_program_fn set_program;
	get_program_fn get_program;
};

#endif

