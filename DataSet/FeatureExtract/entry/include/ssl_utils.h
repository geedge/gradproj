#pragma once 

#define EXTENSION_COUNT_MAX 128
#define CIPHER_SUITE_COUNT_MAX 256

struct cipher_suite
{
	uint16_t value;
	const char* name;
};

struct tls_extension{
	int value;
	const char* name;
};

enum chello_parse_result
{
	CHELLO_PARSE_SUCCESS = 0,
	CHELLO_PARSE_INVALID_FORMAT = -1,
	CHELLO_PARSE_NOT_ENOUGH_BUFF = -2
};

struct ssl_version
{
	uint8_t minor;	
	uint8_t major;
	uint16_t ossl_format;
	char str_format[STRING_MAX];
};

struct ssl_chello
{
	struct ssl_version min_version;
	struct ssl_version max_version;
	int cipher_suites_count;
	int extension_count;
	int cipher_suite_list[CIPHER_SUITE_COUNT_MAX];
	int extension_list[EXTENSION_COUNT_MAX];
	char sni[STRING_MAX];
	char alpn[STRING_MAX];
};

struct ssl_version_map{
	int value;
	const char *name;
};

void ssl_chello_parse(struct ssl_chello* _chello, const unsigned char* buff, size_t buff_len, enum chello_parse_result* result);
void ssl_chello_free(struct ssl_chello* chello);