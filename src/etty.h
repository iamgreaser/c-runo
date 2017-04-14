
enum etty_http_method {
	ETTY_HTTP_METHOD_POST = 0,
	ETTY_HTTP_METHOD_GET,
	ETTY_HTTP_METHOD_PUT,
	ETTY_HTTP_METHOD_DELETE,

	ETTY_HTTP_METHOD_HEAD,

	ETTY_HTTP_METHOD_INVALID
};

struct etty_pair {
	char *key;
	char *value;
};

struct etty_header {
	char *method_str;
	char *path;
	char *httpver;

	enum etty_http_method method;

	size_t pair_count;
	struct etty_pair *pairs;
};

const char *etty_get_errstr(int errcode);
void etty_generate_error(int errcode, const char *msg);
void etty_clear_header(struct etty_header *header);
size_t etty_iterate_header_fields_by_key(struct etty_header *header, const char *key, void *arg, bool (*f_callback)(void *arg, const char *value));
const char *etty_find_header_field(struct etty_header *header, const char *key);
bool etty_read_and_parse_headers(struct etty_header *header);

#define ETTY_ASSERT_TASK(cond, errcode, msg) \
	if(!(cond)) { \
		etty_generate_error(errcode, msg); \
		fprintf(stderr, "FAIL: %s\n", msg); \
		return false; \
	}

