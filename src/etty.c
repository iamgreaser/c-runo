#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <sys/types.h>
#include <unistd.h>

#include "etty.h"

char *etty_strdup(const char *s)
{
	size_t len = strlen(s);
	char *ret = malloc(len+1);
	memcpy(ret, s, len);
	ret[len] = '\x00';
	return ret;
}

const char *etty_get_errstr(int errcode)
{
	switch(errcode)
	{
		// 1xx Informational
		case 100: return "Continue";
		case 101: return "Switching Protocols";

		// 2xx Successful
		case 200: return "OK";
		case 201: return "Created";
		case 202: return "Accepted";
		case 203: return "Non-Authoritative Information";
		case 204: return "No Content";
		case 205: return "Reset Content";
		case 206: return "Partial Content";

		// 3xx Redirection
		case 300: return "Multiple Choices";
		case 301: return "Moved Permanently";
		case 302: return "Moved Temporarily";
		case 303: return "See Other";
		case 304: return "Not Modified";
		case 305: return "Use Proxy";

		// 4xx Client Error
		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 402: return "Payment Required";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 406: return "Not Acceptable";
		case 407: return "Proxy Authentication Required";
		case 408: return "Request Timeout";
		case 409: return "Conflict";
		case 410: return "Gone";
		case 411: return "Length Required";
		case 412: return "Precondition Failed";
		case 413: return "Request Entity Too Large";
		case 414: return "Request-URI Too Long";
		case 415: return "Unsupported Media Type";
		case 418: return "I'm A Teapot";
		case 451: return "Govt A Shit";

		// 5xx Server Error
		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		case 504: return "Gateway Timeout";
		case 505: return "HTTP Version Not Supported";

		default:
			return "Unknown error";
	}
}

void etty_generate_error(int errcode, const char *msg)
{
	(void)msg;
	const char *errstr = etty_get_errstr(errcode);

	fprintf(stderr, "ERR %03d %s - %s\r\n", errcode, errstr, msg);

	// Write our headers
	printf("HTTP/1.1 %03d %s\r\n", errcode, errstr);
	printf("Content-type: text/html\r\n");
	printf("\r\n");

	// Contents
	printf(
		"<html>\r\n"
		"<head>\r\n"
			"<title>%03d %s</title>\r\n"
		"</head>\r\n"
		"<body>\r\n"
		, errcode, errstr
	);
	printf(
		"<center>\r\n"
		"<h1>%s</h1>\r\n"
		"<hr />\r\n"
		"<p>c-runo application server</p>\r\n"
		, errstr
	);

	printf(
		"</body>\r\n"
		"</html>\r\n"
	);
}

void etty_clear_header(struct etty_header *header)
{
	if(header->method_str != NULL) { free(header->method_str); header->method_str = NULL; }
	if(header->path != NULL) { free(header->path); header->path = NULL; }
	if(header->httpver != NULL) { free(header->httpver); header->httpver = NULL; }
	header->method = ETTY_HTTP_METHOD_INVALID;
	if(header->pairs != NULL) {
		for(size_t i = 0; i < header->pair_count; i++) {
			free(header->pairs[i].key); header->pairs[i].key = NULL;
			free(header->pairs[i].value); header->pairs[i].value = NULL;
		}
		header->pairs = realloc(header->pairs, 0);
	}
	header->pair_count = 0;
}

size_t etty_iterate_header_fields_by_key(struct etty_header *header, const char *key, void *arg, bool (*f_callback)(void *arg, const char *value))
{
	size_t found_counter = 0;
	for(size_t i = 0; i < header->pair_count; i++) {
		if(!strcmp(key, header->pairs[i].key)) {
			found_counter++;
			if(!f_callback(arg, header->pairs[i].value)) {
				break;
			}
		}
	}
	return found_counter;
}

static bool cb1_find_header_field(void *arg, const char *value)
{
	*((const char **)arg) = value;
	return false;
}

const char *etty_find_header_field(struct etty_header *header, const char *key)
{
	const char *ret = NULL;
	etty_iterate_header_fields_by_key(header, key, (void *)&ret, cb1_find_header_field);
	return ret;
}

bool etty_read_and_parse_headers(struct etty_header *header)
{
	char linebuf[2048];

	// Read headers
	ETTY_ASSERT_TASK(fgets(linebuf, sizeof(linebuf), stdin) != NULL, 400, "command read error");

	{
		size_t len = strlen(linebuf);
		if(len >= 2 && linebuf[len-2] == '\r') {
			linebuf[len-2] = linebuf[len-1];
			linebuf[len-1] = 0;
			len--;
		}
		ETTY_ASSERT_TASK(len >= 1 && linebuf[len-1] == '\n', 400, "command parse error");
		linebuf[len-1] = 0;
	}

	char *method_str = linebuf;

	char *path = strchr(method_str, ' ');
	ETTY_ASSERT_TASK(path != NULL, 400, "command parse error");
	*(path++) = 0;

	char *httpver = strchr(path, ' ');
	ETTY_ASSERT_TASK(httpver != NULL, 400, "command parse error");
	*(httpver++) = 0;

	header->method_str = etty_strdup(method_str);
	header->path = etty_strdup(path);
	header->httpver = etty_strdup(httpver);

	fprintf(stderr, "%d: METHOD \"%s\", \"%s\", \"%s\"\n", getpid(), header->method_str, header->path, header->httpver);

	// Confirm it's all good
	ETTY_ASSERT_TASK(!strcmp(header->httpver, "HTTP/1.1"), 400, "not HTTP/1.1");
	header->method = ETTY_HTTP_METHOD_INVALID;

	if(!strcmp(header->method_str, "POST")) {
		header->method = ETTY_HTTP_METHOD_POST;
	} else if(!strcmp(header->method_str, "GET")) {
		header->method = ETTY_HTTP_METHOD_GET;
	} else if(!strcmp(header->method_str, "PUT")) {
		header->method = ETTY_HTTP_METHOD_PUT;
	} else if(!strcmp(header->method_str, "DELETE")) {
		header->method = ETTY_HTTP_METHOD_DELETE;
	} else if(!strcmp(header->method_str, "HEAD")) {
		header->method = ETTY_HTTP_METHOD_HEAD;
	} else {
		ETTY_ASSERT_TASK(false, 400, "invalid method");
	}

	ETTY_ASSERT_TASK(header->method == ETTY_HTTP_METHOD_GET, 400, "unhandled method");

	while(fgets(linebuf, sizeof(linebuf), stdin) != NULL) {
		size_t len = strlen(linebuf);
		if(len >= 2 && linebuf[len-2] == '\r') {
			linebuf[len-2] = linebuf[len-1];
			linebuf[len-1] = 0;
			len--;
		}
		ETTY_ASSERT_TASK(len >= 1 && linebuf[len-1] == '\n', 400, "header arg parse error");
		linebuf[len-1] = 0;

		if(len == 1) {
			break;
		}

		char *colonpos = strchr(linebuf, ':');
		ETTY_ASSERT_TASK(colonpos != NULL, 400, "parse error");
		ETTY_ASSERT_TASK(colonpos[1] == ' ', 400, "parse error");
		colonpos[0] = 0;

		// Parse argument
		header->pair_count++;
		header->pairs = realloc(header->pairs, sizeof(header->pairs[0])*header->pair_count);
		struct etty_pair *p = &header->pairs[header->pair_count-1];
		char *arg_key = linebuf;
		char *arg_value = colonpos + 2;
		p->key = etty_strdup(arg_key);
		p->value = etty_strdup(arg_value);

		if(!strcmp(arg_key, "Host")) {
			fprintf(stderr, "HOSTNAME: \"%s\"\n", arg_value);
		} else {
			fprintf(stderr, "Unhandled argument: %s = \"%s\"\n", arg_key, arg_value);
		}
	}

	if(ferror(stdin)) {
		perror("fgets");
		return false;
	}

	return true;
}

