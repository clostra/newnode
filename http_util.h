#ifndef __HTTP_UTIL__
#define __HTTP_UTIL__

struct evhttp_request;

void overwrite_header(struct evhttp_request *to, const char *key, const char *value);
void copy_header(struct evhttp_request *from, struct evhttp_request *to, const char *key);

#endif // __HTTP_UTIL__
