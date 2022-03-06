bool ss_is_valid(sockaddr_storage *);
bool likely_blocked(https_result *);
char *https_strerror(https_result *result);
https_request *https_request_alloc(size_t bufsize, unsigned int flags, unsigned timeout);
