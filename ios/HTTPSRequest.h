void HTTPSRequest_init();

@interface HTTPSRequest: NSObject <NSURLSessionDelegate, NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
- (void)cancel;
- (int64_t)start:(NSURL *)ns_url network:(network*)nn request:(https_request *)req callback:(https_complete_callback)cb;
@end

int64_t do_https(network *n, unsigned short http_port, const char *url, https_complete_callback cb, https_request *request);
