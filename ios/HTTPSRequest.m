@import Foundation;
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "newnode.h"
#include "log.h"
#include "g_https_cb.h"
#include "HTTPSRequest.h"
#include "timer.h"


char *https_strerror(https_result *);

https_error map_https_error(const char *error_domain, NSInteger errorCode)
{
    if (strcmp(error_domain, "NSURLErrorDomain") != 0) {
        // unrecognized error domain
        return HTTPS_GENERIC_ERROR;
    }
    switch(errorCode) {
        // error codes and descriptions from:
        // https://developer.apple.com/documentation/foundation/1508628-url_loading_system_error_codes
        //+KM
        // it's tedious to list them all and to
        // list then in order they appear in that
        // document, but for now that seems like
        // the best way to make sure that the
        // important cases are all dealt with.
        //-KM
    case NSURLErrorAppTransportSecurityRequiresSecureConnection:
        //+CO
        // App Transport Security disallowed a
        // connection because there is no secure
        // network connection.
        //-CO
        //KM XXX not sure if this is the right https_error
        return HTTPS_TLS_ERROR;
    case NSURLErrorBackgroundSessionInUseByAnotherProcess:
        //+CO
        // An app or app extension attempted to
        // connect to a background session that is
        // already connected to a process.
        //-CO
        return HTTPS_RESOURCE_EXHAUSTED;
    case NSURLErrorBackgroundSessionRequiresSharedContainer:
        //+CO
        // The shared container identifier of the
        // URL session configuration is needed but
        // hasn’t been set.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorBackgroundSessionWasDisconnected:
        //+CO
        // The app is suspended or exits while a
        // background data task is processing.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorBadServerResponse:
        //+CO
        // The URL Loading System received bad
        // data from the server.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorBadURL:
        //+CO
        // A malformed URL prevented a URL request from being initiated.
        //-CO
        return HTTPS_PARAMETER_ERROR;
    case NSURLErrorCallIsActive:
        //+CO
        // A connection was attempted while a
        // phone call was active on a network that
        // doesn’t support simultaneous phone and
        // data communication, such as EDGE or
        // GPRS.
        //-CO
        return HTTPS_RESOURCE_EXHAUSTED;
    case NSURLErrorCancelled:
        return HTTPS_NO_ERROR;
    case NSURLErrorCannotCloseFile:
        //+CO
        // A download task couldn’t close the downloaded file on disk.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorCannotConnectToHost:
        //+CO
        // An attempt to connect to a host failed.
        // could be either a timeout or connection refused?
        // (could also be IP blocked)
        //-CO
        return HTTPS_BLOCKING_ERROR;
    case NSURLErrorCannotCreateFile:
        //+CO
        // A download task couldn’t create the
        // downloaded file on disk because of an
        // I/O failure.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorCannotDecodeContentData:
        //+CO
        // Content data received during a
        // connection request had an unknown
        // content encoding.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorCannotDecodeRawData:
        //+CO
        // Content data received during a
        // connection request couldn’t be decoded
        // for a known content encoding.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorCannotFindHost:
        //+CO
        // The host name for a URL couldn’t be resolved.
        //-CO
        return HTTPS_DNS_ERROR;
    case NSURLErrorCannotLoadFromNetwork:
        //+CO
        // A specific request to load an item only
        // from the cache couldn't be satisfied.
        //-CO
        //+KM
        // Seems like this should not be able
        // to happen to us since we should
        // disable any local caches.
        //-KM
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorCannotMoveFile:
        //+CO
        // A downloaded file on disk couldn’t be moved.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorCannotOpenFile:
        //+CO
        // A downloaded file on disk couldn’t be opened.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorCannotParseResponse:
        //+CO
        // A response to a connection request couldn’t be parsed.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorCannotRemoveFile:
        //+CO
        // A downloaded file couldn’t be removed from disk.
        //-CO
        //+KM
        // shouldn't happen, but apparently the URL was accessible.
        //-KM
        return HTTPS_NO_ERROR;
    case NSURLErrorCannotWriteToFile:
        //+CO
        // A download task couldn’t write the file to disk.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorClientCertificateRejected:
        //+CO
        // A server certificate was rejected.
        //-CO
        return HTTPS_TLS_CERT_ERROR;
    case NSURLErrorClientCertificateRequired:
        //+CO
        // A client certificate was required to
        // authenticate an SSL connection during a
        // connection request.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorDataLengthExceedsMaximum:
        //+CO
        // The length of the resource data
        // exceeded the maximum allowed.
        //-CO
        // XXX do we need to detect this and set the truncated flag? (sigh)
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorDataNotAllowed:
        //+CO
        // The cellular network disallowed a connection.
        //-CO
        return HTTPS_RESOURCE_EXHAUSTED;
    case NSURLErrorDNSLookupFailed:
        //+CO
        // The host address couldn’t be found via DNS lookup.
        //-CO
        return HTTPS_DNS_ERROR;
    case NSURLErrorDownloadDecodingFailedMidStream:
        //+CO
        // A download task failed to decode an
        // encoded file during the download.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorDownloadDecodingFailedToComplete:
        //+CO
        // A download task failed to decode an encoded file after downloading.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorFileDoesNotExist:
        //+CO
        // The specified file doesn’t exist.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorFileIsDirectory:
        //+CO
        // A request for an FTP file resulted in
        // the server responding that the file is
        // not a plain file, but a directory.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorFileOutsideSafeArea:
        //+CO
        // An internal file operation failed.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorHTTPTooManyRedirects:
        //+CO
        // A redirect loop was detected or the
        // threshold for number of allowable
        // redirects was exceeded (currently 16).
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorInternationalRoamingOff:
        //+CO
        // The attempted connection required
        // activating a data context while
        // roaming, but international roaming is
        // disabled.
        //-CO
        return HTTPS_RESOURCE_EXHAUSTED;
    case NSURLErrorNetworkConnectionLost:
        //+CO
        // A client or server connection was
        // severed in the middle of an in-progress
        // load.
        //-CO
        //+KM
        // this could be a symptom of blocking but will assume not
        //-KM
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorNoPermissionsToReadFile:
        //+CO
        // A resource couldn’t be read because of
        // insufficient permissions.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorNotConnectedToInternet:
        //+CO
        // A network resource was requested, but
        // an internet connection has not been
        // established and can’t be established
        // automatically.
        //-CO
        return HTTPS_RESOURCE_EXHAUSTED;
    case NSURLErrorRedirectToNonExistentLocation:
        //+CO
        // A redirect was specified by way of
        // server response code, but the server
        // didn’t accompany this code with a
        // redirect URL.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorRequestBodyStreamExhausted:
        //+CO
        // A body stream was needed but the client
        // did not provide one.
        //-CO
        return HTTPS_PARAMETER_ERROR;
    case NSURLErrorResourceUnavailable:
        //+CO
        // A requested resource couldn’t be retrieved.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorSecureConnectionFailed:
        //+CO
        // An attempt to establish a secure
        // connection failed for reasons that
        // can’t be expressed more specifically.
        //-CO
        return HTTPS_TLS_ERROR;
    case NSURLErrorServerCertificateHasBadDate:
        //+CO
        // A server certificate is expired, or is
        // not yet valid.
        //-CO
        return HTTPS_TLS_CERT_ERROR;
    case NSURLErrorServerCertificateHasUnknownRoot:
        //+CO
        // A server certificate wasn’t signed by
        // any root server.
        //-CO
        return HTTPS_TLS_CERT_ERROR;
    case NSURLErrorServerCertificateNotYetValid:
        //+CO
        // A server certificate isn’t valid yet.
        //-CO
        return HTTPS_TLS_CERT_ERROR;
    case NSURLErrorServerCertificateUntrusted:
        //+CO
        // A server certificate was signed by a
        // root server that isn’t trusted.
        //-CO
        return HTTPS_TLS_CERT_ERROR;
    case NSURLErrorTimedOut:
        //+CO
        // An asynchronous operation timed out.
        //-CO
        return HTTPS_TIMEOUT_ERROR;
    case NSURLErrorUnknown:
        //+CO
        // The URL Loading System encountered an
        // error that it can’t interpret.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorUnsupportedURL:
        //+CO
        // A properly formed URL couldn’t be handled by the framework.
        //-CO
        return HTTPS_PARAMETER_ERROR;
    case NSURLErrorUserAuthenticationRequired:
        //+CO
        // Authentication was required to access a resource.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorUserCancelledAuthentication:
        //+CO
        // An asynchronous request for
        // authentication has been canceled by the
        // user.
        //-CO
        return HTTPS_GENERIC_ERROR;
    case NSURLErrorZeroByteResource:
        //+CO
        // A server reported that a URL has a
        // non-zero content length, but terminated
        // the network connection gracefully
        // without sending any data.
        //-CO
        return HTTPS_GENERIC_ERROR;
    default:
        return HTTPS_GENERIC_ERROR;
    }
    return HTTPS_GENERIC_ERROR;
}

// Apple documentation says to not create a new session for every
// request.  So we keep some commonly used types of pre-configured
// sessions cached and only create a new session if a different
// configuration was requested.

static NSURLSession *defaultURLSession;
static NSURLSession *geoipURLSession;
static NSURLSession *statsURLSession;
static NSURLSession *tryfirstURLSession;

// return the session configuration we need to implement 'flags' in https_request
static NSURLSessionConfiguration *sessionConfig(network *n, int flags)
{
    NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;

    // override proxy settings if HTTPS_DIRECT is requested
    if (flags & HTTPS_DIRECT) {
        [config setConnectionProxyDictionary:@{}];
    } else {
        port_t port = newnode_get_port(n);
        // XXX: this should not duplicate logic from NewNode.m
        if (!port) {
            [config setConnectionProxyDictionary:@{}];
        } else {
            [config setConnectionProxyDictionary:@{
                @"HTTPEnable": @1,
                @"HTTPProxy": @"127.0.0.1",
                @"HTTPPort": @(port),
                @"HTTPSEnable": @1,
                @"HTTPSProxy": @"127.0.0.1",
                @"HTTPSPort": @(port),
                @"SOCKSEnable": @1,
                @"SOCKSProxy": @"127.0.0.1",
                @"SOCKSPort": @(port)
            }];
        }
    }
    config.HTTPCookieAcceptPolicy = NSHTTPCookieAcceptPolicyNever;
    return config;
}

static char *method_string(int flags)
{
    static char buf[20];
    switch (flags & HTTPS_METHOD_MASK) {
    case HTTPS_METHOD_GET: return "GET";
    case HTTPS_METHOD_HEAD: return "HEAD";
    case HTTPS_METHOD_POST: return "POST";
    case HTTPS_METHOD_PUT: return "PUT";
    default:
        snprintf(buf, sizeof(buf), "method %d", flags & HTTPS_METHOD_MASK);
        return buf;
    }
}

@interface HTTPSRequest () <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
@property https_complete_callback completion_cb;
@end

// XXX: for < iOS 15 compatibility
static NSMutableDictionary<NSURLSessionTask*,HTTPSRequest*> *_tasks;

@interface SessionDelegate : NSObject <NSURLSessionDelegate, NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
@end

@implementation SessionDelegate
+ (void)initialize
{
    _tasks = NSMutableDictionary.new;
}

+ (id)sharedDelegate
{
    static SessionDelegate *sharedDelegate = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedDelegate = self.new;
    });
    return sharedDelegate;
}

- (void)               URLSession:(NSURLSession *)sess
        didBecomeInvalidWithError:(NSError *)error
{
    NSLog(@"session:%p didBecomeInvalidWithError %@ %@\n", sess, error.domain, error.localizedDescription);
}

- (void)         URLSession:(NSURLSession *)session
        didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
          completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential *credential))completionHandler
{
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
}

#pragma mark - NSURLSessionTaskDelegate

- (void)  URLSession:(NSURLSession *)session
                task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error
{
    [_tasks[task] URLSession:session task:task didCompleteWithError:error];
}

#pragma mark - NSURLSessionDataDelegate

- (void)        URLSession:(NSURLSession *)session
                      task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
                newRequest:(NSURLRequest *)newRequest
         completionHandler:(void (^)(NSURLRequest *))completionHandler
{
    [_tasks[task] URLSession:session task:task willPerformHTTPRedirection:response newRequest:newRequest completionHandler:completionHandler];
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler
{
    [_tasks[dataTask] URLSession:session dataTask:dataTask didReceiveResponse:response completionHandler:completionHandler];
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data
{
    [_tasks[dataTask] URLSession:session dataTask:dataTask didReceiveData:data];
}

@end


@implementation HTTPSRequest
{
    https_request request;
    https_result result;
    NSURLSessionTask *task;
    uint64_t xfer_start_time_us;
    network *n;
}

- (instancetype)initWithRequest:(const https_request*)req
                       callback:(https_complete_callback)cb
                        network:(network*)nn
{
    if (self = [super init]) {
        request = *req;
        _completion_cb = cb;
        n = nn;
    }
    return self;
}

- (NSURLSession*)sessionForRequest
{
    NSURLSessionConfiguration *config;

    id delegate = SessionDelegate.sharedDelegate;

    switch (request.flags & HTTPS_OPTION_MASK) {
    case HTTPS_GEOIP_FLAGS:
        if (!geoipURLSession) {
            geoipURLSession = [NSURLSession sessionWithConfiguration:sessionConfig(n, HTTPS_GEOIP_FLAGS)
                                                            delegate:delegate delegateQueue:nil];
        }
        return geoipURLSession;
    case HTTPS_STATS_FLAGS:
        if (!statsURLSession) {
            statsURLSession = [NSURLSession sessionWithConfiguration:sessionConfig(n, HTTPS_STATS_FLAGS)
                                                            delegate:delegate delegateQueue:nil];
        }
        return statsURLSession;
    case HTTPS_TRYFIRST_FLAGS:
        if (!tryfirstURLSession) {
            tryfirstURLSession = [NSURLSession sessionWithConfiguration:sessionConfig(n, HTTPS_TRYFIRST_FLAGS)
                                                               delegate:delegate delegateQueue:nil];
        }
        return tryfirstURLSession;
    default:
        if (!defaultURLSession) {
            debug("sessionForOptions: flags=0x%x returning default session\n", request.flags);
            defaultURLSession = [NSURLSession sessionWithConfiguration:sessionConfig(n, request.flags)];
        }
        return defaultURLSession;
    }
}

- (void)start:(NSURL *)url
{
    debug("%s: url:%s method:%s\n", __func__, url.absoluteString.UTF8String, method_string(request.flags));

    xfer_start_time_us = us_clock();

    NSMutableURLRequest *ns_request = [NSMutableURLRequest.alloc initWithURL:url];
    NSURLSession *session = self.sessionForRequest;

    if (!(request.flags & HTTPS_DIRECT)) {
        static port_t port = -1;
        if (port != newnode_get_port(n)) {
            port = newnode_get_port(n);
            [defaultURLSession invalidateAndCancel];
            defaultURLSession = NULL;
            [geoipURLSession invalidateAndCancel];
            geoipURLSession = NULL;
            [statsURLSession invalidateAndCancel];
            statsURLSession = NULL;
            [tryfirstURLSession invalidateAndCancel];
            tryfirstURLSession = NULL;
            session = self.sessionForRequest;
        }
    }

    // bypass local URL resource cache
    // (remote cache is presumably ok, we want the same behavior we'd normally get from the
    // publicly accessible server even if it's fronted by a cache)
    ns_request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    ns_request.allowsCellularAccess = YES; // XXX what we really want here is the same policy that's
                                           //     currently in effect for a web browser on the platform
    if (request.flags & HTTPS_ONE_BYTE) {
        ns_request.HTTPShouldUsePipelining = NO;
    } else {
        ns_request.HTTPShouldUsePipelining = YES;
    }
    ns_request.HTTPShouldHandleCookies = NO;

    switch (request.flags & HTTPS_METHOD_MASK) {
    case HTTPS_METHOD_GET:
        break;
    case HTTPS_METHOD_PUT:
        ns_request.HTTPMethod = @"PUT";
        if (request.body_content_type) {
            [ns_request setValue:@(request.body_content_type) forHTTPHeaderField:@"Content-Type"];
        }
        ns_request.HTTPBody = [NSData dataWithBytes:request.body length:request.body_size];
        break;
    case HTTPS_METHOD_HEAD:
        ns_request.HTTPMethod = @"HEAD";
        break;
    case HTTPS_METHOD_POST:
        ns_request.HTTPMethod = @"POST";
        if (request.body_content_type) {
            [ns_request setValue:@(request.body_content_type) forHTTPHeaderField:@"Content-Type"];
        }
        ns_request.HTTPBody = [NSData dataWithBytes:request.body length:request.body_size];
        break;
    }
    if (request.flags & HTTPS_ONE_BYTE) {
        [ns_request setValue:@"bytes=0-1" forHTTPHeaderField:@"Range"];
    }
    if (request.timeout_sec > 0) {
        [ns_request setTimeoutInterval:request.timeout_sec];
    }
    if (request.headers) {
        for (int i = 0; request.headers[i]; ++i) {
            char *colon = strchr(request.headers[i], ':');
            if (!colon) {
                continue;
            }
            auto_free char *name = strndup(request.headers[i], colon - request.headers[i]);
            char *value = colon + 1;
            if (strcasecmp(name, "content-type") != 0 && strcasecmp(name, "range") != 0) {
                [ns_request setValue:@(value) forHTTPHeaderField:@(name)];
            }
        }
    }
    task = [session dataTaskWithRequest:ns_request];
    if (@available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)) {
        task.delegate = self;
    } else {
        _tasks[task] = self;
    }
    [task resume];
}

- (void)cancel
{
    debug("%s request:%p\n", __func__, self);
    _completion_cb = NULL;
    [task cancel];
}

#pragma mark - NSURLSessionTaskDelegate

- (void)  URLSession:(NSURLSession *)session
                task:(NSURLSessionTask *)mytask
didCompleteWithError:(NSError *)error
{
    if (error) {
        NSLog(@"%s request:%p %@ %@\n", __func__, self, error.domain, error.localizedDescription);
        if (result.http_status == 451 || result.http_status == 403) {
            result.https_error = HTTPS_BLOCKING_ERROR;
            debug("%s request:%p HTTP code %d indicates possible server-side blocking\n", __func__,
                  self, result.https_error);
        } else if (!result.https_error) {
            // don't change existing error code if there is one
            result.https_error = map_https_error(error.domain.UTF8String, error.code);
        }
        debug("%s: request:%p https_error set to %d (%s)\n", __func__, self,
              result.https_error, https_strerror(&result));
    }

    uint64_t xfer_time_us = us_clock() - xfer_start_time_us;
    bool success = result.https_error == HTTPS_NO_ERROR;
    debug("%s request:%p completed:%d [%lld us]\n", __func__, self, success, xfer_time_us);
    [_tasks removeObjectForKey:task];
    task = nil;

    if (!result.body && request.bufsize > 0) {
        result.body = calloc(1, result.body_length + 1);
    }

    network_async(n, ^{
        if (_completion_cb) {
            _completion_cb(success, &result);
        }
        free(result.body);
        CFRelease((__bridge CFTypeRef)self);
    });
}

#pragma mark - NSURLSessionDataDelegate

- (void)        URLSession:(NSURLSession *)session
                      task:(NSURLSessionTask *)mytask
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
                newRequest:(NSURLRequest *)newRequest
         completionHandler:(void (^)(NSURLRequest *))completionHandler
{
    if (request.flags & HTTPS_NO_REDIRECT) {
        debug("%s: request:%p [%lld us] ignoring redirect as requested\n",
              __func__, newRequest, us_clock() - xfer_start_time_us);
        completionHandler(NULL);
        return;
    }
    debug("%s: request:%p [%lld us] accepting redirect\n",
          __func__, newRequest, us_clock() - xfer_start_time_us);
    completionHandler(newRequest);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler
{
    NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *) response;
    int statusCode = (int)httpResponse.statusCode;
    debug("%s: request:%p HTTP status code = %d [%lld us]\n", __func__, self, statusCode, us_clock() - xfer_start_time_us);
    result.http_status = statusCode;
    if (request.flags & HTTPS_ONE_BYTE) {
        NSLog(@"%s %@ cancelling due to HTTPS_ONE_BYTE\n", __func__, self);
        completionHandler(NSURLSessionResponseCancel);
        return;
    }
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data
{
    debug("%s: request:%p received %ld bytes [%lld us]\n",
          __func__, self, data.length,
          us_clock() - xfer_start_time_us);
    if (request.bufsize == 0) {
        // caller didn't ask for the response body, and it's not an
        // error that we're getting a response.  internally cancel the
        // request to avoid unnecessary waste of bandwidth, etc.
        debug("%s: no response body requested, cancelling dataTask\n", __func__);
        [dataTask cancel];
        return;
    }
    if (!result.body) {
        // for now assume that requested bufsize is small enough
        // that we can just malloc the whole thing in one call,
        // rather than realloc()ing as needed.
        result.body = calloc(1, request.bufsize);
        if (!result.body) {
            result.https_error = HTTPS_RESOURCE_EXHAUSTED;
            debug("%s malloc failed, cancelling dataTask\n", __func__);
            [dataTask cancel];
            return;
        }
    }
    [data enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
        off_t roomleft = request.bufsize - result.body_length;
        if (roomleft <= 0) {
            debug("%s: insufficient room in buffer, cancelling dataTask\n", __func__);
            result.flags |= HTTPS_RESULT_TRUNCATED;
            [dataTask cancel];
            *stop = YES;
            return;
        }
        size_t to_copy = MIN((off_t)byteRange.length, roomleft);
        memcpy(&result.body[result.body_length], bytes, to_copy);
        //debug("%s: copied %lu bytes into buffer\n", __func__, to_copy);
        result.body_length += to_copy;
    }];
}

@end

void cancel_https_request(network *n, https_request_token token)
{
    debug("%s request:%p\n", __func__, token);
    HTTPSRequest *r = (__bridge HTTPSRequest*)token;
    [r cancel];
}

https_request_token do_https(network *n, const https_request *request, const char *url, https_complete_callback cb)
{
    HTTPSRequest *r;
    @autoreleasepool {
        NSURL *ns_url = [NSURL URLWithString:@(url)];
        r = [HTTPSRequest.alloc initWithRequest:request callback:cb network:n];
        [r start:ns_url];
    }
    return (__bridge_retained https_request_token)r;
}
