#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "newnode.h"
#include "log.h"
#import <Foundation/Foundation.h>
#include "g_https_cb.h"
#include "HTTPSRequest.h"
#include "timer.h"

char *https_strerror(https_result *);

void HTTPSRequest_init()
{
    // we used to need this; leave it here in case we need it again someday.
}

void set_https_error(https_result *result, const char *error_domain, NSInteger errorCode)
{
    if (strcmp(error_domain, "NSURLErrorDomain") == 0) {
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
            result->https_error = HTTPS_TLS_ERROR;
            break;
        case NSURLErrorBackgroundSessionInUseByAnotherProcess:
            //+CO
            // An app or app extension attempted to
            // connect to a background session that is
            // already connected to a process.
            //-CO
            result->https_error = HTTPS_RESOURCE_EXHAUSTED;
            break;
        case NSURLErrorBackgroundSessionRequiresSharedContainer:
            //+CO
            // The shared container identifier of the
            // URL session configuration is needed but
            // hasn’t been set.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorBackgroundSessionWasDisconnected:
            //+CO
            // The app is suspended or exits while a
            // background data task is processing.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorBadServerResponse:
            //+CO
            // The URL Loading System received bad
            // data from the server.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorBadURL:
            //+CO
            // A malformed URL prevented a URL request from being initiated.
            //-CO
            result->https_error = HTTPS_PARAMETER_ERROR;
            break;
        case NSURLErrorCallIsActive:
            //+CO
            // A connection was attempted while a
            // phone call was active on a network that
            // doesn’t support simultaneous phone and
            // data communication, such as EDGE or
            // GPRS.
            //-CO
            result->https_error = HTTPS_RESOURCE_EXHAUSTED;
            break;
        case NSURLErrorCancelled:
            //+CO
            // This seems like the expected result
            // when cancellation of a download has
            // been requested.  But in that case we
            // want to make sure that we don't call
            // the completion callback.
            //-CO
            // debug("NSURLErrorCancelled %d\n", request->flags & HTTPS_CANCELLED);

            // we might cancel ourselves for multiple reasons including
            // received data too big; those are not errors
            // (but if we cancel ourselves we won't call this routine)
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotCloseFile:
            //+CO
            // A download task couldn’t close the downloaded file on disk.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotConnectToHost:
            //+CO
            // An attempt to connect to a host failed.
            // could be either a timeout or connection refused?
            // (could also be IP blocked)
            //-CO
            result->https_error = HTTPS_BLOCKING_ERROR;
            break;
        case NSURLErrorCannotCreateFile:
            //+CO
            // A download task couldn’t create the
            // downloaded file on disk because of an
            // I/O failure.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotDecodeContentData:
            //+CO
            // Content data received during a
            // connection request had an unknown
            // content encoding.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotDecodeRawData:
            //+CO
            // Content data received during a
            // connection request couldn’t be decoded
            // for a known content encoding.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotFindHost:
            //+CO
            // The host name for a URL couldn’t be resolved.
            //-CO
            result->https_error = HTTPS_DNS_ERROR;
            break;
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
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotMoveFile:
            //+CO
            // A downloaded file on disk couldn’t be moved.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotOpenFile:
            //+CO
            // A downloaded file on disk couldn’t be opened.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotParseResponse:
            //+CO
            // A response to a connection request couldn’t be parsed.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorCannotRemoveFile:
            //+CO
            // A downloaded file couldn’t be removed from disk.
            //-CO
            //+KM
            // shouldn't happen, but apparently the URL was accessible.
            //-KM
            result->https_error = HTTPS_NO_ERROR;
            break;
        case NSURLErrorCannotWriteToFile:
            //+CO
            // A download task couldn’t write the file to disk.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorClientCertificateRejected:
            //+CO
            // A server certificate was rejected.
            //-CO
            result->https_error = HTTPS_TLS_CERT_ERROR;
            break;
        case NSURLErrorClientCertificateRequired:
            //+CO
            // A client certificate was required to
            // authenticate an SSL connection during a
            // connection request.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorDataLengthExceedsMaximum:
            //+CO
            // The length of the resource data
            // exceeded the maximum allowed.
            //-CO
            // XXX do we need to detect this and set the truncated flag? (sigh)
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorDataNotAllowed:
            //+CO
            // The cellular network disallowed a connection.
            //-CO
            result->https_error = HTTPS_RESOURCE_EXHAUSTED;
            break;
        case NSURLErrorDNSLookupFailed:
            //+CO
            // The host address couldn’t be found via DNS lookup.
            //-CO
            result->https_error = HTTPS_DNS_ERROR;
            break;
        case NSURLErrorDownloadDecodingFailedMidStream:
            //+CO
            // A download task failed to decode an
            // encoded file during the download.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorDownloadDecodingFailedToComplete:
            //+CO
            // A download task failed to decode an encoded file after downloading.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorFileDoesNotExist:
            //+CO
            // The specified file doesn’t exist.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorFileIsDirectory:
            //+CO
            // A request for an FTP file resulted in
            // the server responding that the file is
            // not a plain file, but a directory.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorFileOutsideSafeArea:
            //+CO
            // An internal file operation failed.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorHTTPTooManyRedirects:
            //+CO
            // A redirect loop was detected or the
            // threshold for number of allowable
            // redirects was exceeded (currently 16).
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorInternationalRoamingOff:
            //+CO
            // The attempted connection required
            // activating a data context while
            // roaming, but international roaming is
            // disabled.
            //-CO
            result->https_error = HTTPS_RESOURCE_EXHAUSTED;
            break;
        case NSURLErrorNetworkConnectionLost:
            //+CO
            // A client or server connection was
            // severed in the middle of an in-progress
            // load.
            //-CO
            //+KM 
            // this could be a symptom of blocking but will assume not
            //-KM
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorNoPermissionsToReadFile:
            //+CO
            // A resource couldn’t be read because of
            // insufficient permissions.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorNotConnectedToInternet:
            //+CO
            // A network resource was requested, but
            // an internet connection has not been
            // established and can’t be established
            // automatically.
            //-CO
            result->https_error = HTTPS_RESOURCE_EXHAUSTED;
            break;
        case NSURLErrorRedirectToNonExistentLocation:
            //+CO
            // A redirect was specified by way of
            // server response code, but the server
            // didn’t accompany this code with a
            // redirect URL.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorRequestBodyStreamExhausted:
            //+CO
            // A body stream was needed but the client
            // did not provide one.
            //-CO
            result->https_error = HTTPS_PARAMETER_ERROR;
            break;
        case NSURLErrorResourceUnavailable:
            //+CO
            // A requested resource couldn’t be retrieved.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorSecureConnectionFailed:
            //+CO
            // An attempt to establish a secure
            // connection failed for reasons that
            // can’t be expressed more specifically.
            //-CO
            result->https_error = HTTPS_TLS_ERROR;
            break;
        case NSURLErrorServerCertificateHasBadDate:
            //+CO
            // A server certificate is expired, or is
            // not yet valid.
            //-CO
            result->https_error = HTTPS_TLS_CERT_ERROR;
            break;
        case NSURLErrorServerCertificateHasUnknownRoot:
            //+CO
            // A server certificate wasn’t signed by
            // any root server.
            //-CO
            result->https_error = HTTPS_TLS_CERT_ERROR;
            break;
        case NSURLErrorServerCertificateNotYetValid:
            //+CO
            // A server certificate isn’t valid yet.
            //-CO
            result->https_error = HTTPS_TLS_CERT_ERROR;
            break;
        case NSURLErrorServerCertificateUntrusted:
            //+CO
            // A server certificate was signed by a
            // root server that isn’t trusted.
            //-CO
            result->https_error = HTTPS_TLS_CERT_ERROR;
            break;
        case NSURLErrorTimedOut:
            //+CO
            // An asynchronous operation timed out.
            //-CO
            result->https_error = HTTPS_TIMEOUT_ERROR;
            break;
        case NSURLErrorUnknown:
            //+CO
            // The URL Loading System encountered an
            // error that it can’t interpret.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorUnsupportedURL:
            //+CO
            // A properly formed URL couldn’t be handled by the framework.
            //-CO
            result->https_error = HTTPS_PARAMETER_ERROR;
            break;
        case NSURLErrorUserAuthenticationRequired:
            //+CO
            // Authentication was required to access a resource.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorUserCancelledAuthentication:
            //+CO
            // An asynchronous request for
            // authentication has been canceled by the
            // user.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        case NSURLErrorZeroByteResource:
            //+CO
            // A server reported that a URL has a
            // non-zero content length, but terminated
            // the network connection gracefully
            // without sending any data.
            //-CO
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        default:
            result->https_error = HTTPS_GENERIC_ERROR;
            break;
        }
    } else {
        // unrecognized error domain
        result->https_error = HTTPS_GENERIC_ERROR;
    }
}

// Apple documentation says to not create a new session for every
// request.  So we keep some commonly used types of pre-configured
// sessions cached and only create a new session if a different
// configuration was requested.

static NSURLSession *geoipURLSession;
static NSURLSession *statsURLSession;
static NSURLSession *tryfirstURLSession;

// return the session configuration we need to implement 'flags' in https_request
static NSURLSessionConfiguration *sessionConfig(network *n, int flags)
{
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];

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

// return the session we want to use, configured the way we want to
// use it, to implement the flags in the https_request
//
// this will either be a preconfigured session or a custom session
// (if the latter it will need to be explicitly invalidated)
static NSURLSession *sessionForRequest(network *n, https_request *hr, id delegate)
{
    NSURLSessionConfiguration *config;

    switch (hr->flags & HTTPS_OPTION_MASK) {
    case HTTPS_GEOIP_FLAGS:
        if (geoipURLSession == NULL) {
            NSURLSessionConfiguration *config_geoip = sessionConfig(n, HTTPS_GEOIP_FLAGS);
            geoipURLSession = [NSURLSession sessionWithConfiguration:config_geoip
                                                            delegate:delegate delegateQueue:nil];
        }
        return geoipURLSession;
    case HTTPS_STATS_FLAGS:
        if (statsURLSession == NULL) {
            NSURLSessionConfiguration *config_stats = sessionConfig(n, HTTPS_STATS_FLAGS);
            statsURLSession = [NSURLSession sessionWithConfiguration:config_stats
                                                            delegate:delegate delegateQueue:nil];
        }
        return statsURLSession;
    case HTTPS_TRYFIRST_FLAGS:
        if (tryfirstURLSession == NULL) {
            NSURLSessionConfiguration *config_tryfirst = sessionConfig(n, HTTPS_TRYFIRST_FLAGS);
            tryfirstURLSession = [NSURLSession sessionWithConfiguration:config_tryfirst
                                                               delegate:delegate delegateQueue:nil];
        }
        return tryfirstURLSession;
    default:
        debug("sessionForOptions: returning custom session\n");
        config = sessionConfig(n, hr->flags);
        // NB: need to invalidate this session when finished with it, else it will leak memory
        // no delegate for this one, b/c we don't know what the session needs anyway
        return [NSURLSession sessionWithConfiguration:config];
    }
}

// keep an array of HTTPSRequests that are associated ("linked") with
// small integers (request_ids) so that we have a way to allow NN to
// cancel requests without having to deal with bridged casts, ref
// counting, etc., and also so that the NSURLSession tasks can
// complete independently of the main client code.

#define NLINK 100

static struct link {
    int64_t request_id;                // this encodes both array index and request_id
    volatile bool cancelled;    // YES if cancelled by NewNode
    volatile bool internally_cancelled; // YES if we should stop trying to collect response data
                                        // but will still call a completion callback
    https_request request;        // copy of request passed to g_https_cb()
    HTTPSRequest *r;
    https_complete_callback completion_cb;
    https_result result;        // storage for result passed to completion callback
} links[NLINK];

static int64_t request_serial = 1;       // request_ids are always > 0

// allocate an unused struct link and return its index into the links[] array
// (which isn't the same as the request_id)

static int alloc_link(https_request *request)
{
    for (int i = 0; i < NLINK; ++i) {
        if (links[i].request_id == 0) {
            links[i].request_id = request_serial++ * NLINK + i;
            links[i].cancelled = NO;
            links[i].internally_cancelled = NO;
            if (request)
                links[i].request = *request;
            else {
                // implement defaults if request==NULL
                // (bufsize=0, flags=0, timeout_sec=7)
                memset(&(links[i].request), 0, sizeof(https_request));
                links[i].request.timeout_sec = 7;
            }
            links[i].r = NULL;
            links[i].completion_cb = NULL;
            memset((&links[i].result), 0, sizeof(https_result));
            if (request) {
                if (request->flags & HTTPS_USE_HEAD)
                    links[i].result.result_flags |= HTTPS_REQUEST_USE_HEAD;
                if (request->flags & HTTPS_ONE_BYTE)
                    links[i].result.result_flags |= HTTPS_REQUEST_ONE_BYTE;
            }
            links[i].result.request_id = links[i].request_id;
            return i;
        }
    }
    return -1;
}

// free the link with the specified request_id

static void free_link(int64_t request_id)
{
    if (request_id <= 0) {
        return;
    }
    int i = request_id % NLINK;
    if (links[i].request_id == request_id) {
        links[i].request_id = 0;
        links[i].cancelled = NO;
        links[i].internally_cancelled = NO;
        memset(&(links[i].request), 0, sizeof(https_request));
        links[i].r = NULL;  // XXX does this decr the ref count for
                            //     the HTTPSRequest instance?
        links[i].completion_cb = NULL;
        if (links[i].result.response_body) {
            free(links[i].result.response_body);
            links[i].result.response_body = NULL;
        }
        memset((&links[i].result), 0, sizeof(https_result));
        return;
    } else {
        // debug("XXX %s links[%d].request_id %" PRId64 " != request_id %" PRId64 "\n",
        //       __func__, i, links[i].request_id, request_id);
    }
}

// find the link with the specified request_id
// return the index of the link in the links array

static int find_link(int64_t request_id)
{
    if (request_id <= 0) {
        // debug("XXX %s invalid request_id:%" PRId64 "\n", __func__, request_id);
        return -1;
    }
    int i = request_id % NLINK;
    if (links[i].request_id == request_id) {
        // debug("XXX %s (request_id:%" PRId64 ") (link_index:%d)\n", __func__, request_id, i);
        return i;
    }
    // debug("XXX %s request_id %" PRId64 " not found at index %d\n", __func__, request_id, i);
    return -1;
}

void cancel_https_request(network *n, int64_t request_id)
{
    debug("%s (request_id:%" PRId64 ")\n", __func__, request_id);
    int link_index = find_link(request_id);
    if (link_index < 0) {
        return;
    }
    links[link_index].cancelled = YES;
    [links[link_index].r cancel];
}

@implementation HTTPSRequest
{ 
    bool needs_invalidation;
    NSURLSessionDataTask *task;
    NSURLSession *session;
    network *n;
    https_complete_callback completion_cb;
}

- (void)cancel
{
    if (needs_invalidation) {
        [session invalidateAndCancel];
    } else {
        [task cancel];
    }
}

- (int64_t) start:(NSURL *)ns_url
          network:(network*)nn
          request:(https_request *)req
         callback:(https_complete_callback)cb
{
    n = nn;
    int link_index = alloc_link(req);

    if (link_index < 0) {
        debug("HTTPSRequest: NLINK exceeded\n");
        // call the completion handler with an error so we always report errors consistently
        timer_start(n, 100, ^{
            https_result result = {.https_error = HTTPS_RESOURCE_EXHAUSTED};
            cb(false, &result);
        });
        return 0;
    }
    needs_invalidation = NO;
    completion_cb = cb;
    int64_t my_request_id = links[link_index].request_id;
    debug("%s: my_request_id:%" PRId64 " url:%s\n", __func__, my_request_id, 
          [[ns_url absoluteString] UTF8String]);

    // we need to store some things in the links[] array so that the
    // delegate called by the data task can access them, since the
    // same instance of HTTPSRequest is used as the delegate for each
    // distinct type of NSURLSession.  So we can't use HTTPSRequest
    // instance variables to pass task-related variables to the
    // delegate.
    links[link_index].request = *req;
    links[link_index].r = self;
    links[link_index].completion_cb = cb;

    links[link_index].result.req_time = time(NULL);
    links[link_index].result.xfer_start_time_us = us_clock();
    links[link_index].result.response_length = 0;
    links[link_index].result.https_error = 0;
    links[link_index].result.http_status = 0;

    NSMutableURLRequest *ns_request = [[NSMutableURLRequest alloc] initWithURL:ns_url];
    session = sessionForRequest(n, req, self);
    if (session != geoipURLSession && session != statsURLSession && session != tryfirstURLSession)
        needs_invalidation = YES;    

    // bypass local URL resource cache
    // (remote cache is presumably ok, we want the same behavior we'd normally get from the
    // publicly accessible server even if it's fronted by a cache)
    ns_request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    ns_request.allowsCellularAccess = YES; // XXX what we really want here is the same policy that's
                                           //     currently in effect for a web browser on the platform
    ns_request.HTTPShouldUsePipelining = NO;
    ns_request.HTTPShouldHandleCookies = NO;
    if (req->flags & HTTPS_USE_HEAD)
        ns_request.HTTPMethod = @"HEAD";
    else if (req->flags & HTTPS_ONE_BYTE)
        [ns_request setValue:@"bytes=0-1" forHTTPHeaderField:@"Range"];
    if (req->timeout_sec > 0)
        [ns_request setTimeoutInterval:req->timeout_sec];

    task = [session dataTaskWithRequest:ns_request];
    task.taskDescription = [NSString stringWithFormat:@"%lld", my_request_id];
    // task.prefersIncrementalDelivery = YES;   // this is the default
    [task resume];
    return my_request_id;
}

// begin NSURLSessionDelegate methods
// https://developer.apple.com/documentation/foundation/nsurlsessiondelegate

// Tells the URL session that the session has been invalidated.
//
// I'm not sure what could cause a session to be invalidated other
// than invoking the finishTasksAndInvalidate method or the
// invalidateAndCancel method (neither of which we do).  But maybe a
// session can be invalidated if the app is backgrounded, in which
// case we might need some way of recovering? -KM
//
// https://developer.apple.com/documentation/foundation/nsurlsessiondelegate/1407776-urlsession

- (void)               URLSession:(NSURLSession *)sess
        didBecomeInvalidWithError:(NSError *)error
{
    const char *error_message = "";
    const char *error_domain = "";
    if (error) {
        error_message = [[error localizedDescription] cStringUsingEncoding:NSUTF8StringEncoding];
        error_domain = [[error domain] cStringUsingEncoding:NSUTF8StringEncoding];
    }
    if (sess == geoipURLSession) {
        debug("session:geoipURLSession didBecomeInvalidWithError %s:%s\n", error_domain, error_message);
        geoipURLSession = NULL;
    } else if (sess == statsURLSession) {
        debug("session:statsURLSession didBecomeInvalidWithError %s:%s\n", error_domain, error_message);
        statsURLSession = NULL;
    } else if (sess == tryfirstURLSession) {
        debug("session:tryfirstURLSession didBecomeInvalidWithError %s:%s\n", error_domain, error_message);
        tryfirstURLSession = NULL;
    } else {
        debug("session:%p didBecomeInvalidWithError %s:%s\n", sess, error_domain, error_message);
    }
}

// Tells the delegate that all messages enqueued for a session have been delivered.
//
// In iOS, when a background transfer completes or requires
// credentials, if your app is no longer running, your app is
// automatically relaunched in the background, and the app’s
// UIApplicationDelegate is sent an
// application:handleEventsForBackgroundURLSession:completionHandler:
// message. This call contains the identifier of the session that
// caused your app to be launched. You should then store that
// completion handler before creating a background configuration
// object with the same identifier, and creating a session with that
// configuration. The newly created session is automatically
// reassociated with ongoing background activity.
//
// When your app later receives a
// URLSessionDidFinishEventsForBackgroundURLSession: message, this
// indicates that all messages previously enqueued for this session
// have been delivered, and that it is now safe to invoke the
// previously stored completion handler or to begin any internal
// updates that may result in invoking the completion handler.
//
// Important
// 
// Because the provided completion handler is part of UIKit, you must
// call it on your main thread.
//
// https://developer.apple.com/documentation/foundation/nsurlsessiondelegate/1617185-urlsessiondidfinisheventsforback
//
// I'm hoping that this isn't needed since we don't use background URL sessions. -KM

#if 0
- (void)URLSessionDidFinishEventsForBackgroundURLSession:(NSURLSession *)session;
{
}
#endif

// Requests credentials from the delegate in response to a
// session-level authentication request from the remote server.
//
// - https://developer.apple.com/documentation/foundation/nsurlsessiondelegate/1409308-urlsession

- (void)         URLSession:(NSURLSession *)session 
        didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge 
          completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, 
                                      NSURLCredential *credential))completionHandler
{
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
}

- (void)  URLSession:(NSURLSession *) session
                task:(NSURLSessionTask *) mytask
didCompleteWithError:(NSError *) error
{
    const char *error_message = "";
    const char *error_domain = "";
    int statusCode = 0;
    int64_t my_request_id = atol(mytask.taskDescription.UTF8String);
    int link_index = find_link(my_request_id);

    if (error) {
        NSHTTPURLResponse *response = (NSHTTPURLResponse *) mytask.response;
        if (response) {
            statusCode = [response statusCode];
            debug("%s my_request_id:%" PRId64 " statusCode:%d\n", __func__, my_request_id, statusCode);
        }
        error_message = [[error localizedDescription] cStringUsingEncoding:NSUTF8StringEncoding];
        error_domain = [[error domain] cStringUsingEncoding:NSUTF8StringEncoding];
        debug("%s my_request_id:%" PRId64 " %s:%s\n", __func__, my_request_id, error_domain, error_message);
    }
    else {
        debug("%s my_request_id:%" PRId64 " (task completed no error)\n", __func__, my_request_id);
    }
    if (link_index < 0) {
        return;
    }
    if (links[link_index].request_id == my_request_id && !links[link_index].cancelled) {
        uint64_t now = us_clock();
        links[link_index].result.xfer_time_us = now - links[link_index].result.xfer_start_time_us;
        if (error) {
            NSInteger errorCode = [error code];
            if (statusCode == 451) {
                links[link_index].result.https_error = HTTPS_BLOCKING_ERROR;
                debug("%s my_request_id:%" PRId64 " HTTP code %d indicates server-side blocking\n", __func__,
                      my_request_id, statusCode);
            }
            else if (links[link_index].internally_cancelled) {
                // don't change existing error code if there is one
                debug("%s: my_request_id:%lld request was internally cancelled\n", __func__, my_request_id);
            }
            else {
                set_https_error(&(links[link_index].result), error_domain, errorCode);
                debug("%s: my_request_id:%" PRId64 " error:%ld domain:%s message:%s\n", __func__, my_request_id,
                      errorCode, error_domain, error_message);
            }
            debug("%s: my_request_id:%" PRId64 " https_error set to %d (%s)\n", __func__, my_request_id,
                  links[link_index].result.https_error, 
                  https_strerror(&(links[link_index].result)));
        } else {
            links[link_index].result.https_error = HTTPS_NO_ERROR;
        }

        // call callback from a timer to make sure it's done in the libevent thread
        // note that links[link_index] might be assigned to a different request
        // by the time the callback gets called
        network_async(n, ^{
            if (links[link_index].request_id != my_request_id) {
                debug("%s links[%d].request_id:%" PRId64 " != my_request_id:%" PRId64 "; NOT calling completion callback\n", 
                      __func__, link_index, links[link_index].request_id, my_request_id);
            } else if (links[link_index].cancelled) {
                debug("%s my_request_id:%" PRId64 " (late) cancelled; NOT calling completion callback\n", 
                      __func__, my_request_id);
            } else if (links[link_index].internally_cancelled) {
                debug("%s my_request_id:%" PRId64 " internally cancelled; calling completion callback\n", 
                      __func__, my_request_id);
                // call completion callback because caller did not explicitly cancel
                links[link_index].completion_cb (error == NULL, &(links[link_index].result));
            } else {
                debug("%s my_request_id:%" PRId64 " completed [%lld us]; calling completion callback\n", 
                      __func__, my_request_id, us_clock() - links[link_index].result.xfer_start_time_us);
                links[link_index].completion_cb (error == NULL, &(links[link_index].result));
            }
            free_link(my_request_id);
        });
    } else {
        network_async(n, ^{
            free_link(my_request_id);
        });
    }
}

- (void)        URLSession:(NSURLSession *)session
                      task:(NSURLSessionTask *)mytask
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
                newRequest:(NSURLRequest *)request
         completionHandler:(void (^)(NSURLRequest *))completionHandler
{
    int64_t my_request_id = atol(mytask.taskDescription.UTF8String);
    int link_index = find_link(my_request_id);
    if (link_index < 0) {
        return;
    }
    if (links[link_index].cancelled) {
        return;
    }
    debug("%s: my_request_id:%" PRId64 " [%lld us]\n", __func__, my_request_id, 
          us_clock() - links[link_index].result.xfer_start_time_us);
    if (links[link_index].request.flags & HTTPS_NO_REDIRECT) {
        debug("%s: ignoring redirect as requested\n", __func__);
        completionHandler(NULL);
    } else {
        debug("%s: accepting redirect\n", __func__);
        completionHandler(request);
    }
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler
{
    NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *) response;
    NSInteger statusCode = [httpResponse statusCode];

    // XXX if we're doing a try first request we could cancel the task
    //     at this point, call the completion callback, and be done,
    //     since any response at all from the origin server means the
    //     connection isn't blocked by an intermediary.   But for now
    //     just save the status code from the HTTP response and let
    //     the data task complete normally.
    int64_t my_request_id = atoi(dataTask.taskDescription.UTF8String);
    debug("%s: my_request_id:%" PRId64 " HTTP status code = %ld\n", __func__, my_request_id, statusCode);
    int link_index = find_link(my_request_id);
    if (link_index >= 0 && !links[link_index].cancelled) {
        links[link_index].result.http_status = statusCode;
        debug("%s [%lld us]\n", __func__, us_clock() - links[link_index].result.xfer_start_time_us);
    }
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data
{
    // if this HTTPSRequest hasn't been cancelled, add the received
    // data to the buffer.  if there's not enough room in the buffer,
    // cancel the dataTask.
    int64_t my_request_id = atol(dataTask.taskDescription.UTF8String);
        
    int link_index = find_link(my_request_id);
    if (link_index < 0 || links[link_index].cancelled) {
        return;
    }
    debug("%s: my_request_id:%" PRId64 " received %ld bytes [%lld us]\n",
          __func__, my_request_id, data.length,
          us_clock() - links[link_index].result.xfer_start_time_us);
    if (links[link_index].request.bufsize == 0) {
        // caller didn't ask for the response body, and it's not an
        // error that we're getting a response.  internally cancel the
        // request to avoid unnecessary waste of bandwidth, etc.
        debug("%s: no response body requested, cancelling transfer\n", __func__);
        links[link_index].result.https_error = HTTPS_NO_ERROR;
        debug("%s about to cancel dataTask\n", __func__);
        [dataTask cancel];
    } else if (links[link_index].cancelled == NO && links[link_index].internally_cancelled == NO) {
        if (links[link_index].result.response_body == NULL) {
            // for now assume that requested bufsize is small enough
            // that we can just malloc the whole thing in one call,
            // rather than realloc()ing as needed.
            if ((links[link_index].result.response_body = malloc(links[link_index].request.bufsize)) == NULL) {
                links[link_index].result.https_error = HTTPS_RESOURCE_EXHAUSTED;
                // XXX could call the completion callback here to
                //     improve response time, but we'd need to make
                //     sure to not call the completion callback again.
                //     malloc failure is unlikely to happen very often
                //     anyway.
                links[link_index].internally_cancelled = YES;
                debug("%s malloc failed, cancelling dataTask\n", __func__);
                [dataTask cancel];
                return;
            }
        }
        off_t roomleft = links[link_index].request.bufsize - links[link_index].result.response_length;
        if (roomleft <= 0) {
            debug("%s: insufficient room in buffer, cancelling\n", __func__);
            links[link_index].result.result_flags |= HTTPS_RESULT_TRUNCATED;
            // XXX could call the completion callback here to
            //     improve response time, but we'd need to make
            //     sure to not call the completion callback again.
            links[link_index].internally_cancelled = YES;
            debug("%s about to cancel dataTask\n", __func__);
            [dataTask cancel];
            return;
        }
        // copy as many bytes as will fit
        //
        // XXX should ideally use [data enumerateByteRangesUsingBlock:...]
        [data getBytes:(links[link_index].result.response_body + links[link_index].result.response_length)
                length:roomleft];
        if ((off_t) data.length > roomleft) {
            debug("%s: insufficient room for new data, cancelling\n", __func__);
            links[link_index].result.result_flags |= HTTPS_RESULT_TRUNCATED;
            links[link_index].internally_cancelled = YES;
            links[link_index].result.response_length = links[link_index].request.bufsize;
            debug("%s about to cancel dataTask\n", __func__);
            [dataTask cancel];
        } else {
            debug("%s: copied %lu bytes into buffer\n", __func__, data.length);
            links[link_index].result.response_length += (off_t) data.length;
        }
    }
}
@end

int64_t do_https(network *n, port_t port, const char *url, https_complete_callback cb, https_request *request)
{
    @autoreleasepool {
        NSURL *ns_url = [NSURL URLWithString:@(url)];
        return [HTTPSRequest.alloc start:ns_url network:n request:request callback:cb];
    }
}
