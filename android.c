#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include <jni.h>
#include <android/log.h>

#include "libevent/util-internal.h"
#include "bugsnag/bugsnag_ndk.h"

#include "network.h"
#include "thread.h"
#include "constants.h"
#include "log.h"
#include "newnode.h"
#include "d2d.h"
#include "lsd.h"
#include "inttypes.h"
#include "dns_prefetch.h"

static int pfd[2];
static JavaVM *g_jvm;
static jobject bugsnagClient;
static jobject newNode;
static network *g_n;


void* stdio_thread(void *useradata)
{
    ssize_t readSize;
    char buf[1024];

    while ((readSize = read(pfd[0], buf, sizeof buf - 1)) > 0) {
        if (buf[readSize - 1] == '\n') {
            --readSize;
        }
        buf[readSize] = 0;
        __android_log_write(ANDROID_LOG_VERBOSE, "newnode", buf);
    }
    return NULL;
}

void start_stdio_thread()
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    pipe(pfd);
    dup2(pfd[1], 1);
    dup2(pfd[1], 2);
    pthread_t t;
    if (pthread_create(&t, NULL, stdio_thread, NULL) == -1) {
        return;
    }
    pthread_detach(t);
}

#define BUGSNAG_API_KEY "141ea25aa72c276c49d3a154b82f2b1f"

#define STR(A) #A

#define JSTR(s) (*env)->NewStringUTF(env, s)

#define IMPORT(pkg, class) jclass c ## class = (*env)->FindClass(env, STR(pkg) "/" STR(class));
#define IMPORT_INNER(pkg, class) jclass c ## class = (*env)->FindClass(env, STR(pkg) "$" STR(class));

#define CALL_VOID(class, obj, meth, sig, ...) \
 jmethodID m ## meth = (*env)->GetMethodID(env, class, #meth, "(" STR(sig) ")V"); \
 if (m ## meth) (*env)->CallVoidMethod(env, obj, m ## meth, __VA_ARGS__);

#define CATCH(code) if ((*env)->ExceptionOccurred(env)) { \
  (*env)->ExceptionDescribe(env); \
  (*env)->ExceptionClear(env); \
  code; \
}

#define push_frame() (*env)->PushLocalFrame(env, 16)
#define pop_frame() (*env)->PopLocalFrame(env, NULL);


void jvm_frame(JNIEnv* env, void (^c)())
{
    push_frame();
    c();
    pop_frame();
}

enum notify_type {
    ALL = 1,
    USER = 2,
    APP = 3,
    DEVICE = 4,
    CONTEXT = 5,
    RELEASE_STAGES = 6,
    FILTERS = 7,
    BREADCRUMB = 8,
    META = 9
};

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_updateBugsnagDetails(JNIEnv* env, jobject thiz, int notifyType)
{
    static bool bugsnag_setup = false;
    if (!bugsnag_setup) {
        bugsnag_setup = true;
        setupBugsnag(env);
    }
    switch ((enum notify_type)notifyType) {
    case USER: Java_com_bugsnag_android_ndk_BugsnagObserver_populateUserDetails(env, NULL); break;
    case APP: Java_com_bugsnag_android_ndk_BugsnagObserver_populateAppDetails(env, NULL); break;
    case DEVICE: Java_com_bugsnag_android_ndk_BugsnagObserver_populateDeviceDetails(env, NULL); break;
    case CONTEXT: Java_com_bugsnag_android_ndk_BugsnagObserver_populateContextDetails(env, NULL); break;
    case RELEASE_STAGES: Java_com_bugsnag_android_ndk_BugsnagObserver_populateReleaseStagesDetails(env, NULL); break;
    case FILTERS: Java_com_bugsnag_android_ndk_BugsnagObserver_populateFilterDetails(env, NULL); break;
    case BREADCRUMB: Java_com_bugsnag_android_ndk_BugsnagObserver_populateBreadcumbDetails(env, NULL); break;
    case META: Java_com_bugsnag_android_ndk_BugsnagObserver_populateMetaDataDetails(env, NULL); break;
    case ALL:
    default:
        Java_com_bugsnag_android_ndk_BugsnagObserver_populateErrorDetails(env, NULL); break;
    }
}

void bugsnag_leave_breadcrumb_log(const char *buf)
{
    bsg_breadcrumb *crumb = bugsnag_breadcrumb_init("newnode", BSG_CRUMB_LOG);
    bugsnag_breadcrumb_add_metadata(crumb, "stdout", (char*)buf);
    bugsnag_add_breadcrumb(crumb);
}

JNIEnv* get_env()
{
    JNIEnv *env;
    int stat = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    assert(stat == JNI_OK);
    return env;
}

// Request that the platform's DNS asychronously library query IPv4
// and IPv6 addresses (as appropriate) for 'host'.  The results are
// stored in evdns cache so that NN can connect directly to an address
// and hopefully also in the platform's DNS cache so that any "try first"
// attempts will be faster.
//
// This routine doesn't return a result.  NN will use the result of
// the query if it arrives in time, or fallback to evdns.

void platform_dns_prefetch(network *n, const char *host)
{
    debug("%s host:%s\n", __func__, host);
    if (!newNode) {
        return;
    }
    JNIEnv *env = get_env();
    jvm_frame(env, ^() {
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(
            debug("%s exception line %d\n", __func__, __LINE__);
            return;
        );
        CALL_VOID(cNewNode, newNode,
                  dnsPrefetch,
                  Ljava/lang/String;,
                  JSTR(host));
        CATCH(
            debug("%s exception line %d\n", __func__, __LINE__);
            return;
        );
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_storeDnsPrefetchResult(JNIEnv *env, jobject thiz, jstring host, jobjectArray addresses)
{

    const char *hoststr = (*env)->GetStringUTFChars(env, host, NULL);
    int n_addresses = (*env)->GetArrayLength(env, addresses);

    debug("%s host:%s n_addresses:%d\n", __func__, hoststr, n_addresses);

    evutil_addrinfo *rai = NULL;
    for (int i = 0; i < n_addresses; ++i) {
        jbyteArray jaddr = (jbyteArray)(*env)->GetObjectArrayElement(env, addresses, i);
        jbyte* addr = (*env)->GetByteArrayElements(env, jaddr, NULL); 
        socklen_t addrlen = (*env)->GetArrayLength(env, jaddr);
        evutil_addrinfo nullhints = {
            .ai_family = PF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP
        };
        evutil_addrinfo *ai = evutil_new_addrinfo_((sockaddr*)addr, addrlen, &nullhints);
        rai = evutil_addrinfo_append_(rai, ai);
        (*env)->ReleaseByteArrayElements(env, jaddr, addr, JNI_ABORT);
    } 

    char *temp_hoststr = strdup(hoststr);
    network_async(g_n, ^{
        dns_prefetch_store_result(g_n, rai, host, 0);
        evutil_freeaddrinfo(rai);
        free(temp_hoststr);
    });
}

void cancel_https_request(network *n, https_request_token token)
{
    debug("%s request:%p)\n", __func__, token);
    JNIEnv *env = get_env();
    jvm_frame(env, ^{
        jobject https_request = (*env)->NewLocalRef(env, token);
        if (!https_request) {
            return;
        }
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(return);
        CALL_VOID(cNewNode, newNode, cancelHttp, Lcom/newnode/internal/NewNode/CallblockThread;, https_request);
        CATCH(assert(false));
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_httpCallback(JNIEnv* env, jobject thiz, jlong callblock, jint https_error, jint http_status_code, jint flags, jbyteArray body)
{
    extern char *https_strerror(https_result *result);

    https_result result = {
        .flags = flags,
        .https_error = https_error,
        .http_status = http_status_code,
        .body_length = (*env)->GetArrayLength(env, body)
    };

    debug("g_https_cb callback length:%zu https_error:%d(%s) http_status_code:%d flags:0x%x\n", 
          result.body_length, https_error, https_strerror(&result),
          http_status_code, flags);

    if (result.body_length > 0 && http_status_code == 200) {
        result.body = malloc(result.body_length);
        (*env)->GetByteArrayRegion(env, body, 0, result.body_length, (jbyte*)result.body);
    }

    https_complete_callback cb = (https_complete_callback)callblock;
    network_async(g_n, ^{
        if (cb) {
            cb(http_status_code == 200, &result);
        }
        free(result.body);
        Block_release(cb);
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_newnodeInit(JNIEnv* env, jobject thiz, jobject newNodeObj)
{
    newNode = (*env)->NewGlobalRef(env, newNodeObj);

    network_set_log_level(1);

    char app_id[64] = {0};
    FILE *cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fread(app_id, sizeof(app_id), 1, cmdline);
        __android_log_print(ANDROID_LOG_DEBUG, "newnode", "application id %s\n", app_id);
        fclose(cmdline);
    }
    // XXX: TODO: use real app name
    const char *app_name = app_id;
    port_t newnode_port = 0;
    g_n = newnode_init(app_name, app_id, &newnode_port, ^(const https_request *request, const char* url, https_complete_callback cb) {
        network *n = g_n;
        debug("g_https_cb(%s)\n", url);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
        JNIEnv *env = get_env();
#pragma clang diagnostic pop
        __block jobject https_request = NULL;
        jvm_frame(env, ^{
            jbyteArray request_body = (*env)->NewByteArray(env, request->body_size);
            if (request->body && request->body_size > 0) {
                (*env)->SetByteArrayRegion(env, request_body, 0, request->body_size, (const jbyte *)request->body);
            }
            jobjectArray request_header_names = NULL;
            jobjectArray request_header_values = NULL;
            if (request->headers) {
                int nheaders;
                for (nheaders = 0; request->headers[nheaders]; ++nheaders);
                if (request->body_content_type) {
                    ++nheaders;
                }
                request_header_names = (*env)->NewObjectArray(env, nheaders, (*env)->FindClass(env, "java/lang/String"), 0);
                request_header_values = (*env)->NewObjectArray(env, nheaders, (*env)->FindClass(env, "java/lang/String"), 0);
                for (int i = 0; request->headers[i]; ++i) {
                    char *colon = strchr(request->headers[i], ':');
                    if (!colon) {
                        continue;
                    }
                    auto_free char *name = strndup(request->headers[i], colon - request->headers[i]);
                    char *value = colon + 1;
                    // debug("%s setting header[%d] %s=%s\n", __func__, i, name, value);
                    (*env)->SetObjectArrayElement(env, request_header_names, i, JSTR(name));
                    (*env)->SetObjectArrayElement(env, request_header_values, i, JSTR(value));
                }
                if (request->body_content_type) {
                    (*env)->SetObjectArrayElement(env, request_header_names, nheaders - 1, JSTR("Content-Type"));
                    (*env)->SetObjectArrayElement(env, request_header_values, nheaders - 1, JSTR(request->body_content_type));
                }
            } else {
                request_header_names = (*env)->NewObjectArray(env, 0, (*env)->FindClass(env, "java/lang/String"), 0);
                request_header_values = (*env)->NewObjectArray(env, 0, (*env)->FindClass(env, "java/lang/String"), 0);
            }

            // debug("(jni call) http(url:%s, cbc:%p, flags:0x%08x, timeout:%d, bufsize:%lu)\n",
            //       url, cbc, request->flags, request->timeout_sec, (unsigned long) request->bufsize);
            // debug("           flags=%s\n", expand_flags(request->flags));

            jclass cNewNode = (*env)->GetObjectClass(env, newNode);
            CATCH(return);
            // javap -s -classpath ./build/intermediates/javac/debug/classes com.clostra.newnode.internal.NewNode
            jmethodID mHttp = (*env)->GetMethodID(env, cNewNode, "http", "(Ljava/lang/String;JIIII[Ljava/lang/String;[Ljava/lang/String;[B)Lcom/clostra/newnode/internal/NewNode$CallblockThread;");
            if (mHttp) {
                https_complete_callback cbc = Block_copy(cb);
                jobject t = (*env)->CallObjectMethod(env, newNode, mHttp,
                    JSTR(url),
                    (jlong)cbc,               // callblock pointer (encoded as long)
                    (jint)request->flags,
                    (jint)(request->timeout_sec * 1000), // timeout_msec
                    (jint)request->bufsize, // bufsize
                    (jint)newnode_get_port(n),
                    request_header_names,
                    request_header_values,
                    request_body);
                CATCH(assert(false));
                https_request = (*env)->NewWeakGlobalRef(env, t);
            }
        });
        return (https_request_token)https_request;
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    const char* cCacheDir = (*env)->GetStringUTFChars(env, cacheDir, NULL);
    chdir(cCacheDir);
    (*env)->ReleaseStringUTFChars(env, cacheDir, cCacheDir);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_registerProxy(JNIEnv* env, jobject thiz)
{
    port_t newnode_port = newnode_get_port(g_n);
    if (!newnode_port) {
        return;
    }

    IMPORT(java/lang, System);
    CATCH(return);
    jmethodID mSetProp = (*env)->GetStaticMethodID(env, cSystem, "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    CATCH(return);

    char port[6];
    snprintf(port, sizeof(port), "%u", newnode_port);
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("socksProxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("socksProxyPort"), JSTR(port));

    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("proxyPort"), JSTR(port));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http.proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http.proxyPort"), JSTR(port));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https.proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https.proxyPort"), JSTR(port));

    char proxy[128];
    snprintf(proxy, sizeof(proxy), "http://127.0.0.1:%s", port);
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http_proxy"), JSTR(proxy));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https_proxy"), JSTR(proxy));
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_unregisterProxy(JNIEnv* env, jobject thiz)
{
    IMPORT(java/lang, System);
    CATCH(return);
    jmethodID mClearProp = (*env)->GetStaticMethodID(env, cSystem, "clearProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    CATCH(return);
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("socksProxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("socksProxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("proxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http.proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http.proxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https.proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https.proxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http_proxy"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https_proxy"));
}

bool vpn_protect(int socket)
{
    JNIEnv *env = get_env();
    push_frame();
    bool r = ^bool() {
        if (!newNode) {
            return false;
        }
        IMPORT(com/clostra/newnode/vpn, VpnService);
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
            return true;
        }
        jmethodID mVpnProtect = (*env)->GetStaticMethodID(env, cVpnService, "vpnProtect", "(I)Z");
        CATCH(return false);
        jboolean success = (*env)->CallStaticBooleanMethod(env, cVpnService, mVpnProtect, socket);
        CATCH(return false);
        return (bool)success;
    }();
    pop_frame();
    return r;
}

int __real_bind(int socket, const sockaddr *address, socklen_t length);
int __wrap_bind(int socket, const sockaddr *address, socklen_t length)
{
    //debug("bind %d %s\n", socket, sockaddr_str(address));
    if (!sockaddr_is_localhost(address, length) && !vpn_protect(socket)) {
        debug("bind failed to protect\n");
        errno = EADDRNOTAVAIL;
        return -1;
    }
    return __real_bind(socket, address, length);
}

int __real_connect(int socket, const sockaddr *address, socklen_t length);
int __wrap_connect(int socket, const sockaddr *address, socklen_t length)
{
    //debug("connect %d %s\n", socket, sockaddr_str(address));
    sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(socket, (sockaddr*)&ss, &slen) == -1 || slen == 0 || sockaddr_get_port((const sockaddr*)&ss) == 0) {
        if (!vpn_protect(socket)) {
            debug("connect failed to protect\n");
            errno = EADDRNOTAVAIL;
            return -1;
        }
    }
    return __real_connect(socket, address, length);
}

ssize_t __real_sendto(int socket, const void *buffer, size_t length, int flags, const sockaddr *dest_addr, socklen_t dest_len);
ssize_t __wrap_sendto(int socket, const void *buffer, size_t length, int flags, const sockaddr *dest_addr, socklen_t dest_len)
{
    //debug("sendto %d %s\n", socket, sockaddr_str(dest_addr));
    sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(socket, (sockaddr*)&ss, &slen) == -1 || slen == 0 || sockaddr_get_port((const sockaddr*)&ss) == 0) {
        if (!vpn_protect(socket)) {
            debug("sendto failed to protect\n");
            errno = EADDRNOTAVAIL;
            return -1;
        }
    }
    return __real_sendto(socket, buffer, length, flags, dest_addr, dest_len);
}

sockaddr_in6 jbyteArray_to_addr(JNIEnv* env, jbyteArray je)
{
    jbyte *buf = (*env)->GetByteArrayElements(env, je, NULL);
    jsize len = (*env)->GetArrayLength(env, je);
    endpoint e = {.port = 0};
    memcpy(&e, buf, MIN((size_t)len, sizeof(e)));
    (*env)->ReleaseByteArrayElements(env, je, buf, JNI_ABORT);
    return endpoint_to_addr(&e);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_addEndpoint(JNIEnv* env, jobject thiz, jbyteArray endpoint)
{
    const sockaddr_in6 sin6 = jbyteArray_to_addr(env, endpoint);
    network_async(g_n, ^{
        add_sockaddr(g_n, (const sockaddr *)&sin6, sizeof(sin6));
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_removeEndpoint(JNIEnv* env, jobject thiz, jbyteArray endpoint)
{
    const sockaddr_in6 sin6 = jbyteArray_to_addr(env, endpoint);
    network_async(g_n, ^{
        // XXX: TODO: remove endpoint
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_packetReceived(JNIEnv* env, jobject thiz, jbyteArray array, jbyteArray endpoint)
{
    jobject arrayref = (*env)->NewGlobalRef(env, array);
    const sockaddr_in6 sin6 = jbyteArray_to_addr(env, endpoint);
    network_async(g_n, ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
        JNIEnv *env = get_env();
#pragma clang diagnostic pop
        jbyte *buf = (*env)->GetByteArrayElements(env, arrayref, NULL);
        jsize len = (*env)->GetArrayLength(env, arrayref);
        udp_received(g_n, (const uint8_t*)buf, len, (const sockaddr *)&sin6, sizeof(sin6));
        (*env)->ReleaseByteArrayElements(env, arrayref, buf, JNI_ABORT);
        (*env)->DeleteGlobalRef(env, arrayref);

        // XXX: this should be called when the read buffer is drained
        utp_issue_deferred_acks(g_n->utp);
    });
}

ssize_t d2d_sendto(const uint8_t* buf, size_t len, const sockaddr_in6 *sin6)
{
    return -1;
    JNIEnv *env = get_env();
    push_frame();
    ssize_t r = ^ssize_t() {
        if (!IN6_IS_ADDR_UNIQUE_LOCAL(&sin6->sin6_addr)) {
            return -1;
        }
        if (!newNode) {
            return -1;
        }
        const endpoint e = addr_to_endpoint(sin6);
        jbyteArray jendpoint = (*env)->NewByteArray(env, sizeof(endpoint));
        CATCH(return -1);
        (*env)->SetByteArrayRegion(env, jendpoint, 0, sizeof(endpoint), (const jbyte *)&e);
        CATCH(return -1);
        jbyteArray array = (*env)->NewByteArray(env, len);
        CATCH(return -1);
        (*env)->SetByteArrayRegion(env, array, 0, len, (const jbyte *)buf);
        CATCH(return -1);
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(return -1);
        CALL_VOID(cNewNode, newNode, sendPacket, [B[B, array, jendpoint);
        CATCH(return -1);
        return len;
    }();
    pop_frame();
    return r;
}

void ui_display_stats(const char *type, uint64_t direct, uint64_t peers)
{
    JNIEnv *env = get_env();
    jvm_frame(env, ^{
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(return);
        CALL_VOID(cNewNode, newNode, displayStats, Ljava/lang/String;JJ, JSTR(type), direct, peers);
        CATCH(return);
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_setLogLevel(JNIEnv* env, jobject thiz, jint level)
{
    network_set_log_level(level);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_newnodeRun(JNIEnv* env, jobject thiz)
{
    newnode_run(g_n);
}

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    g_jvm = vm;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    start_stdio_thread();
    return JNI_VERSION_1_6;
}
