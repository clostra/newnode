// most of the FEATURE_xxx macros should go away
// (either the feature will always be implemented or removed)

#define FEATURE_RANDOM_SKIP_TRYFIRST 1

// the following features should only be enabled when testing
// and should be disabled when shipped or committed to a public repo

#define TEST_WIRED_INJECTOR 0
#define TEST_INJECTOR "52.88.7.21"
#define TEST_INJECTOR_PORT 9000

#define TEST_WIRED_PORT 0
#define TEST_PORT 8006         // only used when TEST_WIRED_PORT != 0

#define TEST_LISTEN_ANY 0      // proxy listens on 0.0.0.0 rather than 127.0.0.1

#define TEST_STALL_DETECTOR 0
