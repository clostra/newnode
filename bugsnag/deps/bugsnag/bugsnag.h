#ifndef BUGSNAG_H
#define BUGSNAG_H

// Function used within the library to log messages
#ifndef BUGSNAG_LOG
#define BUGSNAG_LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

#include "report.h"
#include "serialize.h"

#endif
