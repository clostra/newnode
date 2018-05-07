#ifndef BUGSNAG_SERIALIZE_H
#define BUGSNAG_SERIALIZE_H

#include "report.h"

/**
 * Serialize a report into a JSON representation string. If callback is not
 * NULL,  it is invoked with the completed Parson JSON value before the
 * string representation is returned.
 */
char *bugsnag_serialize_report(bugsnag_report *report,
                               void (*callback)(JSON_Value *));

extern char * bugsnag_serialize_event(bsg_event *event);

#endif
