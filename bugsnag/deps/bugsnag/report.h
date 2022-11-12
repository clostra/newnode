#ifndef BUGSNAG_REPORT_H
#define BUGSNAG_REPORT_H

#include "../deps/parson/parson.h"
#include <time.h>

// Number of frames in a stacktrace
#ifndef BUGSNAG_FRAMES_MAX
#define BUGSNAG_FRAMES_MAX 32
#endif

// Default type assigned to exceptions
#ifndef BUGSNAG_DEFAULT_EX_TYPE
#define BUGSNAG_DEFAULT_EX_TYPE "c"
#endif

typedef enum {
  /** An unhandled exception */
  BSG_SEVERITY_ERR,
  /** A handled exception */
  BSG_SEVERITY_WARN,
  /** Custom, notable error messages */
  BSG_SEVERITY_INFO,
} bsg_severity_t;

typedef enum {
  BSG_CRUMB_MANUAL,
  BSG_CRUMB_ERROR,
  BSG_CRUMB_LOG,
  BSG_CRUMB_NAVIGATION,
  BSG_CRUMB_PROCESS,
  BSG_CRUMB_REQUEST,
  BSG_CRUMB_STATE,
  BSG_CRUMB_USER,
} bsg_breadcrumb_t;

/**
 * A frame of a stacktrace
 */
typedef struct {
  const char *method;
  const char *file;
  int line_number;
  int in_project;

  uintptr_t load_address; // address where the file was loaded in memory
  uintptr_t symbol_address; // address where the method was loaded in memory
  uintptr_t frame_address; // address of the current frame in memory
} bsg_stackframe;

/* a Bugsnag exception */
typedef struct {
  char name[256];
  char message[256];
  char *type;

  int frame_count;
  bsg_stackframe stacktrace[BUGSNAG_FRAMES_MAX];
} bsg_exception;

typedef struct {
  char *name;
  char *id;

  int frame_count;
  bsg_stackframe stacktrace[BUGSNAG_FRAMES_MAX];
} bsg_thread;

typedef struct bsg_breadcrumb {
  const char *name;
  time_t timestamp;
  bsg_breadcrumb_t type;
  /**
   * Key/value pairs of related information for debugging
   */
  JSON_Value *metadata;
} bsg_breadcrumb;

typedef struct {
  const char *payload_version;
  const char *grouping_hash;
  const char *context;
  bsg_severity_t severity;

  int exception_count;
  bsg_exception *exceptions[16];

  int thread_count;
  bsg_thread *threads[16];

  int crumb_count;
  bsg_breadcrumb *breadcrumbs[16];

  JSON_Value *diagnostics;
  JSON_Value *custom_diagnostics;
} bsg_event;

typedef struct {
  const char *name;
  const char *version;
  const char *url;
} bsg_library;

typedef struct {
  const char *api_key;
  bsg_library *notifier;

  int event_count;
  bsg_event *events[16];
} bugsnag_report;

/**
 * Create a new Bugsnag error report
 */
bugsnag_report *bugsnag_report_init(char *api_key);
void bugsnag_report_free(bugsnag_report *report);

/**
 * Create a new Bugsnag event. Each report can have many events.
 */
bsg_event *bugsnag_event_init();
void bugsnag_event_free(bsg_event *event);

/**
 * Create a new Bugsnag exception. Each event can have many exceptions, where
 * the first exception is the caught exception and the rest are successive
 * causes.
 */
bsg_exception *bugsnag_exception_init(char *name, char *message);

/**
 * Create a new bugsnag thread. Each event can have many threads.
 */
bsg_thread *bugsnag_thread_init(char *id, char *name);

/**
 * Create a new Bugsnag breadcrumb. Each breadcrumb has a name and type, and
 * optionally attached metadata pairs
 */
bsg_breadcrumb *bugsnag_breadcrumb_init(char *name, bsg_breadcrumb_t type);

/**
 * Add an event to a report
 */
void bugsnag_report_add_event(bugsnag_report *report, bsg_event *event);

/**
 * Add an exception to an event
 */
void bugsnag_event_add_exception(bsg_event *event, bsg_exception *exc);

/**
 * Add a breadcrumb to an event
 */
void bugsnag_event_add_breadcrumb(bsg_event *event, bsg_breadcrumb *crumb);

/**
 * Removes all the breadcrumbs from the event
 */
void bugsnag_event_clear_breadcrumbs(bsg_event *event);

/**
 * Add a thread to an event
 */
void bugsnag_event_add_thread(bsg_event *event, bsg_thread *thread);

/**
 * Add a stack frame to an exception
 */
void bugsnag_exception_add_frame(bsg_exception *exc, bsg_stackframe frame);

/**
 * Add a stack frame to a thread
 */
void bugsnag_thread_add_frame(bsg_thread *thread, bsg_stackframe frame);

/**
 * Add a key/value pair of metadata to the breadcrumb
 */
void bugsnag_breadcrumb_add_metadata(bsg_breadcrumb *crumb, char *key,
                                     char *value);

typedef enum { BSG_DEVICE, BSG_APP, BSG_REQUEST, BSG_USER } bsg_event_section;

/**
 * Append a string value to the specified diagnostics section of the event.
 */
void bugsnag_event_set_string(bsg_event *event, bsg_event_section section,
                              char *key, char *value);
/**
 * Gets a string that has been stored in the specified diagnostics section of the event.
 */
const char* bugsnag_event_get_string(bsg_event *event, bsg_event_section section, char *key);

/**
 * Append an int value to the specified diagnostics section of the event.
 */
void bugsnag_event_set_bool(bsg_event *event, bsg_event_section section,
                            char *key, int value);
/**
 * Append a bool value to the specified diagnostics section of the event.
 */
void bugsnag_event_set_number(bsg_event *event, bsg_event_section section,
                              char *key, double value);
/**
 * Delete a value from the specified diagnostics section of the event.
 */
void bugsnag_event_delete(bsg_event *event, bsg_event_section section,
                          char *key);

/**
 * Append custom diagnostic data to a report in a specified section
 */
void bugsnag_event_set_metadata_string(bsg_event *event, char *section,
                                       char *key, char *value);

/**
 * Append custom diagnostic data to a report in a specified section
 */
void bugsnag_event_set_metadata_number(bsg_event *event, char *section,
                                       char *key, double value);

/**
 * Append custom diagnostic data to a report in a specified section
 */
void bugsnag_event_set_metadata_bool(bsg_event *event, char *section, char *key, int value);

/**
 * Delete a value from the custom diagnostics section of the report.
 */
void bugsnag_event_delete_metadata(bsg_event *event, char *section, char *key);

/**
 * Delete custom diagnostic data from a report for a specified section
 */
void bugsnag_event_delete_metadata_section(bsg_event *event, char *section);

/**
 * Gets the base object for meta data from an event
 */
JSON_Object* bugsnag_event_get_metadata_base(bsg_event *event);

/**
 * Gets the base object for a meta data section
 */
JSON_Object* bugsnag_event_get_section_base(bsg_event *event, bsg_event_section section);

/**
 * Clears all meta data from an event
 */
void bugsnag_event_clear_metadata_base(bsg_event *event);

/**
 * Adds a new JSON object to the given JSON object
 */
JSON_Object* bugsnag_object_add_object(JSON_Object* object, const char *name);

/**
 * Adds a new JSON array to the given JSON object
 */
JSON_Array* bugsnag_object_add_array(JSON_Object* object, const char *name);

/**
 * Adds a new string to the given JSON object
 */
void bugsnag_object_set_string(JSON_Object* object, const char *key, const char *value);

/**
 * Adds a new number to the given JSON object
 */
void bugsnag_object_set_number(JSON_Object* object, const char *key, double value);

/**
 * Adds a new boolean to the given JSON object
 */
void bugsnag_object_set_bool(JSON_Object* object, const char *key, int value);

/**
 * Adds a new JSON object to the given JSON array
 */
JSON_Object* bugsnag_array_add_object(JSON_Array* array);

/**
 * Adds a new JSON array to the given JSON array
 */
JSON_Array* bugsnag_array_add_array(JSON_Array* array);

/**
 * Adds a new string to the given JSON array
 */
void bugsnag_array_set_string(JSON_Array* array, const char *value);

/**
 * Adds a new number to the given JSON array
 */
void bugsnag_array_set_number(JSON_Array* array, double value);

/**
 * Adds a new boolean to the given JSON array
 */
void bugsnag_array_set_bool(JSON_Array* array, int value);
#endif
