#include "../deps/parson/parson.h"
#include "serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *serialize_crumb_t(bsg_breadcrumb_t crumb_type) {
  switch (crumb_type) {
  case BSG_CRUMB_NAVIGATION:
    return "navigation";
  case BSG_CRUMB_ERROR:
    return "error";
  case BSG_CRUMB_LOG:
    return "log";
  case BSG_CRUMB_REQUEST:
    return "request";
  case BSG_CRUMB_PROCESS:
    return "process";
  case BSG_CRUMB_STATE:
    return "state";
  case BSG_CRUMB_USER:
    return "user";
  case BSG_CRUMB_MANUAL:
  default:
    return "manual";
  }
}

char *serialize_severity(bsg_severity_t severity) {
  switch (severity) {
  case BSG_SEVERITY_ERR:
    return "error";
  case BSG_SEVERITY_INFO:
    return "info";
  case BSG_SEVERITY_WARN:
  default:
    return "warning";
  }
}

/**
 * Removes any path from the filename to make it consistent across API versions
 */
static char* stripPathFromFile(const char* file) {

  char* pos = (char *) file;
  char* newpos = strchr(pos, '/');

  while (newpos) {
    pos = newpos + 1;
    newpos = strchr(pos, '/');
  }

  return pos;
}

JSON_Value *serialize_breadcrumbs(bsg_event *event) {
  JSON_Value *crumbs_value = json_value_init_array();
  JSON_Array *crumbs = json_value_get_array(crumbs_value);
  for (int i = 0; i < event->crumb_count; i++) {
    bsg_breadcrumb *crumb = event->breadcrumbs[i];
    if (!crumb->name)
      continue;

    JSON_Value *crumb_value = json_value_init_object();
    JSON_Object *crumb_obj = json_value_get_object(crumb_value);
    json_object_set_string(crumb_obj, "type", serialize_crumb_t(crumb->type));
    json_object_set_string(crumb_obj, "name", crumb->name);

    if (crumb->metadata)
      json_object_set_value(crumb_obj, "metaData", crumb->metadata);

    char timestamp[sizeof "2016-11-08T09:11:09Z"];
    strftime(timestamp, sizeof "2016-11-08T09:11:09Z", "%Y-%m-%dT%H:%M:%SZ",
             gmtime(&crumb->timestamp));
    json_object_set_string(crumb_obj, "timestamp", timestamp);
    json_array_append_value(crumbs, crumb_value);
  }

  return crumbs_value;
}

JSON_Value *serialize_stackframe(bsg_stackframe frame) {
  JSON_Value *value = json_value_init_object();
  JSON_Object *frame_obj = json_value_get_object(value);
  json_object_set_boolean(frame_obj, "inProject", frame.in_project);

  if (frame.file)
    json_object_set_string(frame_obj, "file", stripPathFromFile(frame.file));
  if (frame.method) {
    json_object_set_string(frame_obj, "method", frame.method);
  } else {
    json_object_set_string(frame_obj, "method", "(null)");
  }
  if (frame.frame_address)
    json_object_set_number(frame_obj, "frameAddress", frame.frame_address);
  if (frame.load_address)
    json_object_set_number(frame_obj, "loadAddress", frame.load_address);
  if (frame.symbol_address)
    json_object_set_number(frame_obj, "symbolAddress", frame.symbol_address);
  if (frame.line_number > 0)
    json_object_set_number(frame_obj, "lineNumber", frame.line_number);

  return value;
}

JSON_Value *serialize_exceptions(bsg_event *event) {
  JSON_Value *value = json_value_init_array();
  JSON_Array *exceptions = json_value_get_array(value);

  for (int i = 0; i < event->exception_count; i++) {
    bsg_exception *exception = event->exceptions[i];
    JSON_Value *exc_value = json_value_init_object();
    JSON_Value *stack_value = json_value_init_array();
    JSON_Object *exc_obj = json_value_get_object(exc_value);
    JSON_Array *stack_obj = json_value_get_array(stack_value);
    json_object_set_value(exc_obj, "stacktrace", stack_value);

    if (strlen(exception->name))
      json_object_set_string(exc_obj, "errorClass", exception->name);
    if (strlen(exception->message))
      json_object_set_string(exc_obj, "message", exception->message);
    if (exception->type && strlen(exception->type))
      json_object_set_string(exc_obj, "type", exception->type);

    for (int j = 0; j < exception->frame_count; j++) {
      bsg_stackframe frame = exception->stacktrace[j];
      json_array_append_value(stack_obj, serialize_stackframe(frame));
    }

    json_array_append_value(exceptions, exc_value);
  }
  return value;
}

JSON_Value *serialize_threads(bsg_event *event) {
  JSON_Value *value = json_value_init_array();
  JSON_Array *threads = json_value_get_array(value);

  for (int i = 0; i < event->thread_count; i++) {
    bsg_thread *thread = event->threads[i];
    JSON_Value *thread_value = json_value_init_object();
    JSON_Value *stack_value = json_value_init_array();
    JSON_Object *thread_obj = json_value_get_object(thread_value);
    JSON_Array *stack_obj = json_value_get_array(stack_value);
    json_object_set_value(thread_obj, "stacktrace", stack_value);

    if (thread->name)
      json_object_set_string(thread_obj, "name", thread->name);
    if (thread->id)
      json_object_set_string(thread_obj, "id", thread->id);

    for (int j = 0; j < thread->frame_count; j++) {
      bsg_stackframe frame = thread->stacktrace[j];
      json_array_append_value(stack_obj, serialize_stackframe(frame));
    }

    json_array_append_value(threads, thread_value);
  }

  return value;
}

JSON_Value *serialize_event(bsg_event *event) {
  JSON_Value *value = json_value_init_object();
  JSON_Object *event_obj = json_value_get_object(value);
  if (event->payload_version)
    json_object_set_string(event_obj, "payloadVersion", event->payload_version);
  if (event->context)
    json_object_set_string(event_obj, "context", event->context);
  if (event->grouping_hash)
    json_object_set_string(event_obj, "groupingHash", event->grouping_hash);
  json_object_set_string(event_obj, "severity",
                         serialize_severity(event->severity));
  if (event->custom_diagnostics)
    json_object_set_value(event_obj, "metaData", event->custom_diagnostics);
  if (event->diagnostics) {
    JSON_Object *diagnostics = json_value_get_object(event->diagnostics);
    for (int i = 0; i < (int)json_object_get_count(diagnostics); i++) {
      const char *key = json_object_get_name(diagnostics, i);
      JSON_Value *v = json_object_get_value(diagnostics, key);
      if (v)
        json_object_set_value(event_obj, key, v);
    }
  }

  json_object_set_value(event_obj, "exceptions", serialize_exceptions(event));
  json_object_set_value(event_obj, "threads", serialize_threads(event));
  json_object_set_value(event_obj, "breadcrumbs", serialize_breadcrumbs(event));

  return value;
}

JSON_Value *serialize_notifier(bsg_library *lib) {
  JSON_Value *value = json_value_init_object();
  JSON_Object *notifier = json_value_get_object(value);
  json_object_set_string(notifier, "name", lib->name);
  json_object_set_string(notifier, "url", lib->url);
  json_object_set_string(notifier, "version", lib->version);

  return value;
}

char * bugsnag_serialize_event(bsg_event *event) {
  JSON_Value *event_value = serialize_event(event);
  char *serialized_string = json_serialize_to_string(event_value);
  json_value_free(event_value);

  return serialized_string;
}

char *bugsnag_serialize_report(bugsnag_report *report,
                               void (*callback)(JSON_Value *)) {
  JSON_Value *root_value = json_value_init_object();
  JSON_Object *root_object = json_value_get_object(root_value);
  JSON_Value *notifier = serialize_notifier(report->notifier);
  JSON_Value *events_value = json_value_init_array();
  JSON_Array *events = json_value_get_array(events_value);

  json_object_set_string(root_object, "apiKey", report->api_key);
  json_object_set_value(root_object, "notifier", notifier);
  json_object_set_value(root_object, "events", events_value);

  for (int i = 0; i < report->event_count; i++) {
    bsg_event *event = report->events[i];
    json_array_append_value(events, serialize_event(event));
  }

  if (callback)
    callback(root_value);

  char *serialized_string = json_serialize_to_string(root_value);
  json_value_free(root_value);

  return serialized_string;
}
