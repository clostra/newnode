#include "report.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NOTIFIER_NAME "Bugsnag C"
#define NOTIFIER_VERSION "0.0.1"
#define NOTIFIER_URL "https://github.com/bugsnag/bugsnag-c"

bsg_library *create_notifier() {
  bsg_library *lib = malloc(sizeof(bsg_library));
  lib->name = NOTIFIER_NAME;
  lib->version = NOTIFIER_VERSION;
  lib->url = NOTIFIER_URL;

  return lib;
}

bugsnag_report *bugsnag_report_init(char *api_key) {
  bugsnag_report *report = malloc(sizeof(bugsnag_report));

  report->event_count = 0;
  report->api_key = api_key;
  report->notifier = create_notifier();

  return report;
}

void bugsnag_report_free(bugsnag_report *report) {
  for (int i = 0; i < report->event_count; i++) {
    bugsnag_event_free(report->events[i]);
    report->events[i] = NULL;
  }
  free(report);
}

bsg_event *bugsnag_event_init() {
  bsg_event *event = malloc(sizeof(bsg_event));
  event->crumb_count = 0;
  event->exception_count = 0;
  event->thread_count = 0;

  event->severity = BSG_SEVERITY_WARN;
  event->payload_version = "3";
  event->context = NULL;
  event->grouping_hash = NULL;

  event->custom_diagnostics = json_value_init_object();
  event->diagnostics = json_value_init_object();

  return event;
}

bsg_thread *bugsnag_thread_init(char *id, char *name) {
  bsg_thread *thread = malloc(sizeof(bsg_thread));
  thread->id = id;
  thread->name = name;
  thread->frame_count = 0;

  return thread;
}

void bugsnag_event_free(bsg_event *event) { free(event); }

bsg_exception *bugsnag_exception_init(char *name, char *message) {
  bsg_exception *exc = malloc(sizeof(bsg_exception));
  exc->frame_count = 0;
  sprintf(exc->message, "%s", message);
  sprintf(exc->name, "%s", name);
  exc->type = BUGSNAG_DEFAULT_EX_TYPE;

  return exc;
}

bsg_breadcrumb *bugsnag_breadcrumb_init(char *name, bsg_breadcrumb_t type) {
  bsg_breadcrumb *crumb = malloc(sizeof(bsg_breadcrumb));
  crumb->name = name;
  crumb->type = type;
  crumb->metadata = json_value_init_object();
  time(&crumb->timestamp);

  return crumb;
}

void bugsnag_report_add_event(bugsnag_report *report, bsg_event *event) {
  report->events[report->event_count++] = event;
}

void bugsnag_event_add_exception(bsg_event *event, bsg_exception *exc) {
  event->exceptions[event->exception_count++] = exc;
}

void bugsnag_event_add_thread(bsg_event *event, bsg_thread *thread) {
  event->threads[event->thread_count++] = thread;
}

void bugsnag_event_add_breadcrumb(bsg_event *event, bsg_breadcrumb *crumb) {
  long length = sizeof(event->breadcrumbs)/sizeof(bsg_breadcrumb *);
  if (event->crumb_count == length) {
    bsg_breadcrumb *old_crumb = event->breadcrumbs[0];
    json_value_free(old_crumb->metadata);
    free(old_crumb);
    for (int i = 0; i < length - 1; i++) {
      bsg_breadcrumb *crumb1 = event->breadcrumbs[i];
      bsg_breadcrumb *crumb2 = event->breadcrumbs[i + 1];
      event->breadcrumbs[i] = event->breadcrumbs[i + 1];
    }
    event->breadcrumbs[length - 1] = crumb;
  } else {
    event->breadcrumbs[event->crumb_count++] = crumb;
  }
}

void bugsnag_event_clear_breadcrumbs(bsg_event *event) {
  for (int i = 0; i < event->crumb_count; i++) {
    bsg_breadcrumb *crumb = event->breadcrumbs[i];
    json_value_free(crumb->metadata);
    free(crumb);
  }

  event->crumb_count = 0;
}

void bugsnag_thread_add_frame(bsg_thread *thread, bsg_stackframe frame) {
  thread->stacktrace[thread->frame_count++] = frame;
}

void bugsnag_exception_add_frame(bsg_exception *exc, bsg_stackframe frame) {
  exc->stacktrace[exc->frame_count++] = frame;
}

void bugsnag_breadcrumb_add_metadata(bsg_breadcrumb *crumb, char *key,
                                     char *value) {
  JSON_Object *obj = json_value_get_object(crumb->metadata);
  json_object_set_string(obj, key, value);
}

char *_event_section_name(bsg_event_section section) {
  switch (section) {
  case BSG_USER:
    return "user";
  case BSG_REQUEST:
    return "request";
  case BSG_APP:
    return "app";
  case BSG_DEVICE:
    return "device";
  }
}

JSON_Object *_event_section(JSON_Value *diagnostics, char *section) {
  JSON_Object *obj = json_value_get_object(diagnostics);
  JSON_Value *section_value = json_object_get_value(obj, section);
  if (!section_value) {
    section_value = json_value_init_object();
    json_object_set_value(obj, section, section_value);
  }
  return json_value_get_object(section_value);
}

void bugsnag_event_set_string(bsg_event *event, bsg_event_section section,
                              char *key, char *value) {
  JSON_Object *section_obj =
      _event_section(event->diagnostics, _event_section_name(section));
  json_object_set_string(section_obj, key, value);
}

const char* bugsnag_event_get_string(bsg_event *event, bsg_event_section section, char *key) {
  JSON_Object *section_obj =
          _event_section(event->diagnostics, _event_section_name(section));
  return json_object_get_string(section_obj, key);
}

void bugsnag_event_set_bool(bsg_event *event, bsg_event_section section,
                            char *key, int value) {
  JSON_Object *section_obj =
      _event_section(event->diagnostics, _event_section_name(section));
  json_object_set_boolean(section_obj, key, value);
}

void bugsnag_event_set_number(bsg_event *event, bsg_event_section section,
                              char *key, double value) {
  JSON_Object *section_obj =
      _event_section(event->diagnostics, _event_section_name(section));
  json_object_set_number(section_obj, key, value);
}

void bugsnag_event_delete(bsg_event *event, bsg_event_section section,
                          char *key) {
  JSON_Object *section_obj =
      _event_section(event->diagnostics, _event_section_name(section));
  json_object_remove(section_obj, key);
}

void bugsnag_event_set_metadata_string(bsg_event *event, char *section,
                                       char *key, char *value) {
  JSON_Object *section_obj = _event_section(event->custom_diagnostics, section);
  json_object_set_string(section_obj, key, value);
}

void bugsnag_event_set_metadata_number(bsg_event *event, char *section,
                                       char *key, double value) {
  JSON_Object *section_obj = _event_section(event->custom_diagnostics, section);
  json_object_set_number(section_obj, key, value);
}

void bugsnag_event_set_metadata_bool(bsg_event *event, char *section, char *key,
                                     int value) {
  JSON_Object *section_obj = _event_section(event->custom_diagnostics, section);
  json_object_set_boolean(section_obj, key, value);
}

void bugsnag_event_delete_metadata(bsg_event *event, char *section, char *key) {
  JSON_Object *section_obj = _event_section(event->custom_diagnostics, section);
  json_object_remove(section_obj, key);
}

void bugsnag_event_delete_metadata_section(bsg_event *event, char *section) {
  JSON_Object *obj = json_value_get_object(event->custom_diagnostics);
  json_object_remove(obj, section);
}

JSON_Object* bugsnag_event_get_metadata_base(bsg_event *event) {
  return json_value_get_object(event->custom_diagnostics);
}

JSON_Object* bugsnag_event_get_section_base(bsg_event *event, bsg_event_section section) {
  return _event_section(event->diagnostics, _event_section_name(section));
}

void bugsnag_event_clear_metadata_base(bsg_event *event) {
  json_object_clear(json_value_get_object(event->custom_diagnostics));
}

JSON_Object* bugsnag_object_add_object(JSON_Object* object, const char *name) {
  JSON_Value *section_value = json_value_init_object();
  json_object_set_value(object, name, section_value);
  return json_value_get_object(section_value);
}

JSON_Array* bugsnag_object_add_array(JSON_Object* object, const char *name) {
  JSON_Value *section_value = json_value_init_array();
  json_object_set_value(object, name, section_value);
  return json_value_get_array(section_value);
}

void bugsnag_object_set_string(JSON_Object* object, const char *key, const char *value) {
  json_object_set_string(object, key, value);
}

void bugsnag_object_set_number(JSON_Object* object, const char *key, double value) {
  json_object_set_number(object, key, value);
}

void bugsnag_object_set_bool(JSON_Object* object, const char *key, int value) {
  json_object_set_boolean(object, key, value);
}

JSON_Object* bugsnag_array_add_object(JSON_Array* array) {
  JSON_Value *section_value = json_value_init_object();
  json_array_append_value(array, section_value);
  return json_value_get_object(section_value);
}

JSON_Array* bugsnag_array_add_array(JSON_Array* array) {
  JSON_Value * section_value = json_value_init_array();
  json_array_append_value(array, section_value);
  return json_value_get_array(section_value);
}

void bugsnag_array_set_string(JSON_Array* array, const char *value) {
  json_array_append_string(array, value);
}

void bugsnag_array_set_number(JSON_Array* array, double value) {
  json_array_append_number(array, value);
}

void bugsnag_array_set_bool(JSON_Array* array, int value) {
  json_array_append_boolean(array, value);
}


