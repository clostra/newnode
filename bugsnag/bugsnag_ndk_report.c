#include <jni.h>
#include <string.h>
#include <ctype.h>

#include "../constants.h"

#include "bugsnag_ndk_report.h"
#include "bugsnag_ndk.h"


void bsg_add_meta_data_item(JNIEnv *env, JSON_Object* object, const char* key, jobject value, struct bugsnag_ndk_string_array *filters);
void bsg_add_meta_data_array_item(JNIEnv *env, JSON_Array* array, jobject value, struct bugsnag_ndk_string_array *filters);

/**
 * Gets the value from a method that returns a string
 */
char *get_method_string(JNIEnv *env, jclass class, const char *method_name) {
    jmethodID method = (*env)->GetStaticMethodID(env, class, method_name, "()Ljava/lang/String;");
    jstring value = (*env)->CallStaticObjectMethod(env, class, method);

    char * str;

    if (value) {
        str = (char*)(*env)->GetStringUTFChars(env, value, JNI_FALSE);
    } else {
        str = "";
    }

    (*env)->DeleteLocalRef(env, value);

    return str;
}

/**
 * Gets the value from a method that contains an int
 */
int get_method_int(JNIEnv *env, jclass class, const char *method_name) {
    jmethodID method = (*env)->GetStaticMethodID(env, class, method_name, "()I");
    jint value = (*env)->CallStaticIntMethod(env, class, method);

    if (value)
        return (int)value;

    return -1;
}

/**
 * Gets the value from a method that contains a java.lang.float
 */
float get_method_float(JNIEnv *env, jclass class, const char *method_name) {
    jmethodID method = (*env)->GetStaticMethodID(env, class, method_name, "()F");
    return (float)(*env)->CallStaticFloatMethod(env, class, method);
}

/**
 * Gets the value from a method that contains a java.lang.long
 */
double get_method_double(JNIEnv *env, jclass class, const char *method_name) {
    jmethodID method = (*env)->GetStaticMethodID(env, class, method_name, "()D");
    return (double)(*env)->CallStaticDoubleMethod(env, class, method);
}

/**
 * Gets the value from a method that contains a java.lang.boolean
 */
int get_method_boolean(JNIEnv *env, jclass class, const char *method_name) {
    jmethodID method = (*env)->GetStaticMethodID(env, class, method_name, "()Ljava/lang/Boolean;");
    jobject value_boolean = (*env)->CallStaticObjectMethod(env, class, method);

    jclass boolean_class = (*env)->FindClass(env, "java/lang/Boolean");
    jmethodID bool_value_method = (*env)->GetMethodID(env, boolean_class, "booleanValue", "()Z");
    jboolean value = (*env)->CallBooleanMethod(env, value_boolean, bool_value_method);

    (*env)->DeleteLocalRef(env, value_boolean);
    (*env)->DeleteLocalRef(env, boolean_class);

    if (value) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Gets the string value of a char from java
 */
const char *get_string_from_char(JNIEnv *env, jchar value) {
    jclass char_class = (*env)->FindClass(env, "java/lang/Character");
    jmethodID to_string_method = (*env)->GetStaticMethodID(env, char_class, "toString", "(C)Ljava/lang/String;");
    jstring string_value = (*env)->CallStaticObjectMethod(env, char_class, to_string_method, value);

    const char * string = (*env)->GetStringUTFChars(env, string_value, JNI_FALSE);

    (*env)->DeleteLocalRef(env, char_class);
    (*env)->DeleteLocalRef(env, string_value);

    return string;
}

/**
 * Gets the class name for the given object
 */
const char* get_class_name(JNIEnv *env, jobject object) {

    jclass class = (*env)->GetObjectClass(env, object);

    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
    jmethodID get_name_method = (*env)->GetMethodID(env, class_class, "getName", "()Ljava/lang/String;");
    jstring class_name = (*env)->CallObjectMethod(env, class, get_name_method);

    const char* name = (*env)->GetStringUTFChars(env, class_name, JNI_FALSE);

    (*env)->DeleteLocalRef(env, class);
    (*env)->DeleteLocalRef(env, class_class);
    (*env)->DeleteLocalRef(env, class_name);

    return name;
}

/**
 * Checks if the given object is an instance of a type of the given name
 */
int is_instance_of(JNIEnv *env, jobject object, const char* type_name) {
    jclass class = (*env)->FindClass(env, type_name);
    jboolean instance_of = (*env)->IsInstanceOf(env, object, class);

    (*env)->DeleteLocalRef(env, class);

    return instance_of;
}

/**
 * Checks if the given object is an array
 */
int is_array(JNIEnv *env, jobject object) {
    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
    jmethodID is_array_method = (*env)->GetMethodID(env, class_class, "isArray", "()Z");
    jclass obj_class = (*env)->GetObjectClass(env, object);
    jboolean is_array = (*env)->CallBooleanMethod(env, obj_class, is_array_method);

    (*env)->DeleteLocalRef(env, class_class);
    (*env)->DeleteLocalRef(env, obj_class);

    return is_array;
}

/**
 * Gets the size of the given map object
 */
int bsg_get_map_size(JNIEnv *env, jobject value) {
    jclass map_class = (*env)->FindClass(env, "java/util/Map");
    jmethodID size_method = (*env)->GetMethodID(env, map_class, "size", "()I");
    jint size = (*env)->CallIntMethod(env, value, size_method);

    (*env)->DeleteLocalRef(env, map_class);

    return size;
}

/**
 * Gets the array of keys from the given map object
 */
jarray bsg_get_map_key_array(JNIEnv *env, jobject value) {
    jclass map_class = (*env)->FindClass(env, "java/util/Map");
    jmethodID key_set_method = (*env)->GetMethodID(env, map_class, "keySet", "()Ljava/util/Set;");
    jobject key_set_value = (*env)->CallObjectMethod(env, value, key_set_method);

    jclass set_class = (*env)->FindClass(env, "java/util/Set");
    jmethodID to_array_method = (*env)->GetMethodID(env, set_class, "toArray", "()[Ljava/lang/Object;");
    jarray array = (*env)->CallObjectMethod(env, key_set_value, to_array_method);

    (*env)->DeleteLocalRef(env, map_class);
    (*env)->DeleteLocalRef(env, set_class);
    (*env)->DeleteLocalRef(env, key_set_value);

    return array;
}

/**
 * Gets an item from a map using the given key
 */
jobject bsg_get_item_from_map(JNIEnv *env, jobject map, jobject key) {
    jclass map_class = (*env)->FindClass(env, "java/util/Map");
    jmethodID get_method = (*env)->GetMethodID(env, map_class, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");

    (*env)->DeleteLocalRef(env, map_class);

    return (*env)->CallObjectMethod(env, map, get_method, key);
}

/**
 * Checks to see if a given string is in the list of filters
 */
int is_in_filters(const char* key, struct bugsnag_ndk_string_array *filters) {

    if (filters) {
        for (int i = 0; i < filters->size; i++) {
            if (strcmp(filters->values[i], key) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

/**
 * Adds the contents of given map value to the given JSON object
 */
void bsg_add_meta_data_map(JNIEnv *env, JSON_Object* object, jobject value, struct bugsnag_ndk_string_array *filters) {

    // loop over all the items in the map and add them
    int size = bsg_get_map_size(env, value);

    if (size > 0) {

        jarray key_array_value = bsg_get_map_key_array(env, value);

        int i;
        for (i = 0; i < size; i++) {
            jobject element_key = (*env)->GetObjectArrayElement(env, key_array_value, i);
            jobject element_value = bsg_get_item_from_map(env, value, element_key);
            const char* element_key_str;

            if (is_instance_of(env, element_key, "java/lang/String")) {
                element_key_str = (*env)->GetStringUTFChars(env, (jstring)element_key, JNI_FALSE);
            } else {
                // The key is not a string, call toString on the object to get a value to use
                jclass object_class = (*env)->FindClass(env, "java/lang/Object");
                jmethodID to_string_method = (*env)->GetMethodID(env, object_class, "toString", "()Ljava/lang/String;");
                jstring object_string = (*env)->CallObjectMethod(env, element_key, to_string_method);

                element_key_str = (*env)->GetStringUTFChars(env, object_string, JNI_FALSE);

                (*env)->DeleteLocalRef(env, object_class);
                (*env)->DeleteLocalRef(env, object_string);
            }

            // If this key is filtered then just display "[FILTERED]"
            if (is_in_filters(element_key_str, filters)) {
                bugsnag_object_set_string(object, element_key_str, "[FILTERED]");
            } else {
                bsg_add_meta_data_item(env, object, element_key_str, element_value, filters);
            }

            (*env)->DeleteLocalRef(env, element_key);
            (*env)->DeleteLocalRef(env, element_value);
        }
    }
}

/**
 * Adds the contents of given array the given JSON array
 */
void bsg_add_meta_data_array(JNIEnv *env, JSON_Array* array, jarray value, struct bugsnag_ndk_string_array *filters) {

    // loop over all the items in the map and add them
    int size = (*env)->GetArrayLength(env, value);

    if (size > 0) {

        const char * array_type_name = get_class_name(env, value);
        int i;

        if (strcmp(array_type_name, "[I") == 0) {
            jint* elements = (*env)->GetIntArrayElements(env, value, 0);

            for (i = 0; i < size; i++) {
                bugsnag_array_set_number(array, elements[i]);
            }
        } else if (strcmp(array_type_name, "[S") == 0) {
            jshort* elements = (*env)->GetShortArrayElements(env, value, 0);

            for (i = 0; i < size; i++) {
                bugsnag_array_set_number(array, elements[i]);
            }
        } else if (strcmp(array_type_name, "[D") == 0) {
            jdouble* elements = (*env)->GetDoubleArrayElements(env, value, 0);

            for (i = 0; i < size; i++) {
                bugsnag_array_set_number(array, elements[i]);
            }
        } else if (strcmp(array_type_name, "[F") == 0) {
            jfloat* elements = (*env)->GetFloatArrayElements(env, value, 0);

            for (i = 0; i < size; i++) {
                bugsnag_array_set_number(array, elements[i]);
            }
        } else if (strcmp(array_type_name, "[J") == 0) {
            jlong* elements = (*env)->GetLongArrayElements(env, value, 0);

            for (i = 0; i < size; i++) {
                bugsnag_array_set_number(array, elements[i]);
            }
        } else if (strcmp(array_type_name, "[B") == 0) {
            jbyte* elements = (*env)->GetByteArrayElements(env, value, 0);

            for (i = 0; i < size; i++) {
                bugsnag_array_set_number(array, elements[i]);
            }
        } else if (strcmp(array_type_name, "[Z") == 0) {
            jboolean* elements = (*env)->GetBooleanArrayElements(env, value, 0);

            for (i = 0; i < size; i++) {
                bugsnag_array_set_bool(array, elements[i]);
            }
        } else if (strcmp(array_type_name, "[C") == 0) {
            jchar* elements = (*env)->GetCharArrayElements(env, value, 0);

            for (i = 0; i < size; i++) {
                bugsnag_array_set_string(array, get_string_from_char(env, elements[i]));
            }
        } else {

            for (i = 0; i < size; i++) {
                jobject element_value = (*env)->GetObjectArrayElement(env, value, i);

                bsg_add_meta_data_array_item(env, array, element_value, filters);
                (*env)->DeleteLocalRef(env, element_value);
            }
        }
    }
}

/**
 * Gets an array of items from the given collection
 */
jarray bsg_get_meta_data_array_from_collection(JNIEnv *env, jobject value) {
    // Get the object array from the collection
    jclass collection_class = (*env)->FindClass(env, "java/util/Collection");
    jmethodID to_array_method = (*env)->GetMethodID(env, collection_class, "toArray", "()[Ljava/lang/Object;");
    jarray array = (*env)->CallObjectMethod(env, value, to_array_method);

    (*env)->DeleteLocalRef(env, collection_class);

    return array;
}

/**
 * Gets a char* from the given jstring
 */
const char* bsg_get_meta_data_string(JNIEnv *env, jstring value) {
    return (*env)->GetStringUTFChars(env, (jstring)value, JNI_FALSE);
}

/**
 * Gets an int from the given Integer object
 */
jint bsg_get_meta_data_int(JNIEnv *env, jobject value) {
    jclass integer_class = (*env)->FindClass(env, "java/lang/Integer");
    jmethodID get_value_method = (*env)->GetMethodID(env, integer_class, "intValue", "()I");

    (*env)->DeleteLocalRef(env, integer_class);

    return (*env)->CallIntMethod(env, value, get_value_method);
}

/**
 * Gets a float from the given Float object
 */
jfloat bsg_get_meta_data_float(JNIEnv *env, jobject value) {
    jclass float_class = (*env)->FindClass(env, "java/lang/Float");
    jmethodID get_value_method = (*env)->GetMethodID(env, float_class, "floatValue", "()F");

    (*env)->DeleteLocalRef(env, float_class);

    return (*env)->CallFloatMethod(env, value, get_value_method);
}

/**
 * Gets a double from the given Double object
 */
jdouble bsg_get_meta_data_double(JNIEnv *env, jobject value) {
    jclass double_class = (*env)->FindClass(env, "java/lang/Double");
    jmethodID get_value_method = (*env)->GetMethodID(env, double_class, "doubleValue", "()D");

    (*env)->DeleteLocalRef(env, double_class);

    return (*env)->CallDoubleMethod(env, value, get_value_method);
}

/**
 * Gets a long from the given Long object
 */
jlong bsg_get_meta_data_long(JNIEnv *env, jobject value) {
    jclass long_class = (*env)->FindClass(env, "java/lang/Long");
    jmethodID get_value_method = (*env)->GetMethodID(env, long_class, "longValue", "()J");

    (*env)->DeleteLocalRef(env, long_class);

    return (*env)->CallLongMethod(env, value, get_value_method);
}

/**
 * Gets a char from the given Character object
 */
jchar bsg_get_meta_data_character(JNIEnv *env, jobject value) {
    jclass char_class = (*env)->FindClass(env, "java/lang/Character");
    jmethodID get_value_method = (*env)->GetMethodID(env, char_class, "charValue", "()C");

    (*env)->DeleteLocalRef(env, char_class);

    return (*env)->CallCharMethod(env, value, get_value_method);
}

/**
 * Gets a byte from the given Byte object
 */
jbyte bsg_get_meta_data_byte(JNIEnv *env, jobject value) {
    jclass byte_class = (*env)->FindClass(env, "java/lang/Byte");
    jmethodID get_value_method = (*env)->GetMethodID(env, byte_class, "byteValue", "()B");

    (*env)->DeleteLocalRef(env, byte_class);

    return (*env)->CallByteMethod(env, value, get_value_method);
}

/**
 * Gets a short from the given Short object
 */
jshort bsg_get_meta_data_short(JNIEnv *env, jobject value) {
    jclass short_class = (*env)->FindClass(env, "java/lang/Short");
    jmethodID get_value_method = (*env)->GetMethodID(env, short_class, "shortValue", "()S");

    (*env)->DeleteLocalRef(env, short_class);

    return (*env)->CallShortMethod(env, value, get_value_method);
}

/**
 * Gets a boolean from the given Boolean object
 */
jboolean bsg_get_meta_data_boolean(JNIEnv *env, jobject value) {
    jclass bool_class = (*env)->FindClass(env, "java/lang/Boolean");
    jmethodID get_value_method = (*env)->GetMethodID(env, bool_class, "booleanValue", "()Z");

    (*env)->DeleteLocalRef(env, bool_class);

    return (*env)->CallBooleanMethod(env, value, get_value_method);
}

/**
 * Adds the given value to the given object
 */
void bsg_add_meta_data_item(JNIEnv *env, JSON_Object* object, const char* key, jobject value, struct bugsnag_ndk_string_array *filters) {
    if (is_array(env, value)) {
        // Create a new section with the given key
        JSON_Array* new_array = bugsnag_object_add_array(object, key);

        bsg_add_meta_data_array(env, new_array, value, filters);
    } else if (is_instance_of(env, value, "java/util/Collection")) {
        // Create a new section with the given key
        JSON_Array* new_array = bugsnag_object_add_array(object, key);

        jarray array = bsg_get_meta_data_array_from_collection(env, value);
        bsg_add_meta_data_array(env, new_array, array, filters);
        (*env)->DeleteLocalRef(env, array);
    } else if (is_instance_of(env, value, "java/util/Map")) {
        // Create a new section with the given key
        JSON_Object* new_section = bugsnag_object_add_object(object, key);

        bsg_add_meta_data_map(env, new_section, value, filters);
    } else if (is_instance_of(env, value, "java/lang/String")) {
        const char* value_str = bsg_get_meta_data_string(env, value);
        bugsnag_object_set_string(object, key, value_str);
    } else if (is_instance_of(env, value, "java/lang/Integer")) {
        jint value_int = bsg_get_meta_data_int(env, value);
        bugsnag_object_set_number(object, key, value_int);
    } else if (is_instance_of(env, value, "java/lang/Float")) {
        jfloat value_float = bsg_get_meta_data_float(env, value);
        bugsnag_object_set_number(object, key, value_float);
    } else if (is_instance_of(env, value, "java/lang/Double")) {
        jdouble value_double = bsg_get_meta_data_double(env, value);
        bugsnag_object_set_number(object, key, value_double);
    } else if (is_instance_of(env, value, "java/lang/Long")) {
        jlong value_long = bsg_get_meta_data_long(env, value);
        bugsnag_object_set_number(object, key, value_long);
    } else if (is_instance_of(env, value, "java/lang/Character")) {
        jchar value_char = bsg_get_meta_data_character(env, value);
        bugsnag_object_set_string(object, key, get_string_from_char(env, value_char));
    } else if (is_instance_of(env, value, "java/lang/Byte")) {
        jbyte value_byte = bsg_get_meta_data_byte(env, value);
        bugsnag_object_set_number(object, key, value_byte);
    } else if (is_instance_of(env, value, "java/lang/Short")) {
        jshort value_short = bsg_get_meta_data_short(env, value);
        bugsnag_object_set_number(object, key, value_short);
    } else if (is_instance_of(env, value, "java/lang/Boolean")) {
        jboolean value_boolean = bsg_get_meta_data_boolean(env, value);
        bugsnag_object_set_bool(object, key, value_boolean);
    } else {
        const char * type_name = get_class_name(env, value);

        BUGSNAG_LOG("unsupported type %s", type_name);

        bugsnag_object_set_string(object, key, type_name);
    }
}

/**
 * Addes the given value to the given array
 */
void bsg_add_meta_data_array_item(JNIEnv *env, JSON_Array* array, jobject value, struct bugsnag_ndk_string_array *filters) {
    if (is_array(env, value)) {
        // Create a new array
        JSON_Array* new_array = bugsnag_array_add_array(array);

        bsg_add_meta_data_array(env, new_array, value, filters);
    } else if (is_instance_of(env, value, "java/util/Collection")) {
        // Create a new array
        JSON_Array* new_array = bugsnag_array_add_array(array);

        jarray array_values = bsg_get_meta_data_array_from_collection(env, value);
        bsg_add_meta_data_array(env, new_array, array_values, filters);
        (*env)->DeleteLocalRef(env, array_values);
    } else if (is_instance_of(env, value, "java/util/Map")) {
        // Create a new object
        JSON_Object* new_object = bugsnag_array_add_object(array);

        bsg_add_meta_data_map(env, new_object, value, filters);
    } else if (is_instance_of(env, value, "java/lang/String")) {
        const char* value_str = bsg_get_meta_data_string(env, value);
        bugsnag_array_set_string(array, value_str);
    } else if (is_instance_of(env, value, "java/lang/Integer")) {
        jint value_int = bsg_get_meta_data_int(env, value);
        bugsnag_array_set_number(array, value_int);
    } else if (is_instance_of(env, value, "java/lang/Float")) {
        jfloat value_float = bsg_get_meta_data_float(env, value);
        bugsnag_array_set_number(array, value_float);
    } else if (is_instance_of(env, value, "java/lang/Double")) {
        jdouble value_double = bsg_get_meta_data_double(env, value);
        bugsnag_array_set_number(array, value_double);
    } else if (is_instance_of(env, value, "java/lang/Long")) {
        jlong value_long = bsg_get_meta_data_long(env, value);
        bugsnag_array_set_number(array, value_long);
    } else if (is_instance_of(env, value, "java/lang/Character")) {
        jchar value_char = bsg_get_meta_data_character(env, value);
        bugsnag_array_set_string(array, get_string_from_char(env, value_char));
    } else if (is_instance_of(env, value, "java/lang/Byte")) {
        jbyte value_byte = bsg_get_meta_data_byte(env, value);
        bugsnag_array_set_number(array, value_byte);
    } else if (is_instance_of(env, value, "java/lang/Short")) {
        jshort value_short = bsg_get_meta_data_short(env, value);
        bugsnag_array_set_number(array, value_short);
    } else if (is_instance_of(env, value, "java/lang/Boolean")) {
        jboolean value_boolean = bsg_get_meta_data_boolean(env, value);
        bugsnag_array_set_bool(array, value_boolean);
    } else {
        const char * type_name = get_class_name(env, value);

        BUGSNAG_LOG("unsupported type %s", type_name);
        bugsnag_array_set_string(array, type_name);
    }
}

/**
 * Gets the meta data from the client class and pre-populates the bugsnag error
 */
void bsg_populate_meta_data(JNIEnv *env, bsg_event *event, struct bugsnag_ndk_string_array *filters) {
    // wipe the existing structure
    bugsnag_event_clear_metadata_base(event);

    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");

    jmethodID get_data_method = (*env)->GetStaticMethodID(env, interface_class, "getMetaData", "()Ljava/util/Map;");
    jobject meta_data_value = (*env)->CallStaticObjectMethod(env, interface_class, get_data_method);

    int size = bsg_get_map_size(env, meta_data_value);

    if (size > 0) {
        jarray key_array_value = bsg_get_map_key_array(env, meta_data_value);

        int i;
        for (i = 0; i < size; i++) {
            // The key should always be a string for the base tabs
            jobject key = (*env)->GetObjectArrayElement(env, key_array_value, i);
            const char* tab_name = (*env)->GetStringUTFChars(env, (jstring)key, JNI_FALSE);

            jobject tab_value = bsg_get_item_from_map(env, meta_data_value, key);

            JSON_Object* meta_data = bugsnag_event_get_metadata_base(event);
            bsg_add_meta_data_item(env, meta_data, tab_name, tab_value, filters);

            (*env)->DeleteLocalRef(env, key);
            (*env)->DeleteLocalRef(env, tab_value);
        }

        (*env)->DeleteLocalRef(env, key_array_value);
    }


    (*env)->DeleteLocalRef(env, interface_class);
    (*env)->DeleteLocalRef(env, meta_data_value);
}

/**
 * Gets the user details from the client class and pre-populates the bugsnag error
 */
void bsg_populate_user_details(JNIEnv *env, bsg_event *event) {
    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");

    bugsnag_event_set_string(event, BSG_USER, "id", get_method_string(env, interface_class, "getUserId"));
    bugsnag_event_set_string(event, BSG_USER, "email", get_method_string(env, interface_class, "getUserEmail"));
    bugsnag_event_set_string(event, BSG_USER, "name", get_method_string(env, interface_class, "getUserName"));

    (*env)->DeleteLocalRef(env, interface_class);
}

int version_to_int(const char *ver)
{
    char v[256] = {0};
    size_t j = 0;
    for (size_t i = 0; i < strlen(ver) && j < sizeof(v) - 1; i++) {
        if (isdigit(ver[i])) {
            v[j] = ver[i]; 
            j++;
        }
    }
    return atoi(v);
}

/**
 * Gets the app data details from the client class and pre-populates the bugsnag error
 */
void bsg_populate_app_data(JNIEnv *env, bsg_event *event) {
    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");

    bugsnag_event_set_string(event, BSG_APP, "releaseStage", get_method_string(env, interface_class, "getReleaseStage"));

    //bugsnag_event_set_string(event, BSG_APP, "id", get_method_string(env, interface_class, "getPackageName"));
    bugsnag_event_set_string(event, BSG_APP, "id", "com.clostra.newnode");

    //bugsnag_event_set_string(event, BSG_APP, "packageName", get_method_string(env, interface_class, "getPackageName"));
    bugsnag_event_set_string(event, BSG_APP, "packageName", "com.clostra.newnode");

    bugsnag_event_set_string(event, BSG_APP, "name", get_method_string(env, interface_class, "getAppName"));

    //bugsnag_event_set_string(event, BSG_APP, "version", get_method_string(env, interface_class, "getAppVersion"));
    bugsnag_event_set_string(event, BSG_APP, "version", VERSION);

    //bugsnag_event_set_string(event, BSG_APP, "versionName", get_method_string(env, interface_class, "getVersionName"));
    bugsnag_event_set_string(event, BSG_APP, "versionName", VERSION);

    //bugsnag_event_set_number(event, BSG_APP, "versionCode", get_method_int(env, interface_class, "getVersionCode"));
    bugsnag_event_set_number(event, BSG_APP, "versionCode", version_to_int(VERSION));

    //bugsnag_event_set_string(event, BSG_APP, "buildUUID", get_method_string(env, interface_class, "getBuildUUID"));
    bugsnag_event_set_string(event, BSG_APP, "buildUUID", VERSION);

    (*env)->DeleteLocalRef(env, interface_class);
}


/**
 * Gets the device CPU ABI details from the client class and pre-populates the bugsnag error
 */
void bsg_populate_device_cpu_abi(JNIEnv *env, bsg_event *event, jclass interface_class) {
    jmethodID method = (*env)->GetStaticMethodID(env, interface_class, "getDeviceCpuAbi", "()[Ljava/lang/String;");
    jobjectArray value = (*env)->CallStaticObjectMethod(env, interface_class, method);

    JSON_Object* device_base = bugsnag_event_get_section_base(event, BSG_DEVICE);
    JSON_Array* abi_array = bugsnag_object_add_array(device_base, "cpuAbi");
    int size = (*env)->GetArrayLength(env, value);

    int i;
    for (i = 0; i < size; i++) {
        // Get the abi value as a char *
        jstring element_value = (*env)->GetObjectArrayElement(env, value, i);
        char* abi = (char*)(*env)->GetStringUTFChars(env, element_value, JNI_FALSE);

        // Add it to the JSON array
        bugsnag_array_set_string(abi_array, abi);
        (*env)->DeleteLocalRef(env, element_value);
    }
    (*env)->DeleteLocalRef(env, value);
}

/**
 * Gets the device data details from the client class and pre-populates the bugsnag error
 */
void bsg_populate_device_data(JNIEnv *env, bsg_event *event) {
    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");

    bugsnag_event_set_string(event, BSG_DEVICE, "osName", "Android");
    bugsnag_event_set_string(event, BSG_DEVICE, "osVersion", get_method_string(env, interface_class, "getDeviceOsVersion"));
    bugsnag_event_set_string(event, BSG_DEVICE, "osBuild", get_method_string(env, interface_class, "getDeviceOsBuild"));
    bugsnag_event_set_string(event, BSG_DEVICE, "id", get_method_string(env, interface_class, "getDeviceId"));
    bugsnag_event_set_number(event, BSG_DEVICE, "totalMemory", get_method_double(env, interface_class, "getDeviceTotalMemory"));
    bugsnag_event_set_string(event, BSG_DEVICE, "locale", get_method_string(env, interface_class, "getDeviceLocale"));

    bugsnag_event_set_bool(event, BSG_DEVICE, "rooted", get_method_boolean(env, interface_class, "getDeviceRooted"));
    bugsnag_event_set_number(event, BSG_DEVICE, "dpi", get_method_int(env, interface_class, "getDeviceDpi"));
    bugsnag_event_set_number(event, BSG_DEVICE, "screenDensity", get_method_float(env, interface_class, "getDeviceScreenDensity"));
    bugsnag_event_set_string(event, BSG_DEVICE, "screenResolution", get_method_string(env, interface_class, "getDeviceScreenResolution"));

    bugsnag_event_set_string(event, BSG_DEVICE, "manufacturer", get_method_string(env, interface_class, "getDeviceManufacturer"));
    bugsnag_event_set_string(event, BSG_DEVICE, "brand", get_method_string(env, interface_class, "getDeviceBrand"));
    bugsnag_event_set_string(event, BSG_DEVICE, "model", get_method_string(env, interface_class, "getDeviceModel"));
    bugsnag_event_set_number(event, BSG_DEVICE, "apiLevel", get_method_int(env, interface_class, "getDeviceApiLevel"));

    bsg_populate_device_cpu_abi(env, event, interface_class);

    (*env)->DeleteLocalRef(env, interface_class);
}

/**
 * Gets the context from the client class and pre-populates the bugsnag error
 */
void bsg_populate_context(JNIEnv *env, bsg_event *event) {
    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");

    event->context = get_method_string(env, interface_class, "getContext");

    (*env)->DeleteLocalRef(env, interface_class);
}

/**
 * Converts a java breadcrumb type into a bsg_breadcrumb_t
 */
bsg_breadcrumb_t bsg_get_breadcrumb_type(JNIEnv *env, jobject type) {
    jclass breadcrumb_type_class = (*env)->FindClass(env, "com/bugsnag/android/BreadcrumbType");
    jmethodID to_string_method = (*env)->GetMethodID(env, breadcrumb_type_class, "toString", "()Ljava/lang/String;");
    jstring breadcrumb_string = (*env)->CallObjectMethod(env, type, to_string_method);

    const char* breadcrumb_type = (*env)->GetStringUTFChars(env, breadcrumb_string, JNI_FALSE);

    (*env)->DeleteLocalRef(env, breadcrumb_type_class);
    (*env)->DeleteLocalRef(env, breadcrumb_string);

    if (strcmp(breadcrumb_type, "error") == 0) {
        return BSG_CRUMB_ERROR;
    } else if (strcmp(breadcrumb_type, "log") == 0) {
        return BSG_CRUMB_LOG;
    } else if (strcmp(breadcrumb_type, "manual") == 0) {
        return BSG_CRUMB_MANUAL;
    } else if (strcmp(breadcrumb_type, "navigation") == 0) {
        return BSG_CRUMB_NAVIGATION;
    } else if (strcmp(breadcrumb_type, "process") == 0) {
        return BSG_CRUMB_PROCESS;
    } else if (strcmp(breadcrumb_type, "request") == 0) {
        return BSG_CRUMB_REQUEST;
    } else if (strcmp(breadcrumb_type, "state") == 0) {
        return BSG_CRUMB_STATE;
    } else if (strcmp(breadcrumb_type, "user") == 0) {
        return BSG_CRUMB_USER;
    } else {
        return BSG_CRUMB_ERROR;
    }
}

/**
 * Constants used for calculating times
 */
const int SecondsPerMinute = 60;
const int SecondsPerHour = 3600;
const int SecondsPerDay = 86400;
const int DaysOfMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

/**
 * Checks if the given year is a leap year
 */
int IsLeapYear(int year)
{
    if (year % 4 != 0) return 0;
    if (year % 100 != 0) return 1;
    return (year % 400) == 0;
}

/**
 * Creates a time_t from a tm structure that is in UTC
 * NOTE: this is needed because the standard mktime() method will use the local timezone
 * and we need all the dates in UTC
 */
static time_t mkgmtime(const struct tm *ptm) {
    time_t secs = 0;
    // tm_year is years since 1900
    int year = ptm->tm_year + 1900;
    for (int y = 1970; y < year; ++y) {
        secs += (IsLeapYear(y)? 366: 365) * SecondsPerDay;
    }
    // tm_mon is month from 0..11
    for (int m = 0; m < ptm->tm_mon; ++m) {
        secs += DaysOfMonth[m] * SecondsPerDay;
        if (m == 1 && IsLeapYear(year)) secs += SecondsPerDay;
    }
    secs += (ptm->tm_mday - 1) * SecondsPerDay;
    secs += ptm->tm_hour       * SecondsPerHour;
    secs += ptm->tm_min        * SecondsPerMinute;
    secs += ptm->tm_sec;
    return secs;
}

/**
 * Constructs a time_t from the given time String (must be in format "yyyy-MM-dd'T'HH:mm:ss'Z'"
 * that the Java code outputs
 */
time_t bsg_get_time_from_string(const char* time_details) {
    struct tm tm;
    strptime(time_details,"%Y-%m-%dT%H:%M:%S%z" , &tm);
    return mkgmtime(&tm);
}

/**
 * Gets the breadcrumbs from the client class and pre-populates the bugsnag error
 */
void bsg_populate_breadcrumbs(JNIEnv *env, bsg_event *event) {
    // Clear out existing breadcrumbs
    bugsnag_event_clear_breadcrumbs(event);

    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");

    jmethodID get_breadcrumbs_method = (*env)->GetStaticMethodID(env, interface_class, "getBreadcrumbs", "()[Ljava/lang/Object;");
    jarray breadcrumbs_value = (*env)->CallStaticObjectMethod(env, interface_class, get_breadcrumbs_method);

    jclass breadcrumb_class = (*env)->FindClass(env, "com/bugsnag/android/Breadcrumb");
    if (!breadcrumb_class) {
        (*env)->ExceptionClear(env);
        breadcrumb_class = (*env)->FindClass(env, "com/bugsnag/android/Breadcrumbs$Breadcrumb");
    }
    jfieldID timestamp_field = (*env)->GetFieldID(env, breadcrumb_class, "timestamp", "Ljava/lang/String;");
    jfieldID name_field = (*env)->GetFieldID(env, breadcrumb_class, "name", "Ljava/lang/String;");
    jfieldID type_field = (*env)->GetFieldID(env, breadcrumb_class, "type", "Lcom/bugsnag/android/BreadcrumbType;");
    jfieldID meta_data_field = (*env)->GetFieldID(env, breadcrumb_class, "metadata", "Ljava/util/Map;");

    // loop over all the items in the map and add them
    int size = (*env)->GetArrayLength(env, breadcrumbs_value);

    for (int i = 0; i < size; i++) {
        jobject breadcrumb = (*env)->GetObjectArrayElement(env, breadcrumbs_value, i);

        const char * timestamp = bsg_get_meta_data_string(env, (*env)->GetObjectField(env, breadcrumb, timestamp_field));
        const char * name = bsg_get_meta_data_string(env, (*env)->GetObjectField(env, breadcrumb, name_field));
        jobject breadcrumb_type = (*env)->GetObjectField(env, breadcrumb, type_field);
        jobject meta_data_value = (*env)->GetObjectField(env, breadcrumb, meta_data_field);

        bsg_breadcrumb *crumb =
                bugsnag_breadcrumb_init((char *)name, bsg_get_breadcrumb_type(env, breadcrumb_type));
        crumb->timestamp = bsg_get_time_from_string(timestamp);

        int meta_size = bsg_get_map_size(env, meta_data_value);

        if (meta_size > 0) {
            jarray key_array_value = bsg_get_map_key_array(env, meta_data_value);

            int j;
            for (j = 0; j < meta_size; j++) {
                jstring key_str = (*env)->GetObjectArrayElement(env, key_array_value, j);
                const char* key = (*env)->GetStringUTFChars(env, key_str, JNI_FALSE);

                jstring value_str = bsg_get_item_from_map(env, meta_data_value, key_str);

                if (value_str != NULL) {
                    const char* value = (*env)->GetStringUTFChars(env, value_str, JNI_FALSE);
                    bugsnag_object_set_string(json_value_get_object(crumb->metadata), key, value);
                }

                (*env)->DeleteLocalRef(env, key_str);
                (*env)->DeleteLocalRef(env, value_str);
            }

            (*env)->DeleteLocalRef(env, key_array_value);
        }

        bugsnag_event_add_breadcrumb(event, crumb);

        (*env)->DeleteLocalRef(env, breadcrumb);
    }


    (*env)->DeleteLocalRef(env, breadcrumbs_value);
    (*env)->DeleteLocalRef(env, interface_class);
    (*env)->DeleteLocalRef(env, breadcrumb_class);
}

/**
 * Gets the release stages from the client to store for later
 */
void bsg_load_release_stages(JNIEnv *env, struct bugsnag_ndk_report *report) {
    // Clear existing release stages
    if (report->notify_release_stages.values) {
        free(report->notify_release_stages.values);
    }

    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");
    jmethodID get_release_stages_method = (*env)->GetStaticMethodID(env, interface_class, "getReleaseStages", "()[Ljava/lang/String;");
    jarray release_stages_value = (*env)->CallStaticObjectMethod(env, interface_class, get_release_stages_method);

    if (release_stages_value) {
        int size = (*env)->GetArrayLength(env, release_stages_value);

        report->notify_release_stages.size = size;
        report->notify_release_stages.values = calloc(sizeof(const char *), (size_t)size);

        for (int i = 0; i < size; i++) {
            jstring release_stage_value = (*env)->GetObjectArrayElement(env, release_stages_value, i);
            const char* release_stage = (*env)->GetStringUTFChars(env, release_stage_value, JNI_FALSE);

            report->notify_release_stages.values[i] = release_stage;

            (*env)->DeleteLocalRef(env, release_stage_value);
        }
    }

    (*env)->DeleteLocalRef(env, interface_class);
}

/**
 * Gets the filters from the client to store for later
 */
void bsg_load_filters(JNIEnv *env, struct bugsnag_ndk_report *report) {
    // Clear existing filters
    if (report->filters.values) {
        free(report->filters.values);
    }

    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");
    jmethodID get_filters_method = (*env)->GetStaticMethodID(env, interface_class, "getFilters", "()[Ljava/lang/String;");
    jarray filters_value = (*env)->CallStaticObjectMethod(env, interface_class, get_filters_method);

    if (filters_value) {
        int size = (*env)->GetArrayLength(env, filters_value);

        report->filters.size = size;
        report->filters.values = calloc(sizeof(const char *), (size_t)size);

        for (int i = 0; i < size; i++) {
            jstring filter_value = (*env)->GetObjectArrayElement(env, filters_value, i);
            const char* filter = (*env)->GetStringUTFChars(env, filter_value, JNI_FALSE);

            report->filters.values[i] = filter;

            (*env)->DeleteLocalRef(env, filter_value);
        }
    }

    (*env)->DeleteLocalRef(env, interface_class);
}

/**
 * Gets the location to write the error files to
 */
char *bsg_load_error_store_path(JNIEnv *env) {
    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");

    char* path = get_method_string(env, interface_class, "getErrorStorePath");

    (*env)->DeleteLocalRef(env, interface_class);

    return path;
}

/**
 * Gets details from java to pre-populates the bugsnag error
 */
void bsg_populate_event_details(JNIEnv *env, struct bugsnag_ndk_report *report) {
    bsg_event *event = report->event;
    event->severity = BSG_SEVERITY_ERR;

    bsg_populate_context(env, event);
    bsg_populate_user_details(env, event);
    bsg_populate_app_data(env, event);
    bsg_populate_device_data(env, event);
    bsg_populate_breadcrumbs(env, event);
    bsg_populate_meta_data(env, event, &report->filters);


    bsg_load_release_stages(env, report);
    bsg_load_filters(env, report);
}

void bsg_set_user(JNIEnv *env, char* id, char* email, char* name) {
    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");
    jmethodID set_user_method = (*env)->GetStaticMethodID(env, interface_class, "setUser", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

    jstring jid = (*env)->NewStringUTF(env, id);
    jstring jemail = (*env)->NewStringUTF(env, email);
    jstring jname = (*env)->NewStringUTF(env, name);

    (*env)->CallStaticVoidMethod(env, interface_class, set_user_method, jid, jemail, jname);


    (*env)->DeleteLocalRef(env, jid);
    (*env)->DeleteLocalRef(env, jemail);
    (*env)->DeleteLocalRef(env, jname);
    (*env)->DeleteLocalRef(env, interface_class);
}

void bsg_leave_breadcrumb(JNIEnv *env, char *name, bsg_breadcrumb_t type) {
    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");
    jmethodID leave_breadcrumb_method = (*env)->GetStaticMethodID(env, interface_class, "leaveBreadcrumb", "(Ljava/lang/String;Lcom/bugsnag/android/BreadcrumbType;)V");


    jclass type_class = (*env)->FindClass(env, "com/bugsnag/android/BreadcrumbType");
    jfieldID type_field;
    if (type == BSG_CRUMB_MANUAL) {
        type_field = (*env)->GetStaticFieldID(env, type_class , "MANUAL", "Lcom/bugsnag/android/BreadcrumbType;");
    } else if (type == BSG_CRUMB_ERROR) {
        type_field = (*env)->GetStaticFieldID(env, type_class , "ERROR", "Lcom/bugsnag/android/BreadcrumbType;");
    } else if (type == BSG_CRUMB_LOG) {
        type_field = (*env)->GetStaticFieldID(env, type_class , "LOG", "Lcom/bugsnag/android/BreadcrumbType;");
    } else if (type == BSG_CRUMB_NAVIGATION) {
        type_field = (*env)->GetStaticFieldID(env, type_class , "NAVIGATION", "Lcom/bugsnag/android/BreadcrumbType;");
    } else if (type == BSG_CRUMB_PROCESS) {
        type_field = (*env)->GetStaticFieldID(env, type_class , "PROCESS", "Lcom/bugsnag/android/BreadcrumbType;");
    } else if (type == BSG_CRUMB_REQUEST) {
        type_field = (*env)->GetStaticFieldID(env, type_class , "REQUEST", "Lcom/bugsnag/android/BreadcrumbType;");
    } else if (type == BSG_CRUMB_STATE) {
        type_field = (*env)->GetStaticFieldID(env, type_class , "STATE", "Lcom/bugsnag/android/BreadcrumbType;");
    } else {
        type_field = (*env)->GetStaticFieldID(env, type_class , "USER", "Lcom/bugsnag/android/BreadcrumbType;");
    }

    jobject jtype = (*env)->GetStaticObjectField(env, type_class, type_field);
    jstring jname = (*env)->NewStringUTF(env, name);
    (*env)->CallStaticVoidMethod(env, interface_class, leave_breadcrumb_method, jname, jtype);


    (*env)->DeleteLocalRef(env, jtype);
    (*env)->DeleteLocalRef(env, jname);

    (*env)->DeleteLocalRef(env, type_class);
    (*env)->DeleteLocalRef(env, interface_class);
}

void bsg_add_to_tab(JNIEnv *env, char *tab, char *key, jobject value) {

    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");
    jmethodID add_to_tab_method = (*env)->GetStaticMethodID(env, interface_class, "addToTab", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V");

    jstring jtab = (*env)->NewStringUTF(env, tab);
    jstring jkey = (*env)->NewStringUTF(env, key);

    (*env)->CallStaticVoidMethod(env, interface_class, add_to_tab_method, jtab, jkey, value);

    (*env)->DeleteLocalRef(env, jtab);
    (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, interface_class);
}

void bsg_add_string_to_tab(JNIEnv *env, char *tab, char *key, char* value) {
    jstring jvalue = (*env)->NewStringUTF(env, value);

    bsg_add_to_tab(env, tab, key, jvalue);

    (*env)->DeleteLocalRef(env, jvalue);
}

void bsg_add_number_to_tab(JNIEnv *env, char *tab, char *key, double value) {
    jclass double_class = (*env)->FindClass(env, "java/lang/Double");
    jmethodID double_constructor = (*env)->GetMethodID(env, double_class, "<init>", "(D)V");
    jobject jvalue = (*env)->NewObject(env, double_class, double_constructor, (jdouble)value);

    bsg_add_to_tab(env, tab, key, jvalue);

    (*env)->DeleteLocalRef(env, double_class);
    (*env)->DeleteLocalRef(env, jvalue);
}

void bsg_add_boolean_to_tab(JNIEnv *env, char *tab, char *key, int value) {
    jclass boolean_class = (*env)->FindClass(env, "java/lang/Boolean");
    jmethodID boolean_constructor = (*env)->GetMethodID(env, boolean_class, "<init>", "(Z)V");
    jobject jvalue = (*env)->NewObject(env, boolean_class, boolean_constructor, (jboolean)value);

    bsg_add_to_tab(env, tab, key, jvalue);

    (*env)->DeleteLocalRef(env, boolean_class);
    (*env)->DeleteLocalRef(env, jvalue);
}





