#ifndef __HASH_TABLE_H__
#define __HASH_TABLE_H__

#include <stdbool.h>

struct kh_hash_table_val_s;
typedef struct kh_hash_table_val_s hash_table;

typedef void* (^create_fn)(void);
typedef bool (^iter_fn)(const char *key, void *val);

hash_table* hash_table_create(void);
size_t hash_length(hash_table *h);
void* hash_get(hash_table *h, const char *key);
void* hash_get_or_insert(hash_table *h, const char *key, create_fn c);
void* hash_set(hash_table *h, const char *key, void *val);
void* hash_remove(hash_table *h, const char *key);
void hash_iter(hash_table *h, iter_fn iter);
void hash_table_free(hash_table *h);

#endif // __HASH_TABLE_H__
