#ifndef __HASH_TABLE_H__
#define __HASH_TABLE_H__

struct kh_hash_table_val_s;
typedef struct kh_hash_table_val_s hash_table;

typedef void* (^create_fn)();

hash_table* hash_table_create();
void* hash_get(hash_table *h, const char *key);
void* hash_get_or_insert(hash_table *h, const char *key, create_fn c);
void hash_set(hash_table *h, const char *key, void *val);
void hash_table_free(hash_table *h);

#endif // __HASH_TABLE_H__
