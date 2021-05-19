#include <stdio.h>
#include <assert.h>

#include "hash_table.h"
#include "khash.h"


typedef void* hash_table_val;
KHASH_MAP_INIT_STR(hash_table_val, hash_table_val);
typedef khash_t(hash_table_val) hash_table;


hash_table* hash_table_create()
{
    return kh_init(hash_table_val);
}

size_t hash_length(hash_table *h)
{
    return kh_size(h);
}

void* hash_get(hash_table *h, const char *key)
{
    khint_t k = kh_get(hash_table_val, h, key);
    if (k == kh_end(h)) {
        return NULL;
    }
    return kh_val(h, k);
}

void* hash_get_or_insert(hash_table *h, const char *key, create_fn c)
{
    int absent;
    char *key_dup = strdup(key);
    khint_t k = kh_put(hash_table_val, h, key_dup, &absent);
    if (absent) {
        kh_val(h, k) = c();
    } else {
        free(key_dup);
    }
    return kh_val(h, k);
}

void* hash_set(hash_table *h, const char *key, void *val)
{
    int absent;
    char *key_dup = strdup(key);
    khint_t k = kh_put(hash_table_val, h, key_dup, &absent);
    void *old = absent ? NULL : kh_val(h, k);
    if (!absent) {
        free(key_dup);
    }
    kh_val(h, k) = val;
    return old;
}

void* hash_remove(hash_table *h, const char *key)
{
    khint_t k = kh_get(hash_table_val, h, key);
    if (k == kh_end(h)) {
        return NULL;
    }
    void *r = kh_val(h, k);
    char *key_dup = (char*)kh_key(h, k);
    free(key_dup);
    kh_del(hash_table_val, h, k);
    return r;
}

void hash_iter(hash_table *h, iter_fn iter)
{
    const char *k;
    void *v;
    kh_foreach(h, k, v, {
        if (!iter(k, v)) {
            break;
        }
    });
}

void hash_table_free(hash_table *h)
{
    kh_destroy(hash_table_val, h);
}
