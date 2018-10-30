#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <sodium.h>

#include "log.h"
#include "network.h"
#include "merkle_tree.h"


void merkle_tree_free(merkle_tree *m)
{
    if (!m) {
        return;
    }
    free(m->nodes);
    free(m);
}

bool merkle_tree_set_leaves(merkle_tree *m, const uint8_t *data, size_t length)
{
    if (length % member_sizeof(node, hash) != 0) {
        return false;
    }
    _Static_assert(sizeof(node) == member_sizeof(node, hash), "node hash packing");
    m->leaves_num = length / member_sizeof(node, hash);
    m->nodes_alloc = m->leaves_num*2 - 1;
    m->nodes = calloc(m->nodes_alloc, sizeof(node));
    memcpy(m->nodes, data, length);
    return true;
}

void merkle_tree_leaf_finish(merkle_tree *m)
{
    assert(m->leaves_num <= m->nodes_alloc);
    if (m->leaves_num == m->nodes_alloc) {
        if (!m->nodes_alloc) {
            m->nodes_alloc = 1;
        }
        m->nodes_alloc *= 2;
        m->nodes = realloc(m->nodes, m->nodes_alloc * sizeof(node));
    }
    crypto_generichash_final(&m->leaf_state, m->nodes[m->leaves_num].hash, sizeof(m->nodes[m->leaves_num].hash));
    m->leaves_num++;
    m->leaf_progress = 0;
}

void merkle_tree_add_hashed_data(merkle_tree *m, const uint8_t *data, size_t length)
{
    for (size_t remain = length; remain; ) {
        assert(m->leaf_progress < LEAF_CHUNK_SIZE);
        if (m->leaf_progress == 0) {
            crypto_generichash_init(&m->leaf_state, NULL, 0, member_sizeof(node, hash));
        }
        size_t len = MIN(LEAF_CHUNK_SIZE - m->leaf_progress, remain);
        crypto_generichash_update(&m->leaf_state, &data[length - remain], len);
        remain -= len;
        m->leaf_progress += len;
        assert(m->leaf_progress <= LEAF_CHUNK_SIZE);
        if (m->leaf_progress == LEAF_CHUNK_SIZE) {
            merkle_tree_leaf_finish(m);
        }
    }
}

size_t power_two_ceil(size_t v)
{
    v--;
    for (size_t i = 1; i < sizeof(v) * 8; i *= 2) {
        v |= v >> i;
    }
    return v + 1;
}

void node_hash(const node *l, const node *r, node *n)
{
    uint8_t key[crypto_generichash_KEYBYTES] = "node";
    crypto_generichash_state state;
    crypto_generichash_init(&state, key, sizeof(key), member_sizeof(node, hash));
    crypto_generichash_update(&state, l->hash, sizeof(l->hash));
    crypto_generichash_update(&state, r->hash, sizeof(r->hash));
    crypto_generichash_final(&state, n->hash, sizeof(n->hash));
}

void merkle_tree_finish_leaves(merkle_tree *m)
{
    if (m->leaf_progress > 0) {
        merkle_tree_leaf_finish(m);
    }
    int round_up = power_two_ceil(m->leaves_num) - m->leaves_num;
    for (int i = 0; i < round_up; i++) {
        crypto_generichash_init(&m->leaf_state, NULL, 0, member_sizeof(node, hash));
        merkle_tree_leaf_finish(m);
    }
    assert(m->leaves_num);

    size_t nodes_num = m->leaves_num - 1;
    m->nodes = realloc(m->nodes, (m->leaves_num + nodes_num) * sizeof(node));
    if (m->leaves_num > 1) {
        for (size_t i = 0; i < m->leaves_num*2 - 2; i += 2) {
            node_hash(&m->nodes[i], &m->nodes[i+1], &m->nodes[m->leaves_num + i/2]);
        }
    }
}

void merkle_tree_get_root(merkle_tree *m, uint8_t *root_hash)
{
    merkle_tree_finish_leaves(m);
    const node *root_node = &m->nodes[m->leaves_num*2 - 2];
    memcpy(root_hash, root_node->hash, sizeof(root_node->hash));
}
