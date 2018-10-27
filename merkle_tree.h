#ifndef __MERKLE_TREE_H__
#define __MERKLE_TREE_H__

#define LEAF_CHUNK_SIZE 16384

typedef struct {
    uint8_t hash[crypto_generichash_BYTES];
} node;

typedef struct {
    crypto_generichash_state leaf_state;
    uint16_t leaf_progress;
    size_t leaves_num;
    size_t nodes_alloc;
    node *nodes;
} merkle_tree;

void merkle_tree_free(merkle_tree *m);
bool merkle_tree_set_leaves(merkle_tree *m, const uint8_t *data, size_t length);
void merkle_tree_add_hashed_data(merkle_tree *m, const uint8_t *data, size_t length);
void merkle_tree_get_root(merkle_tree *m, uint8_t *root_hash);

#endif // __MERKLE_TREE_H__
