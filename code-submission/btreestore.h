//
// Created by herain on 5/23/21.
//

#ifndef UNTITLED_BTREESTORE_H
#define UNTITLED_BTREESTORE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct info {
    uint32_t size;
    uint32_t key[4];
    uint64_t nonce;
    void * data;
};

struct node {
    uint16_t num_keys;
    uint32_t * keys;
};

void * init_store(uint16_t branching, uint8_t n_processors);

void close_store(void * helper);

int btree_insert(uint32_t key, void * plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void * helper);

int btree_retrieve(uint32_t key, struct info * found, void * helper);

int btree_decrypt(uint32_t key, void * output, void * helper);

int btree_delete(uint32_t key, void * helper);

uint64_t btree_export(void * helper, struct node ** list);

void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4]);

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4]);

void encrypt_tea_ctr(uint64_t * plain, uint32_t key[4], uint64_t nonce, uint64_t * cipher, uint32_t num_blocks);

void decrypt_tea_ctr(uint64_t * cipher, uint32_t key[4], uint64_t nonce, uint64_t * plain, uint32_t num_blocks);

#include <stdint.h>
#include <malloc.h>
#include <math.h>
#include <pthread.h>

#define DEFAULT -1

#define SUCCESS 0
#define KEYEXIST 1
#define NOSUCHKEY 1
#define NULLHELPER -1

#define TRUE 0
#define FALSE 1

struct btree_node;
struct key_item;
struct btree_manager;

/**
 * For the key_item:
 * 1. All nodes in the left child is less then key_value
 * 2. All nodes in the right child is greater than key_value
 */
struct key_item{
    uint32_t key_value;
    struct btree_node * left_child;
    struct btree_node * right_child;
    uint32_t size;
    uint32_t key[4];
    uint64_t nonce;
    void *data;
};

/**
 * For the btree_node:
 *   It will contains n keys, it will use n-1 keys to store the keys generally, but when insert operation overflow, it will store the new key temporarily.
 *   At first, maximum array_size is unknown, so it should be malloc later.
 */
struct btree_node{
    uint16_t array_size;
    int isLeaf;
    struct key_item * keys_array;
    struct btree_node * parent_node;
    struct key_item * left_parent_key_item;
    struct key_item * right_parent_key_item;
};

struct btree_manager{
    uint32_t btree_size;
    uint16_t branching;
    uint8_t max_task;
    uint8_t thread_counter;
    pthread_mutex_t change_thread_counter_mutex;
    pthread_cond_t wait_cond;
    pthread_rwlock_t rwlock;
    struct btree_node * btree;
};


struct btree_node * basic_node_init(uint16_t branching);
int basic_btree_insert(struct btree_manager *manager, uint32_t key_value, uint32_t size, uint32_t *key, uint64_t nonce, void *data);
int basic_btree_search(struct btree_manager *manager, uint32_t key_value, struct info *found);
void insert_to_array_index(struct btree_node *target_node, uint16_t target_index, uint32_t insert_key);
void spilt_node(struct btree_manager *manager, struct btree_node *target_node);
int basic_btree_delete(struct btree_manager *manager, uint32_t key_value);
void delete_from_array_index(struct btree_node *target_node, uint16_t target_index);
void merge_node(struct btree_manager *manager, struct btree_node *target_node);
void copy_keys(struct key_item* target, struct key_item* source);
void pre_order_travel(struct btree_node *target_node, struct node ** list, uint16_t *order);
void free_pre_order(struct btree_node *target_node);

#endif //UNTITLED_BTREESTORE_H
