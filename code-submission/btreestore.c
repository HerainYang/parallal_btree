//
// Created by herain on 5/23/21.
//

#include "btreestore.h"

void * init_store(uint16_t branching, uint8_t n_processors) {
    // Your code here
    struct btree_manager *manager = malloc(sizeof(struct btree_manager));
    manager->max_task = n_processors;
    manager->branching = branching;
    while ( pthread_rwlock_init(&manager->rwlock, NULL) != 0);
    pthread_mutex_init(&manager->change_thread_counter_mutex, NULL);
    pthread_cond_init(&manager->wait_cond, NULL);
    manager->thread_counter = 0;
    manager->btree = NULL;
    manager->btree_size = 0;
    return manager;
}


void close_store(void * helper) {
    // Your code here
    if(helper == NULL){
        return;
    }
    struct btree_manager *manager = (struct btree_manager*) helper;

    free_pre_order(manager->btree);
    pthread_mutex_destroy(&manager->change_thread_counter_mutex);
    pthread_rwlock_destroy(&manager->rwlock);
    pthread_cond_destroy(&manager->wait_cond);
    free(manager);
}

int btree_insert(uint32_t key, void * plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void * helper) {
    //one plaintext element is u64, a chunk is u64
    if(helper == NULL){
        return NULLHELPER;
    }
    struct btree_manager *manager = (struct btree_manager*) helper;

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    while (manager->thread_counter == manager->max_task){
        pthread_cond_wait(&manager->wait_cond, &manager->change_thread_counter_mutex);
    }
    manager->thread_counter++;
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    uint16_t convert = count/8;
    if(convert * 8 != count)
        convert++;
    uint64_t * cipher = (uint64_t*) malloc(sizeof(uint64_t) * convert);
    uint64_t * text = (uint64_t*) malloc(sizeof(uint64_t) * convert);
    memset(text, 0, sizeof(uint64_t)*convert);
    memcpy(text, plaintext, count);
    encrypt_tea_ctr(text, encryption_key, nonce, cipher, convert);
    free(text);

    pthread_rwlock_wrlock(&manager->rwlock);
    int result = basic_btree_insert(manager, key, count, encryption_key, nonce, cipher);
    if(result == KEYEXIST){
        free(cipher);
    }
    pthread_rwlock_unlock(&manager->rwlock);

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    manager->thread_counter--;
    pthread_cond_signal(&manager->wait_cond);
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    return result;
}

int btree_retrieve(uint32_t key, struct info * found, void * helper) {
    // Your code here
    if(helper == NULL){
        return NULLHELPER;
    }
    struct btree_manager *manager = (struct btree_manager*) helper;

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    while (manager->thread_counter == manager->max_task){
        pthread_cond_wait(&manager->wait_cond, &manager->change_thread_counter_mutex);
    }
    manager->thread_counter++;
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    pthread_rwlock_rdlock(&manager->rwlock);
    int result = basic_btree_search(manager, key, found);
    pthread_rwlock_unlock(&manager->rwlock);

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    manager->thread_counter--;
    pthread_cond_signal(&manager->wait_cond);
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    return result;
}

int btree_decrypt(uint32_t key, void * output, void * helper) {
    // Your code here
    if(helper == NULL){
        return NULLHELPER;
    }
    struct btree_manager *manager = (struct btree_manager*) helper;

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    while (manager->thread_counter == manager->max_task){
        pthread_cond_wait(&manager->wait_cond, &manager->change_thread_counter_mutex);
    }
    manager->thread_counter++;
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    pthread_rwlock_rdlock(&manager->rwlock);
    struct info *found;
    found = malloc(sizeof(struct info));
    int result = basic_btree_search(manager, key, found);
    if(result == TRUE){
        uint16_t convert = found->size/8;
        if(convert * 8 != found->size)
            convert++;
        uint64_t *plaintext = (uint64_t *) malloc(sizeof(uint64_t)*convert);
        decrypt_tea_ctr(found->data, found->key, found->nonce, plaintext, convert);
        memcpy(output, plaintext, found->size);
        free(plaintext);
    }
    free(found);
    pthread_rwlock_unlock(&manager->rwlock);

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    manager->thread_counter--;
    pthread_cond_signal(&manager->wait_cond);
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);
    return result;
}

int btree_delete(uint32_t key, void * helper) {
    // Your code here
    if(helper == NULL){
        return NULLHELPER;
    }
    struct btree_manager *manager = (struct btree_manager*) helper;

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    while (manager->thread_counter == manager->max_task){
        pthread_cond_wait(&manager->wait_cond, &manager->change_thread_counter_mutex);
    }
    manager->thread_counter++;
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    pthread_rwlock_wrlock(&manager->rwlock);
    int result = basic_btree_delete(manager, key);
    pthread_rwlock_unlock(&manager->rwlock);

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    manager->thread_counter--;
    pthread_cond_signal(&manager->wait_cond);
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    return result;
}

uint64_t btree_export(void * helper, struct node ** list) {
    // Your code here
    if(helper == NULL){
        return NULLHELPER;
    }
    struct btree_manager *manager = (struct btree_manager *) helper;
    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    while (manager->thread_counter == manager->max_task){
        pthread_cond_wait(&manager->wait_cond, &manager->change_thread_counter_mutex);
    }
    manager->thread_counter++;
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    pthread_rwlock_rdlock(&manager->rwlock);
    uint16_t order = 0;
    if(manager->btree != NULL){
        (*list) = malloc(sizeof(struct node)*manager->btree_size);
        pre_order_travel(manager->btree, list, &order);
    } else {
        return 0;
    }
    pthread_rwlock_unlock(&manager->rwlock);

    pthread_mutex_lock(&manager->change_thread_counter_mutex);
    manager->thread_counter--;
    pthread_cond_signal(&manager->wait_cond);
    pthread_mutex_unlock(&manager->change_thread_counter_mutex);

    return manager->btree_size;
}

void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4]){
    uint32_t sum = 0;
    uint32_t delta = 0x9E3779B9;
    uint32_t temp[6];
    cipher[0] = plain[0];
    cipher[1] = plain[1];
    for(uint16_t loop_time = 0; loop_time < 1024; loop_time++){
        sum = sum + delta; // Overflow will perform the same effect as mode 2^32
        temp[0] = (cipher[1] << 4) + key[0];
        temp[1] = cipher[1] + sum;
        temp[2] = (cipher[1] >> 5) + key[1];
        cipher[0] = cipher[0] + (temp[0] ^ temp[1] ^ temp[2]);

        temp[3] = (cipher[0] << 4) + key[2];
        temp[4] = cipher[0] + sum;
        temp[5] = (cipher[0] >> 5) + key[3];
        cipher[1] = cipher[1] + (temp[3] ^ temp[4] ^ temp[5]);
    }
}

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4]){
    uint32_t sum = 0xDDE6E400;
    uint32_t delta = 0x9E3779B9;
    uint32_t temp[6] = {0,0,0,0,0,0};
    for(uint16_t loop_time = 0; loop_time < 1024; loop_time++){
        temp[3] = (cipher[0] << 4) + key[2];
        temp[4] = cipher[0] + sum;
        temp[5] = (cipher[0] >> 5) + key[3];

        cipher[1] = cipher[1] - (temp[3] ^ temp[4] ^ temp[5]);
        temp[0] = (cipher[1] << 4) + key[0];
        temp[1] = cipher[1] + sum;
        temp[2] = (cipher[1] >> 5) + key[1];
        cipher[0] = cipher[0] - (temp[0] ^ temp[1] ^ temp[2]);

        sum = sum - delta;
    }
    plain[0] = cipher[0];
    plain[1] = cipher[1];
}

void encrypt_tea_ctr(uint64_t * plain, uint32_t key[4], uint64_t nonce, uint64_t * cipher, uint32_t num_blocks){
    uint64_t tmp[2];
    for(uint32_t index = 0; index < num_blocks; index++){
        tmp[0] = index ^ nonce;
        encrypt_tea((uint32_t *) &tmp[0], (uint32_t *) &tmp[1], key);
        cipher[index] = tmp[1] ^ plain[index];
    }
}

void decrypt_tea_ctr(uint64_t * cipher, uint32_t key[4], uint64_t nonce, uint64_t * plain, uint32_t num_blocks){
    uint64_t tmp[2];
    for(uint32_t index = 0; index < num_blocks; index++){
        tmp[0] = index ^ nonce;
        encrypt_tea((uint32_t *) &tmp[0], (uint32_t *) &tmp[1], key);
        plain[index] = tmp[1] ^ cipher[index];
    }
}

struct btree_node * basic_node_init(uint16_t branching){
    uint16_t maximum_array_size = branching;
    struct btree_node * newNode = (struct btree_node *) malloc(sizeof(struct btree_node));
    newNode->array_size = 0;
    newNode->keys_array = (struct key_item *) malloc(sizeof(struct key_item) * maximum_array_size);//keys_array can store as much as branching node for temporary
    for(uint16_t i = 0; i < maximum_array_size; ++i){
        newNode->keys_array[i].left_child = NULL;
        newNode->keys_array[i].right_child = NULL;
    }
    newNode->parent_node = NULL;
    newNode->left_parent_key_item = NULL;
    newNode->right_parent_key_item = NULL;
    return newNode;
}

int basic_btree_insert(struct btree_manager *manager, uint32_t key_value, uint32_t size, uint32_t *key, uint64_t nonce,
                       void *data) {
    if(manager->btree == NULL){
        //printf("btree is NULL\n");
        manager->btree = basic_node_init(manager->branching);
        manager->btree_size++;
        manager->btree->isLeaf = TRUE;
    }

    struct btree_node *cursor = (struct btree_node *)manager->btree;
    uint16_t target_index = 0;
    struct btree_node * target_node = NULL;
    while (cursor != NULL){
        uint16_t index = 0;
        if(cursor->array_size == 0){
            target_node = cursor;
            target_index = 0;
            break;
        }
        while (index < cursor->array_size){ // In this part, select the correct children.
            if(cursor->keys_array[index].key_value == key_value) //In this case, key_value already existed.
                return KEYEXIST;
            if(index == 0 && cursor->keys_array[0].key_value > key_value){ // If it is the first one.
                target_node = cursor;
                target_index = index;
                cursor = cursor->keys_array[0].left_child;
                break;
            } else if(index + 1 < cursor->array_size){ // When it is not the last one in the array.
                if(cursor->keys_array[index].key_value < key_value && cursor->keys_array[index + 1].key_value > key_value) //If the key_value is between current key_item and the next one, go further.
                {
                    target_node = cursor;
                    target_index = index + 1;
                    cursor = cursor->keys_array[index].right_child;
                    break;
                } else {
                    index++;
                }
            } else { // If it is the last one.
                target_node = cursor;
                target_index = index + 1;
                cursor = cursor->keys_array[index].right_child; // If the next key item is not exist, go further.
                break;
            }
        }
    }
    insert_to_array_index(target_node, target_index, key_value);
    target_node->keys_array[target_index].data = data;
    target_node->keys_array[target_index].nonce = nonce;
    target_node->keys_array[target_index].key[0] = key[0];
    target_node->keys_array[target_index].key[1] = key[1];
    target_node->keys_array[target_index].key[2] = key[2];
    target_node->keys_array[target_index].key[3] = key[3];
    target_node->keys_array[target_index].size = size;

    target_node->keys_array[target_index].left_child = NULL;
    target_node->keys_array[target_index].right_child = NULL;

    spilt_node(manager, target_node);
    return SUCCESS;
}

int basic_btree_search(struct btree_manager *manager, uint32_t key_value, struct info *found) {
    if(manager->btree == NULL){
        return FALSE;
    }
    struct btree_node * cursor = manager->btree;
    while (cursor != NULL){
        uint16_t index = 0;
        if(cursor->array_size == 0){
            return FALSE;
        }
        while (index < cursor->array_size){ // In this part, select the correct children.
            if(cursor->keys_array[index].key_value == key_value) { //In this case, key_value is found.
                found->size = cursor->keys_array[index].size;
                found->data = cursor->keys_array[index].data;
                found->nonce = cursor->keys_array[index].nonce;
                found->key[0] = cursor->keys_array[index].key[0];
                found->key[1] = cursor->keys_array[index].key[1];
                found->key[2] = cursor->keys_array[index].key[2];
                found->key[3] = cursor->keys_array[index].key[3];
                return TRUE;
            }
            if(index == 0 && cursor->keys_array[0].key_value > key_value){ // If it is the first one.
                cursor = cursor->keys_array[0].left_child;
                break;
            } else if(index + 1 < cursor->array_size){ // When it is not the last one in the array.
                if(cursor->keys_array[index].key_value < key_value && cursor->keys_array[index + 1].key_value > key_value){ //If the key_value is between current key_item and the next one, go further.
                    cursor = cursor->keys_array[index].right_child;
                    break;
                } else {
                    index++;
                }
            } else { // If it is the last one.
                cursor = cursor->keys_array[index].right_child; // If the next key item is not exist, go further.
                break;
            }
        }
    }
    return FALSE;
}

void insert_to_array_index(struct btree_node *target_node, uint16_t target_index, uint32_t insert_key) {
    target_node->array_size++;
    if(target_node->array_size == 0){
        target_node->keys_array[0].key_value = insert_key;
        return;
    }
    for(uint16_t from = target_node->array_size - 1; from > target_index; --from){
        target_node->keys_array[from].left_child = target_node->keys_array[from - 1].left_child;
        target_node->keys_array[from].right_child = target_node->keys_array[from - 1].right_child;

        target_node->keys_array[from] = target_node->keys_array[from - 1];
        copy_keys(&target_node->keys_array[from], &target_node->keys_array[from - 1]);
        if(target_node->isLeaf == FALSE){
            target_node->keys_array[from].left_child->right_parent_key_item = &target_node->keys_array[from];
            target_node->keys_array[from].right_child->left_parent_key_item = &target_node->keys_array[from];
        }
    }
    target_node->keys_array[target_index].key_value = insert_key;
    if(target_index - 1 >= 0){
        target_node->keys_array[target_index].left_child = target_node->keys_array[target_index-1].right_child;
    }
    if(target_index + 1 < target_node->array_size){
        target_node->keys_array[target_index].right_child = target_node->keys_array[target_index + 1].left_child;
    }
}

void spilt_node(struct btree_manager *manager, struct btree_node *target_node) {
    if(target_node->array_size < manager->branching){
        return;
    }
    uint16_t mid_index = (manager->branching - 1) / 2;
    struct btree_node * new_split_node = basic_node_init(manager->branching);
    manager->btree_size++;

    new_split_node->isLeaf = target_node->isLeaf;

    for(uint16_t index = mid_index + 1; index < target_node->array_size; ++index){ //copy target to new_split_node
        new_split_node->keys_array[new_split_node->array_size] = target_node->keys_array[index];
        copy_keys(&new_split_node->keys_array[new_split_node->array_size], &target_node->keys_array[index]);
        if(target_node->isLeaf == FALSE){
            new_split_node->keys_array[new_split_node->array_size].left_child->right_parent_key_item = &new_split_node->keys_array[new_split_node->array_size];
            new_split_node->keys_array[new_split_node->array_size].left_child->parent_node = new_split_node;
            new_split_node->keys_array[new_split_node->array_size].right_child->left_parent_key_item = &new_split_node->keys_array[new_split_node->array_size];
            new_split_node->keys_array[new_split_node->array_size].right_child->parent_node = new_split_node;
            target_node->keys_array[index].left_child = NULL;
            target_node->keys_array[index].right_child = NULL;
        }
        new_split_node->array_size++;
    }

    if(target_node->isLeaf == FALSE){
        target_node->keys_array[mid_index].left_child->right_parent_key_item = NULL;
        target_node->keys_array[mid_index].right_child->left_parent_key_item = NULL;
        // still need last key_item's left child.
        target_node->keys_array[mid_index].right_child = NULL;
        target_node->keys_array[mid_index].left_child = NULL;
    }

    target_node->array_size = target_node->array_size - new_split_node->array_size - 1; // resize target_node
    if(target_node->parent_node != NULL){ //If target_node has parent, don't need to create a new node, just add it into it's parent's key_array.
        if(target_node->left_parent_key_item == NULL){ // If target_node has not left parent, target_node's right parent must be the first one in the parent's array.
            insert_to_array_index(target_node->parent_node, 0, target_node->keys_array[mid_index].key_value);
            copy_keys(&target_node->parent_node->keys_array[0], &target_node->keys_array[mid_index]);
            target_node->parent_node->keys_array[0].left_child = target_node;
            target_node->parent_node->keys_array[0].right_child = new_split_node;
            target_node->parent_node->keys_array[1].left_child = new_split_node;

            new_split_node->right_parent_key_item = target_node->right_parent_key_item;
            new_split_node->left_parent_key_item = &target_node->parent_node->keys_array[0];
            target_node->right_parent_key_item = &target_node->parent_node->keys_array[0];
            new_split_node->parent_node = target_node->parent_node;
        } else {
            uint16_t target_index;
            for(target_index = 0; target_index < target_node->parent_node->array_size; target_index++){
                if(target_node->parent_node->keys_array[target_index].key_value == target_node->left_parent_key_item->key_value)
                    break;
            }

            if(target_index + 1 >= manager->branching){
                fprintf(stderr, "error, now target size is %d, allow %d\n",target_node->parent_node->array_size, manager->branching);
            }

            insert_to_array_index(target_node->parent_node, target_index + 1, target_node->keys_array[mid_index].key_value);
            copy_keys(&target_node->parent_node->keys_array[target_index + 1], &target_node->keys_array[mid_index]);

            target_node->parent_node->keys_array[target_index + 1].left_child = target_node;
            target_node->parent_node->keys_array[target_index].right_child = target_node;

            target_node->parent_node->keys_array[target_index + 1].right_child = new_split_node;

            if(target_index + 2 < target_node->parent_node->array_size) {
                //fprintf(stderr, "special case\n");
                target_node->parent_node->keys_array[target_index + 2].left_child = new_split_node;
            }

            new_split_node->right_parent_key_item = target_node->right_parent_key_item;
            new_split_node->left_parent_key_item = &(target_node->parent_node->keys_array[target_index + 1]);
            target_node->right_parent_key_item = &(target_node->parent_node->keys_array[target_index + 1]); //target_node's left parent key_item doesn't change
            new_split_node->parent_node = target_node->parent_node;
        }
        spilt_node(manager, target_node->parent_node);
    } else { // target_node has not parent, have to generate a new parent_node
        struct btree_node * new_parent_node = basic_node_init(manager->branching);
        manager->btree_size++;
        new_parent_node->isLeaf = FALSE;
        insert_to_array_index(new_parent_node, 0, target_node->keys_array[mid_index].key_value);
        copy_keys(&new_parent_node->keys_array[0], &target_node->keys_array[mid_index]);

        new_parent_node->keys_array[0].left_child = target_node;
        new_parent_node->keys_array[0].right_child = new_split_node;



        target_node->right_parent_key_item = &(new_parent_node->keys_array[0]);
        new_split_node->left_parent_key_item = &(new_parent_node->keys_array[0]);
        target_node->parent_node = new_parent_node;
        new_split_node->parent_node = new_parent_node;

        manager->btree = new_parent_node;
        return;
    }
}

int basic_btree_delete(struct btree_manager *manager, uint32_t key_value){
    if(manager->btree == NULL){
        return NOSUCHKEY;
    }

    struct btree_node * cursor = manager->btree;
    struct key_item * target_key_item = NULL;
    struct btree_node * target_node = NULL;
    uint16_t target_index;
    while (cursor != NULL){
        uint16_t index = 0;
        if(cursor->array_size == 0){
            return NOSUCHKEY;
        }
        while (index < cursor->array_size){ // In this part, select the correct children.
            if(cursor->keys_array[index].key_value == key_value) { //In this case, key_value is found.
                target_key_item = &cursor->keys_array[index];
                target_node = cursor;
                target_index = index;
                break;
            }
            if(index == 0 && cursor->keys_array[0].key_value > key_value){ // If it is the first one.
                cursor = cursor->keys_array[0].left_child;
                break;
            } else if(index + 1 < cursor->array_size){ // When it is not the last one in the array.
                if(cursor->keys_array[index].key_value < key_value && cursor->keys_array[index + 1].key_value > key_value){ //If the key_value is between current key_item and the next one, go further.
                    cursor = cursor->keys_array[index].right_child;
                    break;
                } else {
                    index++;
                }
            } else { // If it is the last one.
                cursor = cursor->keys_array[index].right_child; // If the next key item is not exist, go further.
                break;
            }
        }
        if(target_key_item != NULL){
            break;
        }
    }
    if(target_key_item == NULL){
        return NOSUCHKEY;
    }
    if(target_node->isLeaf == FALSE){
        target_node = target_key_item->left_child;
        while (target_node->isLeaf == FALSE)
            target_node = target_node->keys_array[target_node->array_size - 1].right_child;
        //swap two number, target_key_item should be delete, swap with target_node...key_value
        target_key_item->key_value = target_node->keys_array[target_node->array_size - 1].key_value;
        target_node->array_size--; // Internal node always swap with the largest node in the left subtree, so it will always be the rightmost node in the array. Since it is a leaf, we don't need to reset it's child.
        free(target_node->keys_array[target_node->array_size].data);
    } else {
        free(target_node->keys_array[target_index].data);
        delete_from_array_index(target_node, target_index);
    }



    merge_node(manager, target_node);

    return SUCCESS;
}

void delete_from_array_index(struct btree_node *target_node, uint16_t target_index){
    target_node->array_size--;
    for(; target_index < target_node->array_size; target_index++){ // Also move the empty node, node we delete always satisfy array_size < branching - 1, so it is safe to touch array_size + 1
        target_node->keys_array[target_index].left_child = target_node->keys_array[target_index+1].left_child;
        target_node->keys_array[target_index].right_child = target_node->keys_array[target_index+1].right_child;
        target_node->keys_array[target_index] = target_node->keys_array[target_index+1];
        if(target_node->isLeaf != TRUE){
            if(target_node->isLeaf == FALSE){
                if(target_node->keys_array[target_index].left_child!=NULL)//target node's left child has been freed be used again
                    target_node->keys_array[target_index].left_child->right_parent_key_item = &target_node->keys_array[target_index];
                if(target_node->keys_array[target_index].right_child!=NULL)
                    target_node->keys_array[target_index].right_child->left_parent_key_item = &target_node->keys_array[target_index];
            }
        }
    }
}

void merge_node(struct btree_manager *manager, struct btree_node *target_node){
    if(target_node->isLeaf == TRUE){
        //printf("target node is leaf\n");
        if(target_node == manager->btree) // If this node is the root
        {
            //printf("it is a root\n");
            if(target_node->array_size > 0)
                return;
            free(target_node->keys_array);
            free(target_node);
            manager->btree_size--;
            manager->btree = NULL;
            return;
        } else {
            if(target_node->array_size >= (ceil(manager->branching/2.0) - 1)){
                return;
            }
            //Deletion Operation 4)
            if(target_node->left_parent_key_item != NULL){ // From left to right
                if(target_node->left_parent_key_item->left_child->array_size > (ceil(manager->branching/2.0) - 1)){ // Target_node is leaf, don't need to consider it's child.
                    insert_to_array_index(target_node, 0, target_node->left_parent_key_item->key_value);
                    copy_keys(&target_node->keys_array[0], target_node->left_parent_key_item);
                    copy_keys(target_node->left_parent_key_item, &target_node->left_parent_key_item->left_child->keys_array[target_node->left_parent_key_item->left_child->array_size - 1]);
                    target_node->left_parent_key_item->left_child->keys_array[target_node->left_parent_key_item->left_child->array_size - 1].data = NULL;
                    target_node->left_parent_key_item->left_child->array_size--;
                    return;
                }
            }
            if(target_node->right_parent_key_item != NULL){
                if(target_node->right_parent_key_item->right_child->array_size > (ceil(manager->branching/2.0) - 1)){
                    //printf("Can borrow from right sibling\n");
                    insert_to_array_index(target_node, target_node->array_size, target_node->right_parent_key_item->key_value);
                    copy_keys(&target_node->keys_array[target_node->array_size - 1], target_node->right_parent_key_item);
                    copy_keys(target_node->right_parent_key_item, &target_node->right_parent_key_item->right_child->keys_array[0]);
                    delete_from_array_index(target_node->right_parent_key_item->right_child, 0);
                    return;
                }
            }
            //printf("Can't borrow from siblings\n");
        }
    } else { //In this case, target_node is an internal.
        //printf("It is a internal node\n");
        if(target_node == manager->btree) // If this node is the root
        {
            if(target_node->array_size > 0)
                return;
            manager->btree = target_node->keys_array[0].left_child;
            free(target_node->keys_array);
            free(target_node);
            manager->btree_size--;
            if(manager->btree_size == 0){
                manager->btree = NULL;
            }
            return;
        }
        if(target_node->array_size >= (ceil(manager->branching/2.0) - 1)){
            return;
        }
        if(target_node->left_parent_key_item != NULL){ //From left to right
            if(target_node->left_parent_key_item->left_child->array_size > (ceil(manager->branching/2.0) - 1)){
                //printf("Can borrow from left sibling\n");

                insert_to_array_index(target_node, 0, target_node->left_parent_key_item->key_value);
                copy_keys(&target_node->keys_array[0], target_node->left_parent_key_item);
                copy_keys(target_node->left_parent_key_item, &target_node->left_parent_key_item->left_child->keys_array[target_node->left_parent_key_item->left_child->array_size - 1]);
                target_node->left_parent_key_item->left_child->keys_array[target_node->left_parent_key_item->left_child->array_size - 1].data = NULL;
                target_node->left_parent_key_item->left_child->array_size--;

                if(target_node->array_size == 1){
                    target_node->keys_array[0].right_child = target_node->keys_array[0].left_child;
                    target_node->keys_array[0].right_child->right_parent_key_item = NULL;
                    target_node->keys_array[0].left_child = NULL;
                } else {
                    target_node->keys_array[0].right_child = target_node->keys_array[1].left_child;
                    target_node->keys_array[0].right_child->right_parent_key_item = &target_node->keys_array[1];
                }

                target_node->keys_array[0].right_child->left_parent_key_item = &target_node->keys_array[0];
                target_node->keys_array[0].left_child = target_node->left_parent_key_item->left_child->keys_array[target_node->left_parent_key_item->left_child->array_size].right_child; // Borrow
                target_node->keys_array[0].left_child->right_parent_key_item = &target_node->keys_array[0]; // Change parent
                target_node->keys_array[0].left_child->left_parent_key_item = NULL;
                target_node->keys_array[0].left_child->parent_node = target_node;
                target_node->left_parent_key_item->left_child->keys_array[target_node->left_parent_key_item->left_child->array_size].right_child = NULL;
                target_node->left_parent_key_item->left_child->keys_array[target_node->left_parent_key_item->left_child->array_size].left_child = NULL;
                target_node->left_parent_key_item->left_child->keys_array[target_node->left_parent_key_item->left_child->array_size].data = NULL;

                return;
            }
        }
        if(target_node->right_parent_key_item != NULL){ // From right to left
            if(target_node->right_parent_key_item->right_child->array_size > (ceil(manager->branching/2.0) - 1)){
                //printf("Can borrow from right sibling\n");
                struct btree_node *temp_node = target_node->right_parent_key_item->right_child->keys_array[0].left_child;

                insert_to_array_index(target_node, target_node->array_size, target_node->right_parent_key_item->key_value);

                if(target_node->array_size == 1){
                    target_node->keys_array[0].left_child->right_parent_key_item = &target_node->keys_array[0];
                } else {
                    target_node->keys_array[target_node->array_size - 1].left_child = target_node->keys_array[target_node->array_size - 2].right_child;
                }

                copy_keys(&target_node->keys_array[target_node->array_size - 1], target_node->right_parent_key_item);
                copy_keys(target_node->right_parent_key_item, &target_node->right_parent_key_item->right_child->keys_array[0]);
                delete_from_array_index(target_node->right_parent_key_item->right_child, 0);

                target_node->keys_array[target_node->array_size - 1].right_child = temp_node;
                temp_node->left_parent_key_item = &target_node->keys_array[target_node->array_size - 1];

                target_node->keys_array[target_node->array_size - 1].left_child->right_parent_key_item = &target_node->keys_array[target_node->array_size - 1];

                temp_node->right_parent_key_item = NULL;
                temp_node->parent_node = target_node;

                return;
            }
        }
    }
    // Deletion Operation 6)
    // If left neighbour and right neighbour both don't have enough key_item.
    if(target_node->left_parent_key_item != NULL){ //target_node is *not* the leftmost node, from left to right.
        struct btree_node *sibling = target_node->left_parent_key_item->left_child;
        // Move parent key_value into target_node
        insert_to_array_index(target_node, 0, target_node->left_parent_key_item->key_value);
        copy_keys(&target_node->keys_array[0], target_node->left_parent_key_item);

        //printf("Insert [%d] into target\n", target_node->left_parent_key_item->key_value);
        if(target_node->isLeaf == FALSE){
            if(target_node->array_size == 1){
                target_node->keys_array[0].right_child = target_node->keys_array[0].left_child;
                target_node->keys_array[0].right_child->right_parent_key_item = NULL;
                target_node->keys_array[0].left_child = NULL;
            } else {
                target_node->keys_array[0].right_child = target_node->keys_array[1].left_child;
                target_node->keys_array[0].right_child->right_parent_key_item = &target_node->keys_array[1];
            }
            target_node->keys_array[0].left_child = sibling->keys_array[target_node->left_parent_key_item->left_child->array_size - 1].right_child;
            target_node->keys_array[0].left_child->right_parent_key_item = &target_node->keys_array[0];
            target_node->keys_array[0].left_child->left_parent_key_item = NULL;
            target_node->keys_array[0].left_child->parent_node = target_node;
            target_node->keys_array[0].right_child->parent_node = target_node;
        }

        if(sibling->array_size != 0){
            uint16_t previous = sibling->array_size;
            int index = sibling->array_size;
            index--;
            for(; index >= 0; index--){
                //printf("now index is %d\n", index);
                insert_to_array_index(target_node, 0, sibling->keys_array[index].key_value);
                copy_keys(&target_node->keys_array[0], &sibling->keys_array[index]);
                if(target_node->isLeaf == FALSE){
                    target_node->keys_array[0].right_child = target_node->keys_array[1].left_child;
                    target_node->keys_array[0].right_child->left_parent_key_item = &target_node->keys_array[0];
                    target_node->keys_array[0].left_child = sibling->keys_array[index].left_child;
                    target_node->keys_array[0].left_child->right_parent_key_item = &target_node->keys_array[0];
                    target_node->keys_array[0].left_child->left_parent_key_item = NULL;
                    target_node->keys_array[0].left_child->parent_node = target_node;
                    target_node->keys_array[0].right_child->parent_node = target_node;
                }
            }
        }

        uint16_t target_index;
        for(target_index = 0; target_index < target_node->parent_node->array_size; target_index++){
            if(target_node->parent_node->keys_array[target_index].key_value == target_node->left_parent_key_item->key_value)
                break;
        }
        // The target node is the right child of the node we found
        delete_from_array_index(target_node->parent_node, target_index); //remove key_item from the parent

        if(target_node->parent_node->array_size == 0){
            target_node->parent_node->keys_array[0].left_child = target_node;
            target_node->right_parent_key_item = NULL;
            target_node->left_parent_key_item = NULL;
        } else {
            if(target_index > 0) {
                target_node->parent_node->keys_array[target_index - 1].right_child = target_node;
                target_node->left_parent_key_item = &target_node->parent_node->keys_array[target_index - 1];
                if(target_index >= target_node->array_size){
                    target_node->right_parent_key_item = NULL;
                } else {
                    target_node->right_parent_key_item = &target_node->parent_node->keys_array[target_index];
                }
            } else {
                target_node->left_parent_key_item = NULL;
                target_node->right_parent_key_item = &target_node->parent_node->keys_array[0];
                target_node->parent_node->keys_array[0].left_child = target_node;
            }
        }

        free(sibling->keys_array);
        free(sibling);
        manager->btree_size--;
        merge_node(manager, target_node->parent_node);
    } else { // From right to left.
        //printf("Sibling test fail, merge with the right sibling\n");



        struct btree_node *sibling = target_node->right_parent_key_item->right_child;
        target_node->keys_array[0];
        insert_to_array_index(target_node, target_node->array_size, target_node->right_parent_key_item->key_value);
        copy_keys(&target_node->keys_array[target_node->array_size - 1], target_node->right_parent_key_item);
        //printf("Insert [%d] into target\n", target_node->right_parent_key_item->key_value);
        if(target_node->isLeaf == FALSE){
            target_node->keys_array[target_node->array_size - 1].right_child = sibling->keys_array[0].left_child;
            target_node->keys_array[target_node->array_size - 1].right_child->parent_node = target_node;
            if(target_node->array_size - 1 != 0){
                target_node->keys_array[target_node->array_size - 1].left_child = target_node->keys_array[target_node->array_size - 2].right_child;
             }
            //if the size of it is 0, it will also have left child.
            target_node->keys_array[target_node->array_size - 1].left_child->right_parent_key_item = &target_node->keys_array[target_node->array_size - 1];
            target_node->keys_array[target_node->array_size - 1].right_child->left_parent_key_item = &target_node->keys_array[target_node->array_size - 1];
        }
        
        for(uint16_t index = 0; index < target_node->right_parent_key_item->right_child->array_size; index++){
            insert_to_array_index(target_node, target_node->array_size, sibling->keys_array[index].key_value);
            copy_keys(&target_node->keys_array[target_node->array_size - 1], &sibling->keys_array[index]);
            if(target_node->isLeaf == FALSE){
                target_node->keys_array[target_node->array_size - 1].right_child = sibling->keys_array[index].right_child;
                target_node->keys_array[target_node->array_size - 1].right_child->left_parent_key_item = &target_node->keys_array[target_node->array_size - 1];
                target_node->keys_array[target_node->array_size - 1].left_child = sibling->keys_array[index].left_child;
                target_node->keys_array[target_node->array_size - 1].left_child->right_parent_key_item = &target_node->keys_array[target_node->array_size - 1];
                target_node->keys_array[target_node->array_size - 1].left_child->left_parent_key_item = &target_node->keys_array[target_node->array_size - 2];
                target_node->keys_array[target_node->array_size - 1].right_child->parent_node = target_node;
                target_node->keys_array[target_node->array_size - 1].left_child->parent_node = target_node;
//                sibling->keys_array[index].right_child = NULL;
//                sibling->keys_array[index].left_child = NULL;
//                sibling->keys_array[index].data = NULL;
            }
        }

        uint16_t target_index;
        for(target_index = 0; target_index < target_node->parent_node->array_size; target_index++){//target node must have right parent now
            if(target_node->parent_node->keys_array[target_index].key_value == target_node->right_parent_key_item->key_value)
                break;
        }
        delete_from_array_index(target_node->parent_node, target_index); //remove key_item from the parent

        if(target_node->parent_node->array_size == 0){
            target_node->parent_node->keys_array[0].left_child = target_node;
            target_node->right_parent_key_item = NULL;
            target_node->left_parent_key_item = NULL;
        } else {
            if(target_index == 0){
                target_node->parent_node->keys_array[0].left_child = target_node;
                target_node->right_parent_key_item = &target_node->parent_node->keys_array[0];
                target_node->left_parent_key_item = NULL;
            } else if (target_index < target_node->array_size) {
                target_node->parent_node->keys_array[target_index].left_child = target_node;
                target_node->right_parent_key_item = &target_node->parent_node->keys_array[target_index];
            } else {
                target_node->right_parent_key_item = NULL;
            }
        }

        free(sibling->keys_array);
        free(sibling);
        manager->btree_size--;
        merge_node(manager, target_node->parent_node);
    }
}

void copy_keys(struct key_item* target, struct key_item* source){
    target->key_value = source->key_value;
    target->key[0] = source->key[0];
    target->key[1] = source->key[1];
    target->key[2] = source->key[2];
    target->key[3] = source->key[3];
    target->nonce = source->nonce;
    target->data = source->data;
    target->size = source->size;
}

void pre_order_travel(struct btree_node *target_node, struct node ** list, uint16_t *order) {
    (*list)[(*order)].num_keys = target_node->array_size;
    (*list)[(*order)].keys = malloc(sizeof(uint32_t)*target_node->array_size);
    for(uint16_t index = 0; index < target_node->array_size; index++){
        (*list)[(*order)].keys[index] = target_node->keys_array[index].key_value;
    }
    (*order)++;
    if(target_node->isLeaf == FALSE){
        for (uint16_t index = 0; index < target_node->array_size; ++index) {
            pre_order_travel(target_node->keys_array[index].left_child, list, order);
        }
        pre_order_travel(target_node->keys_array[target_node->array_size - 1].right_child, list, order);
    }
}

void free_pre_order(struct btree_node *target_node){
    if(target_node == NULL){
        return;
    }
    if(target_node->isLeaf == FALSE){
        for (uint16_t index = 0; index < target_node->array_size; ++index) {
            //printf("leftward: command from parent [%d]\n", target_node->keys_array[index].key_value);
            free_pre_order(target_node->keys_array[index].left_child);
        }
        //printf("rightward: command from parent [%d]\n", target_node->keys_array[target_node->array_size - 1].key_value);
        free_pre_order(target_node->keys_array[target_node->array_size - 1].right_child);
    }
    for (uint16_t index = 0; index < target_node->array_size; ++index) {
        //printf("gonna free [%d]\n", target_node->keys_array[index].key_value);
        free(target_node->keys_array[index].data);
        //printf("free done\n");
    }
    free(target_node->keys_array);
    free(target_node);
}
