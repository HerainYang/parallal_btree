
#include <assert.h>
#include <string.h>
#include "btreestore.h"
int main() {
    struct btree_manager *manager;
    manager = init_store(3, 8);

    uint64_t *plain = malloc(sizeof(uint64_t) * 2);



    uint64_t nonce = 0x0123456789ABCDEF;

    uint32_t key1[4];
    key1[0] = 0xAAAAAAAA;
    key1[1] = 0xBBBBBBBB;
    key1[2] = 0xCCCCCCCC;
    key1[3] = 0xDDDDDDDD;


    plain[0] = 0x2828282828282828;
    plain[1] = 0x8282828282828282;

    //test adding from 0 to 30 then delete from 0 to 30
    for(int i = 0; i < 30; i++){
        assert(btree_insert(i, plain, 16, key1, nonce, manager) == 0);
    }

    for(int i = 0; i < 30; i++){
        assert(btree_delete(i, manager) == 0);
    }

    //test helper is NULL

    assert(btree_insert(0, plain, 16, key1, nonce, manager) == 0);


    assert(btree_delete(0, manager) == 0);

    //test btree is NULL
    assert(btree_export(manager, NULL) == 0);


    free(plain);

    close_store(manager);

    return 0;
}

