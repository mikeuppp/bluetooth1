#ifndef PAIRING_H
#define PAIRING_H

#include "bt_defs.h"
#include <stdbool.h>
#include <stdint.h>

#define LINK_KEY_LEN 16
#define MAX_LINK_KEYS 256

typedef struct {
    bt_addr_t addr;
    uint8_t key[LINK_KEY_LEN];
    uint8_t type;
} link_key_record_t;

typedef struct {
    link_key_record_t rec[MAX_LINK_KEYS];
    size_t count;
    char path[512];
} key_db_t;

typedef struct {
    int hci_fd;
    int dev_id;
    key_db_t db;
    bool auto_confirm;
    bool have_passkey;
    uint32_t passkey;
    char pin[17];
    uint8_t io_capability;
    uint8_t auth_requirement;
    int timeout_sec;
} pairing_ctx_t;

typedef struct {
    bt_addr_t addr;
    uint16_t handle;
    bool connected;
    bool authenticated;
    bool encrypted;
    bool link_key_seen;
    uint8_t last_status;
} peer_state_t;

int bt_addr_parse(const char *s, bt_addr_t *out);
void bt_addr_format(const bt_addr_t *a, char out[18]);
bool bt_addr_equal(const bt_addr_t *a, const bt_addr_t *b);

int key_db_load(key_db_t *db, const char *path);
int key_db_save(const key_db_t *db);
const link_key_record_t *key_db_find(const key_db_t *db, const bt_addr_t *addr);
int key_db_put(key_db_t *db, const bt_addr_t *addr, const uint8_t key[16], uint8_t type);

int pairing_open(pairing_ctx_t *ctx, int dev_id, const char *db_path);
void pairing_close(pairing_ctx_t *ctx);
int pairing_configure_controller(pairing_ctx_t *ctx);
int pairing_pair_outgoing(pairing_ctx_t *ctx, const bt_addr_t *target, peer_state_t *state);
int pairing_listen(pairing_ctx_t *ctx);

#endif
