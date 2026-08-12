#define _GNU_SOURCE
#include "pairing.h"
#include "sdp.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void key_hex(const uint8_t key[16], char out[33])
{
    static const char h[] = "0123456789ABCDEF";
    for (int i = 0; i < 16; i++) {
        out[i * 2] = h[key[i] >> 4];
        out[i * 2 + 1] = h[key[i] & 15];
    }
    out[32] = 0;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int key_parse(const char *s, uint8_t key[16])
{
    if (strlen(s) != 32) return -1;
    for (int i = 0; i < 16; i++) {
        int hi = hex_nibble(s[i * 2]);
        int lo = hex_nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        key[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int bt_addr_parse(const char *s, bt_addr_t *out)
{
    unsigned v[6];
    char tail;
    if (!s || !out ||
        sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &tail) != 6)
        return -1;

    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff) return -1;
        out->b[5 - i] = (uint8_t)v[i];
    }
    return 0;
}

void bt_addr_format(const bt_addr_t *a, char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             a->b[5], a->b[4], a->b[3], a->b[2], a->b[1], a->b[0]);
}

bool bt_addr_equal(const bt_addr_t *a, const bt_addr_t *b)
{
    return memcmp(a->b, b->b, 6) == 0;
}

const link_key_record_t *key_db_find(const key_db_t *db, const bt_addr_t *addr)
{
    for (size_t i = 0; i < db->count; i++)
        if (bt_addr_equal(&db->rec[i].addr, addr))
            return &db->rec[i];
    return NULL;
}

int key_db_load(key_db_t *db, const char *path)
{
    memset(db, 0, sizeof(*db));
    if (!path || strlen(path) >= sizeof(db->path)) {
        errno = EINVAL;
        return -1;
    }
    strcpy(db->path, path);

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    char line[256];
    unsigned lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char addr_s[32], key_s[64];
        unsigned type;
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%31s %63s %x", addr_s, key_s, &type) != 3) {
            fprintf(stderr, "key DB: ignoring malformed line %u\n", lineno);
            continue;
        }
        if (db->count >= MAX_LINK_KEYS) {
            fprintf(stderr, "key DB: maximum %d records reached\n", MAX_LINK_KEYS);
            break;
        }
        link_key_record_t *r = &db->rec[db->count];
        if (bt_addr_parse(addr_s, &r->addr) < 0 ||
            key_parse(key_s, r->key) < 0 || type > 0xff) {
            fprintf(stderr, "key DB: ignoring invalid line %u\n", lineno);
            continue;
        }
        r->type = (uint8_t)type;
        db->count++;
    }
    fclose(f);
    return 0;
}

int key_db_save(const key_db_t *db)
{
    char tmp[600];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", db->path, (long)getpid())
        >= (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;

    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmp);
        return -1;
    }

    fprintf(f, "# BD_ADDR LINK_KEY KEY_TYPE\n");
    for (size_t i = 0; i < db->count; i++) {
        char addr[18], key[33];
        bt_addr_format(&db->rec[i].addr, addr);
        key_hex(db->rec[i].key, key);
        fprintf(f, "%s %s %02X\n", addr, key, db->rec[i].type);
    }

    if (fflush(f) != 0 || fsync(fileno(f)) != 0 || fclose(f) != 0) {
        unlink(tmp);
        return -1;
    }
    if (chmod(tmp, 0600) < 0 || rename(tmp, db->path) < 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

int key_db_put(key_db_t *db, const bt_addr_t *addr,
               const uint8_t key[16], uint8_t type)
{
    for (size_t i = 0; i < db->count; i++) {
        if (bt_addr_equal(&db->rec[i].addr, addr)) {
            memcpy(db->rec[i].key, key, 16);
            db->rec[i].type = type;
            return key_db_save(db);
        }
    }
    if (db->count >= MAX_LINK_KEYS) {
        errno = ENOSPC;
        return -1;
    }
    link_key_record_t *r = &db->rec[db->count++];
    r->addr = *addr;
    memcpy(r->key, key, 16);
    r->type = type;
    return key_db_save(db);
}

static int hci_send_cmd(int fd, uint16_t opcode, const void *params, uint8_t plen)
{
    uint8_t buf[4 + 255];
    buf[0] = HCI_COMMAND_PKT;
    put_le16(buf + 1, opcode);
    buf[3] = plen;
    if (plen && params) memcpy(buf + 4, params, plen);

    size_t len = 4u + plen;
    for (;;) {
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        if ((size_t)n != len) {
            errno = EIO;
            return -1;
        }
        return 0;
    }
}

int pairing_open(pairing_ctx_t *ctx, int dev_id, const char *db_path)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->hci_fd = -1;
    ctx->dev_id = dev_id;
    ctx->auto_confirm = true;
    strcpy(ctx->pin, "0000");
    ctx->io_capability = IO_CAP_NO_INPUT_OUTPUT;
    ctx->auth_requirement = AUTH_MITM_NOT_REQUIRED_GENERAL_BOND;
    ctx->timeout_sec = 60;

    if (key_db_load(&ctx->db, db_path) < 0) {
        perror("load link-key database");
        return -1;
    }

    int fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
    if (fd < 0) {
        perror("socket(AF_BLUETOOTH,HCI)");
        return -1;
    }

    struct sockaddr_hci_local sa;
    memset(&sa, 0, sizeof(sa));
    sa.hci_family = AF_BLUETOOTH;
    sa.hci_dev = (uint16_t)dev_id;
    sa.hci_channel = HCI_CHANNEL_RAW;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind(HCI raw)");
        close(fd);
        return -1;
    }

    /*
     * Raw HCI sockets are filterable. Ask explicitly for HCI Event packets
     * and all event codes so pairing/security events are never dependent on
     * the socket's initial filter state.
     */
    hci_filter_local_t flt;
    memset(&flt, 0, sizeof(flt));
    flt.type_mask = (1u << HCI_EVENT_PKT);
    flt.event_mask[0] = 0xFFFFFFFFu;
    flt.event_mask[1] = 0xFFFFFFFFu;
    flt.opcode = 0;
    if (setsockopt(fd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        perror("setsockopt(HCI_FILTER)");
        close(fd);
        return -1;
    }

    ctx->hci_fd = fd;
    return 0;
}

void pairing_close(pairing_ctx_t *ctx)
{
    if (ctx->hci_fd >= 0) close(ctx->hci_fd);
    ctx->hci_fd = -1;
}

static int cmd_u8(pairing_ctx_t *ctx, uint16_t op, uint8_t value)
{
    if (hci_send_cmd(ctx->hci_fd, op, &value, 1) < 0) {
        fprintf(stderr, "HCI command 0x%04x failed to write: %s\n",
                op, strerror(errno));
        return -1;
    }
    return 0;
}

int pairing_configure_controller(pairing_ctx_t *ctx)
{
    /*
     * Do not reset the adapter here: a reset can disrupt an already initialized
     * kernel HCI device. These commands make BR/EDR page scanning and SSP usable.
     */
    if (cmd_u8(ctx, HCI_OP_WRITE_AUTH_ENABLE, 0x01) < 0) return -1;
    if (cmd_u8(ctx, HCI_OP_WRITE_SIMPLE_PAIRING_MODE, 0x01) < 0) return -1;
    if (cmd_u8(ctx, HCI_OP_WRITE_SCAN_ENABLE, 0x03) < 0) return -1; /* inquiry+page */
    return 0;
}

static int send_link_key_reply(pairing_ctx_t *ctx, const bt_addr_t *addr,
                               const uint8_t key[16])
{
    uint8_t p[22];
    memcpy(p, addr->b, 6);
    memcpy(p + 6, key, 16);
    return hci_send_cmd(ctx->hci_fd, HCI_OP_LINK_KEY_REPLY, p, sizeof(p));
}

static int send_addr_cmd(pairing_ctx_t *ctx, uint16_t op, const bt_addr_t *addr)
{
    return hci_send_cmd(ctx->hci_fd, op, addr->b, 6);
}

static int send_pin_reply(pairing_ctx_t *ctx, const bt_addr_t *addr)
{
    size_t pin_len = strnlen(ctx->pin, 16);
    if (pin_len == 0 || pin_len > 16)
        return send_addr_cmd(ctx, HCI_OP_PIN_CODE_NEG_REPLY, addr);

    uint8_t p[23];
    memset(p, 0, sizeof(p));
    memcpy(p, addr->b, 6);
    p[6] = (uint8_t)pin_len;
    memcpy(p + 7, ctx->pin, pin_len);
    return hci_send_cmd(ctx->hci_fd, HCI_OP_PIN_CODE_REPLY, p, sizeof(p));
}

static int send_io_capability_reply(pairing_ctx_t *ctx, const bt_addr_t *addr)
{
    uint8_t p[9];
    memcpy(p, addr->b, 6);
    p[6] = ctx->io_capability;
    p[7] = OOB_NOT_PRESENT;
    p[8] = ctx->auth_requirement;
    return hci_send_cmd(ctx->hci_fd, HCI_OP_IO_CAPABILITY_REPLY, p, sizeof(p));
}

static bool ask_yes_no(const char *prompt)
{
    if (!isatty(STDIN_FILENO)) return false;
    fprintf(stderr, "%s [y/N]: ", prompt);
    fflush(stderr);
    char line[32];
    if (!fgets(line, sizeof(line), stdin)) return false;
    return line[0] == 'y' || line[0] == 'Y';
}

static int get_passkey(pairing_ctx_t *ctx, uint32_t *passkey)
{
    if (ctx->have_passkey) {
        *passkey = ctx->passkey;
        return 0;
    }
    if (!isatty(STDIN_FILENO)) return -1;

    fprintf(stderr, "Enter 6-digit Bluetooth passkey: ");
    fflush(stderr);
    char line[64], *end = NULL;
    if (!fgets(line, sizeof(line), stdin)) return -1;
    errno = 0;
    unsigned long v = strtoul(line, &end, 10);
    if (errno || end == line || v > 999999) return -1;
    *passkey = (uint32_t)v;
    return 0;
}

static int start_auth(pairing_ctx_t *ctx, uint16_t handle)
{
    uint8_t p[2];
    put_le16(p, handle);
    return hci_send_cmd(ctx->hci_fd, HCI_OP_AUTH_REQUESTED, p, sizeof(p));
}

static int start_encrypt(pairing_ctx_t *ctx, uint16_t handle)
{
    uint8_t p[3];
    put_le16(p, handle);
    p[2] = 1;
    return hci_send_cmd(ctx->hci_fd, HCI_OP_SET_CONN_ENCRYPT, p, sizeof(p));
}

static int accept_connection(pairing_ctx_t *ctx, const bt_addr_t *addr)
{
    uint8_t p[7];
    memcpy(p, addr->b, 6);
    p[6] = 0x01; /* remain slave/peripheral for incoming ACL */
    return hci_send_cmd(ctx->hci_fd, HCI_OP_ACCEPT_CONN_REQ, p, sizeof(p));
}

static int create_connection(pairing_ctx_t *ctx, const bt_addr_t *addr)
{
    uint8_t p[13];
    memcpy(p, addr->b, 6);
    put_le16(p + 6, 0xCC18); /* broad BR/EDR ACL packet-type mask */
    p[8] = 0x01;             /* page scan repetition mode R1 */
    p[9] = 0x00;             /* reserved */
    put_le16(p + 10, 0x0000);/* unknown clock offset */
    p[12] = 0x01;            /* allow role switch */
    return hci_send_cmd(ctx->hci_fd, HCI_OP_CREATE_CONN, p, sizeof(p));
}

static void status_log(const char *what, uint8_t status)
{
    if (status)
        fprintf(stderr, "%s: Bluetooth status 0x%02X\n", what, status);
}

static int process_security_event(pairing_ctx_t *ctx,
                                  const uint8_t *ev, size_t len,
                                  peer_state_t *watch,
                                  bool proactive_auth,
                                  bool *pair_done)
{
    if (len < 3 || ev[0] != HCI_EVENT_PKT) return 0;
    uint8_t code = ev[1], plen = ev[2];
    if ((size_t)plen + 3 > len) return 0;
    const uint8_t *p = ev + 3;

    switch (code) {
    case EVT_CONN_REQUEST: {
        if (plen < 10) break;
        bt_addr_t addr; memcpy(addr.b, p, 6);
        uint8_t link_type = p[9];
        char s[18]; bt_addr_format(&addr, s);
        if (link_type == HCI_LINK_ACL) {
            fprintf(stderr, "Incoming ACL connection from %s; accepting\n", s);
            if (accept_connection(ctx, &addr) < 0)
                perror("Accept Connection Request");
        }
        break;
    }
    case EVT_CONN_COMPLETE: {
        if (plen < 11) break;
        uint8_t status = p[0];
        uint16_t handle = get_le16(p + 1) & 0x0FFF;
        bt_addr_t addr; memcpy(addr.b, p + 3, 6);
        uint8_t link_type = p[9];
        char s[18]; bt_addr_format(&addr, s);
        if (status || link_type != HCI_LINK_ACL) {
            status_log("Connection Complete", status);
            if (watch && bt_addr_equal(&watch->addr, &addr))
                watch->last_status = status ? status : 0xFF;
            break;
        }
        fprintf(stderr, "ACL connected: %s handle=0x%04X\n", s, handle);
        if (watch && bt_addr_equal(&watch->addr, &addr)) {
            watch->handle = handle;
            watch->connected = true;
        }
        if (proactive_auth) {
            if (start_auth(ctx, handle) < 0) perror("Authentication Requested");
        }
        break;
    }
    case EVT_LINK_KEY_REQ: {
        if (plen < 6) break;
        bt_addr_t addr; memcpy(addr.b, p, 6);
        char s[18]; bt_addr_format(&addr, s);
        const link_key_record_t *r = key_db_find(&ctx->db, &addr);
        if (r) {
            fprintf(stderr, "Link Key Request from %s: using stored key\n", s);
            if (send_link_key_reply(ctx, &addr, r->key) < 0)
                perror("Link Key Request Reply");
        } else {
            fprintf(stderr, "Link Key Request from %s: no stored key\n", s);
            if (send_addr_cmd(ctx, HCI_OP_LINK_KEY_NEG_REPLY, &addr) < 0)
                perror("Link Key Request Negative Reply");
        }
        break;
    }
    case EVT_PIN_CODE_REQ: {
        if (plen < 6) break;
        bt_addr_t addr; memcpy(addr.b, p, 6);
        char s[18]; bt_addr_format(&addr, s);
        fprintf(stderr, "Legacy PIN Code Request from %s; replying with configured PIN\n", s);
        if (send_pin_reply(ctx, &addr) < 0) perror("PIN Code Request Reply");
        break;
    }
    case EVT_IO_CAPABILITY_REQUEST: {
        if (plen < 6) break;
        bt_addr_t addr; memcpy(addr.b, p, 6);
        char s[18]; bt_addr_format(&addr, s);
        fprintf(stderr, "IO Capability Request from %s: io=0x%02X auth=0x%02X\n",
                s, ctx->io_capability, ctx->auth_requirement);
        if (send_io_capability_reply(ctx, &addr) < 0)
            perror("IO Capability Request Reply");
        break;
    }
    case EVT_USER_CONFIRM_REQUEST: {
        if (plen < 10) break;
        bt_addr_t addr; memcpy(addr.b, p, 6);
        uint32_t value = (uint32_t)p[6] | ((uint32_t)p[7] << 8) |
                         ((uint32_t)p[8] << 16) | ((uint32_t)p[9] << 24);
        char s[18]; bt_addr_format(&addr, s);
        fprintf(stderr, "Numeric comparison for %s: %06u\n", s, value);
        bool yes = ctx->auto_confirm;
        if (!ctx->auto_confirm) {
            char prompt[128];
            snprintf(prompt, sizeof(prompt), "Does peer %s show %06u?", s, value);
            yes = ask_yes_no(prompt);
        }
        if (send_addr_cmd(ctx,
              yes ? HCI_OP_USER_CONFIRM_REPLY : HCI_OP_USER_CONFIRM_NEG_REPLY,
              &addr) < 0)
            perror("User Confirmation Reply");
        break;
    }
    case EVT_USER_PASSKEY_REQUEST: {
        if (plen < 6) break;
        bt_addr_t addr; memcpy(addr.b, p, 6);
        uint32_t passkey;
        if (get_passkey(ctx, &passkey) == 0) {
            uint8_t q[10];
            memcpy(q, addr.b, 6);
            q[6] = (uint8_t)passkey;
            q[7] = (uint8_t)(passkey >> 8);
            q[8] = (uint8_t)(passkey >> 16);
            q[9] = (uint8_t)(passkey >> 24);
            if (hci_send_cmd(ctx->hci_fd, HCI_OP_USER_PASSKEY_REPLY,
                             q, sizeof(q)) < 0)
                perror("User Passkey Request Reply");
        } else {
            fprintf(stderr, "No passkey available; rejecting passkey request\n");
            if (send_addr_cmd(ctx, HCI_OP_USER_PASSKEY_NEG_REPLY, &addr) < 0)
                perror("User Passkey Negative Reply");
        }
        break;
    }
    case EVT_REMOTE_OOB_DATA_REQUEST: {
        if (plen < 6) break;
        bt_addr_t addr; memcpy(addr.b, p, 6);
        fprintf(stderr, "Remote OOB data requested; no OOB data configured\n");
        if (send_addr_cmd(ctx, HCI_OP_REMOTE_OOB_NEG_REPLY, &addr) < 0)
            perror("Remote OOB Negative Reply");
        break;
    }
    case EVT_SIMPLE_PAIRING_COMPLETE: {
        if (plen < 7) break;
        uint8_t status = p[0];
        bt_addr_t addr; memcpy(addr.b, p + 1, 6);
        char s[18]; bt_addr_format(&addr, s);
        fprintf(stderr, "Simple Pairing Complete: %s status=0x%02X\n", s, status);
        if (watch && bt_addr_equal(&watch->addr, &addr) && status)
            watch->last_status = status;
        break;
    }
    case EVT_LINK_KEY_NOTIFY: {
        if (plen < 23) break;
        bt_addr_t addr; memcpy(addr.b, p, 6);
        const uint8_t *key = p + 6;
        uint8_t type = p[22];
        char s[18]; bt_addr_format(&addr, s);
        if (key_db_put(&ctx->db, &addr, key, type) < 0) {
            perror("save link key");
        } else {
            fprintf(stderr, "Stored link key for %s (type 0x%02X)\n", s, type);
        }
        if (watch && bt_addr_equal(&watch->addr, &addr))
            watch->link_key_seen = true;
        break;
    }
    case EVT_AUTH_COMPLETE: {
        if (plen < 3) break;
        uint8_t status = p[0];
        uint16_t handle = get_le16(p + 1) & 0x0FFF;
        fprintf(stderr, "Authentication Complete handle=0x%04X status=0x%02X\n",
                handle, status);
        if (watch && watch->handle == handle) {
            watch->last_status = status;
            if (!status) {
                watch->authenticated = true;
                if (start_encrypt(ctx, handle) < 0)
                    perror("Set Connection Encryption");
            }
        }
        break;
    }
    case EVT_ENCRYPT_CHANGE: {
        if (plen < 4) break;
        uint8_t status = p[0];
        uint16_t handle = get_le16(p + 1) & 0x0FFF;
        uint8_t enabled = p[3];
        fprintf(stderr, "Encryption Change handle=0x%04X status=0x%02X enabled=%u\n",
                handle, status, enabled);
        if (watch && watch->handle == handle) {
            watch->last_status = status;
            if (!status && enabled) {
                watch->encrypted = true;
                if (pair_done) *pair_done = true;
            } else if (watch->authenticated) {
                /*
                 * Pairing/authentication succeeded even if encryption could not
                 * be enabled for a controller-specific reason. Let caller decide.
                 */
                if (pair_done) *pair_done = true;
            }
        }
        break;
    }
    case EVT_DISCONN_COMPLETE: {
        if (plen < 4) break;
        uint16_t handle = get_le16(p + 1) & 0x0FFF;
        if (watch && watch->handle == handle) {
            fprintf(stderr, "Peer disconnected during pairing\n");
            watch->connected = false;
            if (!watch->authenticated) watch->last_status = 0xFF;
        }
        break;
    }
    default:
        break;
    }
    return 0;
}

int pairing_pair_outgoing(pairing_ctx_t *ctx, const bt_addr_t *target,
                          peer_state_t *state)
{
    memset(state, 0, sizeof(*state));
    state->addr = *target;

    char s[18]; bt_addr_format(target, s);
    fprintf(stderr, "Creating BR/EDR ACL connection to %s\n", s);
    if (create_connection(ctx, target) < 0) {
        perror("Create Connection");
        return -1;
    }

    time_t deadline = time(NULL) + ctx->timeout_sec;
    bool done = false;

    while (time(NULL) < deadline) {
        struct pollfd pfd = {.fd = ctx->hci_fd, .events = POLLIN};
        int ms = 1000;
        int pr;
        do { pr = poll(&pfd, 1, ms); } while (pr < 0 && errno == EINTR);
        if (pr < 0) {
            perror("poll(HCI)");
            return -1;
        }
        if (pr == 0) continue;

        uint8_t buf[2048];
        ssize_t n;
        do { n = read(ctx->hci_fd, buf, sizeof(buf)); }
        while (n < 0 && errno == EINTR);
        if (n < 0) {
            perror("read(HCI)");
            return -1;
        }

        process_security_event(ctx, buf, (size_t)n, state, true, &done);

        if (state->last_status && !state->authenticated) {
            errno = EACCES;
            return -1;
        }
        if (done && state->authenticated)
            return 0;
    }

    fprintf(stderr, "Pairing timed out after %d seconds\n", ctx->timeout_sec);
    errno = ETIMEDOUT;
    return -1;
}

int pairing_listen(pairing_ctx_t *ctx)
{
    fprintf(stderr,
        "Pairing listener active on hci%d. Incoming ACL connections will be "
        "accepted and authenticated.\n", ctx->dev_id);

    peer_state_t peer;
    memset(&peer, 0, sizeof(peer));

    for (;;) {
        uint8_t buf[2048];
        ssize_t n = read(ctx->hci_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read(HCI)");
            return -1;
        }

        bool done = false;

        /*
         * Track the most recently connected ACL peer so that, after successful
         * authentication, we can immediately perform SDP discovery.
         */
        if (n >= 14 && buf[0] == HCI_EVENT_PKT && buf[1] == EVT_CONN_COMPLETE) {
            const uint8_t *p = buf + 3;
            if (p[0] == 0 && p[9] == HCI_LINK_ACL) {
                memset(&peer, 0, sizeof(peer));
                peer.handle = get_le16(p + 1) & 0x0FFF;
                memcpy(peer.addr.b, p + 3, 6);
                peer.connected = true;
            }
        }

        process_security_event(ctx, buf, (size_t)n, &peer, true, &done);

        if (done && peer.authenticated) {
            char s[18]; bt_addr_format(&peer.addr, s);
            uint8_t ch = 0;
            if (sdp_find_hfp_hf_rfcomm_channel(&peer.addr, &ch) == 0)
                printf("PAIRED %s HFP_HF_RFCOMM_CHANNEL=%u\n", s, ch);
            else
                printf("PAIRED %s HFP_HF_RFCOMM_CHANNEL=NOT_FOUND\n", s);
            fflush(stdout);
            /* Avoid repeating SDP on unrelated subsequent events. */
            peer.authenticated = false;
        }
    }
}
