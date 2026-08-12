#define _GNU_SOURCE
#include "sdp.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SDP_PSM 0x0001
#define SDP_SERVICE_SEARCH_ATTR_REQ  0x06
#define SDP_SERVICE_SEARCH_ATTR_RSP  0x07
#define SDP_UUID_HANDSFREE            0x111E
#define SDP_UUID_RFCOMM               0x0003
#define SDP_ATTR_PROTOCOL_DESC_LIST   0x0004
#define SDP_MAX_AGGREGATE             (64 * 1024)

static int write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int poll_read(int fd, void *buf, size_t cap, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    for (;;) {
        int r = poll(&pfd, 1, timeout_ms);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            if (r == 0) errno = ETIMEDOUT;
            return -1;
        }
        ssize_t n = read(fd, buf, cap);
        if (n < 0 && errno == EINTR) continue;
        return (int)n;
    }
}

/* Build ServiceSearchAttributeRequest for Hands-Free (HF) service, attr 0x0004. */
static size_t build_request(uint8_t *out, size_t cap, uint16_t tid,
                            const uint8_t *cont, uint8_t cont_len)
{
    const uint8_t pattern[] = {
        0x35, 0x03,       /* Data Element Sequence, 3 bytes */
        0x19, 0x11, 0x1E  /* UUID16: Handsfree (0x111E) */
    };
    const uint8_t attrs[] = {
        0x35, 0x03,
        0x09, 0x00, 0x04  /* uint16 attr ID: ProtocolDescriptorList */
    };
    size_t params = sizeof(pattern) + 2 + sizeof(attrs) + 1 + cont_len;
    if (cap < 5 + params || cont_len > 16) return 0;

    size_t o = 0;
    out[o++] = SDP_SERVICE_SEARCH_ATTR_REQ;
    put_be16(out + o, tid); o += 2;
    put_be16(out + o, (uint16_t)params); o += 2;
    memcpy(out + o, pattern, sizeof(pattern)); o += sizeof(pattern);
    put_be16(out + o, 0xFFFF); o += 2; /* MaximumAttributeByteCount */
    memcpy(out + o, attrs, sizeof(attrs)); o += sizeof(attrs);
    out[o++] = cont_len;
    if (cont_len) {
        memcpy(out + o, cont, cont_len);
        o += cont_len;
    }
    return o;
}

typedef struct {
    uint8_t type;
    const uint8_t *payload;
    size_t len;
    size_t total_len;
} de_t;

/* SDP Data Element parser. */
static int de_parse(const uint8_t *p, size_t avail, de_t *de)
{
    if (avail < 1) return -1;
    uint8_t d = p[0];
    uint8_t type = d >> 3;
    uint8_t size_idx = d & 7;
    size_t hdr = 1, len = 0;

    if (type == 0) {
        len = 0;
    } else if (size_idx <= 4) {
        static const size_t fixed[] = {1,2,4,8,16};
        len = fixed[size_idx];
    } else if (size_idx == 5) {
        if (avail < 2) return -1;
        hdr = 2; len = p[1];
    } else if (size_idx == 6) {
        if (avail < 3) return -1;
        hdr = 3; len = get_be16(p + 1);
    } else {
        if (avail < 5) return -1;
        hdr = 5;
        len = ((size_t)p[1] << 24) | ((size_t)p[2] << 16) |
              ((size_t)p[3] << 8) | p[4];
    }
    if (hdr + len > avail) return -1;

    de->type = type;
    de->payload = p + hdr;
    de->len = len;
    de->total_len = hdr + len;
    return 0;
}

static int de_u16(const de_t *de, uint16_t *v)
{
    /* UINT type=1 or UUID type=3, 2-byte representation. */
    if ((de->type != 1 && de->type != 3) || de->len != 2) return -1;
    *v = get_be16(de->payload);
    return 0;
}

static int de_u8(const de_t *de, uint8_t *v)
{
    if (de->type != 1 || de->len != 1) return -1;
    *v = de->payload[0];
    return 0;
}

/* Parse ProtocolDescriptorList value and return RFCOMM channel. */
static int parse_protocol_list(const de_t *value, uint8_t *channel)
{
    if (value->type != 6) return -1; /* sequence */
    size_t off = 0;

    while (off < value->len) {
        de_t proto;
        if (de_parse(value->payload + off, value->len - off, &proto) < 0)
            return -1;
        off += proto.total_len;
        if (proto.type != 6) continue;

        size_t poff = 0;
        de_t uuid;
        if (de_parse(proto.payload + poff, proto.len - poff, &uuid) < 0)
            continue;
        poff += uuid.total_len;

        uint16_t uuid16;
        if (de_u16(&uuid, &uuid16) < 0 || uuid.type != 3)
            continue;
        if (uuid16 != SDP_UUID_RFCOMM)
            continue;

        de_t param;
        if (poff >= proto.len ||
            de_parse(proto.payload + poff, proto.len - poff, &param) < 0)
            return -1;

        uint8_t ch;
        if (de_u8(&param, &ch) == 0 && ch >= 1 && ch <= 30) {
            *channel = ch;
            return 0;
        }
    }
    return -1;
}

/*
 * AttributeLists is normally:
 * sequence {
 *   sequence { uint16 attr-id, value, ... }   // one service record
 *   ...
 * }
 */
static int parse_attribute_lists(const uint8_t *buf, size_t len, uint8_t *channel)
{
    de_t outer;
    if (de_parse(buf, len, &outer) < 0 || outer.type != 6)
        return -1;

    size_t roff = 0;
    while (roff < outer.len) {
        de_t record;
        if (de_parse(outer.payload + roff, outer.len - roff, &record) < 0)
            return -1;
        roff += record.total_len;
        if (record.type != 6) continue;

        size_t aoff = 0;
        while (aoff < record.len) {
            de_t id;
            if (de_parse(record.payload + aoff, record.len - aoff, &id) < 0)
                return -1;
            aoff += id.total_len;

            uint16_t attr_id;
            if (de_u16(&id, &attr_id) < 0 || id.type != 1)
                return -1;

            if (aoff >= record.len) return -1;
            de_t value;
            if (de_parse(record.payload + aoff, record.len - aoff, &value) < 0)
                return -1;
            aoff += value.total_len;

            if (attr_id == SDP_ATTR_PROTOCOL_DESC_LIST &&
                parse_protocol_list(&value, channel) == 0)
                return 0;
        }
    }
    return -1;
}

int sdp_find_hfp_hf_rfcomm_channel(const bt_addr_t *remote, uint8_t *channel)
{
    if (!remote || !channel) {
        errno = EINVAL;
        return -1;
    }

    int fd = socket(AF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC, BTPROTO_L2CAP);
    if (fd < 0) {
        perror("socket(AF_BLUETOOTH,L2CAP)");
        return -1;
    }

    struct sockaddr_l2_local dst;
    memset(&dst, 0, sizeof(dst));
    dst.l2_family = AF_BLUETOOTH;
    dst.l2_psm = SDP_PSM; /* Linux Bluetooth ABI uses little-endian PSM. */
    dst.l2_bdaddr = *remote;

    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("connect(SDP PSM 1)");
        close(fd);
        return -1;
    }

    uint8_t *aggregate = malloc(SDP_MAX_AGGREGATE);
    if (!aggregate) {
        close(fd);
        return -1;
    }
    size_t aggregate_len = 0;

    uint8_t cont[16] = {0};
    uint8_t cont_len = 0;
    uint16_t tid = 0x3344;

    for (unsigned round = 0; round < 32; round++) {
        uint8_t req[64];
        size_t req_len = build_request(req, sizeof(req), tid, cont, cont_len);
        if (!req_len) {
            errno = EPROTO;
            goto fail;
        }
        if (write_full(fd, req, req_len) < 0) {
            perror("write(SDP request)");
            goto fail;
        }

        uint8_t rsp[4096];
        int n = poll_read(fd, rsp, sizeof(rsp), 5000);
        if (n < 0) {
            perror("read(SDP response)");
            goto fail;
        }
        if (n < 7 || rsp[0] != SDP_SERVICE_SEARCH_ATTR_RSP) {
            fprintf(stderr, "SDP: unexpected PDU 0x%02x, len=%d\n",
                    n > 0 ? rsp[0] : 0, n);
            errno = EPROTO;
            goto fail;
        }
        if (get_be16(rsp + 1) != tid) {
            fprintf(stderr, "SDP: transaction ID mismatch\n");
            errno = EPROTO;
            goto fail;
        }
        uint16_t param_len = get_be16(rsp + 3);
        if ((size_t)n < 5u + param_len || param_len < 3) {
            fprintf(stderr, "SDP: truncated response\n");
            errno = EPROTO;
            goto fail;
        }

        const uint8_t *p = rsp + 5;
        size_t remain = param_len;
        uint16_t attr_bytes = get_be16(p);
        p += 2; remain -= 2;

        if (attr_bytes > remain - 1 ||
            aggregate_len + attr_bytes > SDP_MAX_AGGREGATE) {
            fprintf(stderr, "SDP: invalid/oversized attribute list\n");
            errno = EOVERFLOW;
            goto fail;
        }
        memcpy(aggregate + aggregate_len, p, attr_bytes);
        aggregate_len += attr_bytes;
        p += attr_bytes; remain -= attr_bytes;

        if (remain < 1) {
            errno = EPROTO;
            goto fail;
        }
        uint8_t next_len = *p++;
        remain--;
        if (next_len > sizeof(cont) || next_len > remain) {
            fprintf(stderr, "SDP: invalid continuation state\n");
            errno = EPROTO;
            goto fail;
        }
        cont_len = next_len;
        if (cont_len)
            memcpy(cont, p, cont_len);

        if (cont_len == 0) {
            int rc = parse_attribute_lists(aggregate, aggregate_len, channel);
            if (rc < 0) {
                fprintf(stderr,
                        "SDP: Hands-Free service found response, but RFCOMM "
                        "channel was not present/parsable\n");
                errno = ENOENT;
            }
            free(aggregate);
            close(fd);
            return rc;
        }
    }

    fprintf(stderr, "SDP: too many continuation responses\n");
    errno = ELOOP;

fail:
    free(aggregate);
    close(fd);
    return -1;
}
