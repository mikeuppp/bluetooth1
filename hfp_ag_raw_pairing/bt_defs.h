#ifndef BT_DEFS_H
#define BT_DEFS_H

#include <stdint.h>
#include <sys/socket.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#ifndef PF_BLUETOOTH
#define PF_BLUETOOTH AF_BLUETOOTH
#endif

#define BTPROTO_L2CAP 0
#define BTPROTO_HCI    1

#define HCI_CHANNEL_RAW 0
#define SOL_HCI         0
#define HCI_FILTER      2

typedef struct {
    uint32_t type_mask;
    uint32_t event_mask[2];
    uint16_t opcode;
} hci_filter_local_t;

#define HCI_COMMAND_PKT 0x01
#define HCI_ACLDATA_PKT 0x02
#define HCI_SCODATA_PKT 0x03
#define HCI_EVENT_PKT   0x04

/* HCI event codes */
#define EVT_INQUIRY_COMPLETE            0x01
#define EVT_CONN_COMPLETE               0x03
#define EVT_CONN_REQUEST                0x04
#define EVT_DISCONN_COMPLETE            0x05
#define EVT_AUTH_COMPLETE               0x06
#define EVT_ENCRYPT_CHANGE              0x08
#define EVT_CMD_COMPLETE                0x0E
#define EVT_CMD_STATUS                  0x0F
#define EVT_PIN_CODE_REQ                0x16
#define EVT_LINK_KEY_REQ                0x17
#define EVT_LINK_KEY_NOTIFY             0x18
#define EVT_IO_CAPABILITY_REQUEST       0x31
#define EVT_IO_CAPABILITY_RESPONSE      0x32
#define EVT_USER_CONFIRM_REQUEST        0x33
#define EVT_USER_PASSKEY_REQUEST        0x34
#define EVT_REMOTE_OOB_DATA_REQUEST     0x35
#define EVT_SIMPLE_PAIRING_COMPLETE     0x36
#define EVT_USER_PASSKEY_NOTIFY         0x3B

/* Link types */
#define HCI_LINK_SCO   0x00
#define HCI_LINK_ACL   0x01
#define HCI_LINK_ESCO  0x02

/* OGF values */
#define OGF_LINK_CTL    0x01
#define OGF_HOST_CTL    0x03

#define HCI_OPCODE(ogf, ocf) ((uint16_t)(((ocf) & 0x03ff) | ((ogf) << 10)))

/* Link Control commands */
#define HCI_OP_CREATE_CONN               HCI_OPCODE(OGF_LINK_CTL, 0x0005)
#define HCI_OP_ACCEPT_CONN_REQ            HCI_OPCODE(OGF_LINK_CTL, 0x0009)
#define HCI_OP_REJECT_CONN_REQ            HCI_OPCODE(OGF_LINK_CTL, 0x000A)
#define HCI_OP_LINK_KEY_REPLY              HCI_OPCODE(OGF_LINK_CTL, 0x000B)
#define HCI_OP_LINK_KEY_NEG_REPLY          HCI_OPCODE(OGF_LINK_CTL, 0x000C)
#define HCI_OP_PIN_CODE_REPLY              HCI_OPCODE(OGF_LINK_CTL, 0x000D)
#define HCI_OP_PIN_CODE_NEG_REPLY          HCI_OPCODE(OGF_LINK_CTL, 0x000E)
#define HCI_OP_AUTH_REQUESTED              HCI_OPCODE(OGF_LINK_CTL, 0x0011)
#define HCI_OP_SET_CONN_ENCRYPT            HCI_OPCODE(OGF_LINK_CTL, 0x0013)
#define HCI_OP_IO_CAPABILITY_REPLY         HCI_OPCODE(OGF_LINK_CTL, 0x002B)
#define HCI_OP_USER_CONFIRM_REPLY          HCI_OPCODE(OGF_LINK_CTL, 0x002C)
#define HCI_OP_USER_CONFIRM_NEG_REPLY      HCI_OPCODE(OGF_LINK_CTL, 0x002D)
#define HCI_OP_USER_PASSKEY_REPLY          HCI_OPCODE(OGF_LINK_CTL, 0x002E)
#define HCI_OP_USER_PASSKEY_NEG_REPLY      HCI_OPCODE(OGF_LINK_CTL, 0x002F)
#define HCI_OP_REMOTE_OOB_NEG_REPLY        HCI_OPCODE(OGF_LINK_CTL, 0x0033)

/* Host Controller & Baseband commands */
#define HCI_OP_WRITE_AUTH_ENABLE           HCI_OPCODE(OGF_HOST_CTL, 0x0020)
#define HCI_OP_WRITE_SCAN_ENABLE           HCI_OPCODE(OGF_HOST_CTL, 0x001A)
#define HCI_OP_WRITE_SIMPLE_PAIRING_MODE   HCI_OPCODE(OGF_HOST_CTL, 0x0056)

/* SSP IO capabilities */
#define IO_CAP_DISPLAY_ONLY       0x00
#define IO_CAP_DISPLAY_YESNO      0x01
#define IO_CAP_KEYBOARD_ONLY      0x02
#define IO_CAP_NO_INPUT_OUTPUT    0x03
#define IO_CAP_KEYBOARD_DISPLAY  0x04

#define OOB_NOT_PRESENT 0x00

/* Authentication requirements */
#define AUTH_MITM_NOT_REQUIRED_NO_BONDING      0x00
#define AUTH_MITM_REQUIRED_NO_BONDING          0x01
#define AUTH_MITM_NOT_REQUIRED_DEDICATED_BOND  0x02
#define AUTH_MITM_REQUIRED_DEDICATED_BOND      0x03
#define AUTH_MITM_NOT_REQUIRED_GENERAL_BOND    0x04
#define AUTH_MITM_REQUIRED_GENERAL_BOND        0x05

typedef struct {
    uint8_t b[6]; /* Bluetooth address in Linux/HCI little-endian byte order */
} bt_addr_t;

struct sockaddr_hci_local {
    sa_family_t hci_family;
    uint16_t    hci_dev;
    uint16_t    hci_channel;
};

struct sockaddr_l2_local {
    sa_family_t l2_family;
    uint16_t    l2_psm;
    bt_addr_t   l2_bdaddr;
    uint16_t    l2_cid;
    uint8_t     l2_bdaddr_type;
};

static inline uint16_t get_le16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}
static inline void put_le16(void *p, uint16_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
}
static inline uint16_t get_be16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint16_t)b[0] << 8) | b[1];
}
static inline void put_be16(void *p, uint16_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}

#endif
