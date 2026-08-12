#define _GNU_SOURCE
#include "pairing.h"
#include "sdp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *f, const char *argv0)
{
    fprintf(f,
"Usage:\n"
"  %s [options] pair <BD_ADDR>\n"
"  %s [options] listen\n"
"  %s [options] sdp <BD_ADDR>\n"
"\n"
"Options:\n"
"  --dev N                 HCI adapter index (default: 0)\n"
"  --db PATH               link-key DB (default: ./linkkeys.db)\n"
"  --pin PIN               legacy PIN, 1..16 chars (default: 0000)\n"
"  --passkey N             SSP passkey 0..999999 when peer requests entry\n"
"  --no-auto-confirm       ask on terminal for numeric comparison\n"
"  --io-cap MODE           no-input-output (default), display-yesno,\n"
"                          display-only, keyboard-only, keyboard-display\n"
"  --mitm                  request General Bonding with MITM\n"
"  --timeout SEC           outgoing pairing timeout (default: 60)\n"
"\n"
"Examples:\n"
"  sudo %s pair 11:22:33:44:55:66\n"
"  sudo %s --pin 0000 listen\n"
"  sudo %s sdp 11:22:33:44:55:66\n",
        argv0, argv0, argv0, argv0, argv0, argv0);
}

static int parse_io(const char *s, uint8_t *out)
{
    if (!strcmp(s, "no-input-output")) *out = IO_CAP_NO_INPUT_OUTPUT;
    else if (!strcmp(s, "display-yesno")) *out = IO_CAP_DISPLAY_YESNO;
    else if (!strcmp(s, "display-only")) *out = IO_CAP_DISPLAY_ONLY;
    else if (!strcmp(s, "keyboard-only")) *out = IO_CAP_KEYBOARD_ONLY;
    else if (!strcmp(s, "keyboard-display")) *out = IO_CAP_KEYBOARD_DISPLAY;
    else return -1;
    return 0;
}

int main(int argc, char **argv)
{
    int dev_id = 0;
    const char *db_path = "./linkkeys.db";
    const char *pin = "0000";
    bool auto_confirm = true;
    bool have_passkey = false;
    uint32_t passkey = 0;
    uint8_t io_cap = IO_CAP_NO_INPUT_OUTPUT;
    uint8_t auth = AUTH_MITM_NOT_REQUIRED_GENERAL_BOND;
    int timeout = 60;

    int i = 1;
    while (i < argc && !strncmp(argv[i], "--", 2)) {
        if (!strcmp(argv[i], "--dev") && i + 1 < argc) {
            dev_id = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--db") && i + 1 < argc) {
            db_path = argv[++i];
        } else if (!strcmp(argv[i], "--pin") && i + 1 < argc) {
            pin = argv[++i];
            if (strlen(pin) < 1 || strlen(pin) > 16) {
                fprintf(stderr, "--pin must contain 1..16 characters\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--passkey") && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (!end || *end || v > 999999) {
                fprintf(stderr, "--passkey must be 0..999999\n");
                return 2;
            }
            passkey = (uint32_t)v;
            have_passkey = true;
        } else if (!strcmp(argv[i], "--no-auto-confirm")) {
            auto_confirm = false;
        } else if (!strcmp(argv[i], "--io-cap") && i + 1 < argc) {
            if (parse_io(argv[++i], &io_cap) < 0) {
                fprintf(stderr, "invalid --io-cap mode\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--mitm")) {
            auth = AUTH_MITM_REQUIRED_GENERAL_BOND;
        } else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
            timeout = atoi(argv[++i]);
            if (timeout < 5 || timeout > 600) {
                fprintf(stderr, "--timeout range is 5..600 seconds\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--help")) {
            usage(stdout, argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        }
        i++;
    }

    if (i >= argc) {
        usage(stderr, argv[0]);
        return 2;
    }

    const char *cmd = argv[i++];

    if (!strcmp(cmd, "sdp")) {
        if (i != argc - 1) {
            usage(stderr, argv[0]);
            return 2;
        }
        bt_addr_t addr;
        if (bt_addr_parse(argv[i], &addr) < 0) {
            fprintf(stderr, "Invalid Bluetooth address\n");
            return 2;
        }
        uint8_t ch;
        if (sdp_find_hfp_hf_rfcomm_channel(&addr, &ch) < 0)
            return 1;
        printf("%u\n", ch);
        return 0;
    }

    pairing_ctx_t ctx;
    if (pairing_open(&ctx, dev_id, db_path) < 0)
        return 1;

    ctx.auto_confirm = auto_confirm;
    ctx.have_passkey = have_passkey;
    ctx.passkey = passkey;
    strncpy(ctx.pin, pin, 16);
    ctx.pin[16] = 0;
    ctx.io_capability = io_cap;
    ctx.auth_requirement = auth;
    ctx.timeout_sec = timeout;

    if (pairing_configure_controller(&ctx) < 0) {
        pairing_close(&ctx);
        return 1;
    }

    int rc = 1;

    if (!strcmp(cmd, "pair")) {
        if (i != argc - 1) {
            usage(stderr, argv[0]);
            goto out;
        }

        bt_addr_t addr;
        if (bt_addr_parse(argv[i], &addr) < 0) {
            fprintf(stderr, "Invalid Bluetooth address\n");
            goto out;
        }

        peer_state_t state;
        if (pairing_pair_outgoing(&ctx, &addr, &state) < 0) {
            fprintf(stderr, "Pairing failed: %s\n", strerror(errno));
            goto out;
        }

        char s[18]; bt_addr_format(&addr, s);
        printf("PAIRING_OK %s AUTHENTICATED=1 ENCRYPTED=%u\n",
               s, state.encrypted ? 1 : 0);

        uint8_t channel;
        if (sdp_find_hfp_hf_rfcomm_channel(&addr, &channel) == 0) {
            printf("HFP_HF_RFCOMM_CHANNEL=%u\n", channel);
            rc = 0;
        } else {
            fprintf(stderr,
                "Pairing succeeded, but HFP HF SDP channel discovery failed.\n");
            rc = 3;
        }
    } else if (!strcmp(cmd, "listen")) {
        if (i != argc) {
            usage(stderr, argv[0]);
            goto out;
        }
        rc = pairing_listen(&ctx) == 0 ? 0 : 1;
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(stderr, argv[0]);
    }

out:
    pairing_close(&ctx);
    return rc;
}
