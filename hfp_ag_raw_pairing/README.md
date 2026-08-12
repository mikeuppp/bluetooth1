# HFP AG raw-HCI pairing + HFP HF RFCOMM channel discovery

A Linux/Ubuntu C implementation that uses only the kernel Bluetooth socket ABI
and libc:

- raw HCI socket for BR/EDR connection + pairing/security events,
- handles locally initiated and remotely initiated pairing,
- handles SSP Just Works / Numeric Comparison / Passkey Entry,
- handles legacy PIN pairing,
- persists Classic Bluetooth link keys in a private file,
- reuses saved link keys on `Link Key Request`,
- enables link encryption after authentication,
- opens an L2CAP socket to SDP PSM 1,
- sends a raw SDP ServiceSearchAttributeRequest for the HFP Hands-Free service
  UUID `0x111E`,
- parses `ProtocolDescriptorList` (`0x0004`) and returns the RFCOMM channel.

It deliberately does **not** link to libbluetooth and does not use D-Bus,
`bluetoothctl`, `sdptool`, or a BlueZ client API.

## Build

```bash
make
```

Only GCC/Clang, libc, Linux Bluetooth kernel support, and normal Linux socket
headers are needed. There is no `-lbluetooth`.

## Runtime ownership

Run as root or with the capabilities required for raw Bluetooth HCI access.

For predictable behavior, do not run a userspace Bluetooth manager that is
simultaneously acting as the pairing agent on the same adapter. On a normal
Ubuntu desktop/server this usually means stopping the `bluetooth` service
before this program owns pairing policy:

```bash
sudo systemctl stop bluetooth
```

This program uses `HCI_CHANNEL_RAW`, not `HCI_CHANNEL_USER`, because after
pairing it must keep the kernel Bluetooth stack available for the L2CAP/SDP
socket. A USER-channel implementation would take exclusive controller
ownership and would therefore require implementing ACL/L2CAP/SDP itself.

## Outgoing pairing

```bash
sudo ./hfp_pair pair 11:22:33:44:55:66
```

Typical successful output:

```text
PAIRING_OK 11:22:33:44:55:66 AUTHENTICATED=1 ENCRYPTED=1
HFP_HF_RFCOMM_CHANNEL=2
```

The actual channel is obtained from the remote SDP server; it is never assumed
to be 1, 2, or any other fixed value.

### Legacy HFP headset PIN

Many old HFP/HSP devices use `0000`:

```bash
sudo ./hfp_pair --pin 0000 pair 11:22:33:44:55:66
```

`0000` is already the default.

### Numeric-comparison confirmation

The default is automated/no-input-no-output pairing, suitable for a headless
AG and "Just Works". If the AG has a real UI and MITM protection is required:

```bash
sudo ./hfp_pair \
  --io-cap display-yesno \
  --mitm \
  --no-auto-confirm \
  pair 11:22:33:44:55:66
```

### Passkey entry

```bash
sudo ./hfp_pair \
  --io-cap keyboard-only \
  --mitm \
  --passkey 123456 \
  pair 11:22:33:44:55:66
```

If a passkey is requested and `--passkey` was not supplied, the program prompts
on a TTY. In a non-interactive process it rejects that passkey request rather
than inventing a value.

## Accept pairing initiated by a nearby HF

```bash
sudo ./hfp_pair listen
```

The program enables page/inquiry scanning, accepts incoming BR/EDR ACL
connection requests, handles the pairing security events, stores the resulting
link key, then queries the remote HF SDP server and prints:

```text
PAIRED 11:22:33:44:55:66 HFP_HF_RFCOMM_CHANNEL=2
```

## Query SDP only

For an already connected/reachable peer:

```bash
sudo ./hfp_pair sdp 11:22:33:44:55:66
```

On success it prints only the RFCOMM channel number.

## Link-key database

Default:

```text
./linkkeys.db
```

Override:

```bash
sudo ./hfp_pair --db /var/lib/my-hfp-ag/linkkeys.db listen
```

Format:

```text
# BD_ADDR LINK_KEY KEY_TYPE
11:22:33:44:55:66 00112233445566778899AABBCCDDEEFF 04
```

The file is created with mode `0600` and replaced atomically.

## Security note

`--auto-confirm` is the default because the requested use case is a headless AG
that should pair without source changes. That is appropriate for SSP
"NoInputNoOutput / Just Works", but it does **not** provide MITM protection.
For devices requiring authenticated numeric comparison/passkey entry, use the
corresponding `--io-cap`, `--mitm`, and interactive/passkey options.

## What "pair with any nearby device" can and cannot mean

No Bluetooth implementation can force every arbitrary peer to pair. A peer may
reject bonding, require a user action, require MITM/passkey/OOB authentication,
or not expose HFP HF at all. This implementation handles the standard Classic
Bluetooth pairing mechanisms without changing source code, but the peer's
security policy still has to permit the pairing procedure.

## Integration point for your HFP AG

After this program prints:

```text
HFP_HF_RFCOMM_CHANNEL=N
```

connect your AG RFCOMM control socket to that channel and perform the HFP
Service Level Connection (BRSF/CIND/CMER/etc.). The SDP channel discovery here
is specifically for the remote **Hands-Free** service UUID `0x111E`.
