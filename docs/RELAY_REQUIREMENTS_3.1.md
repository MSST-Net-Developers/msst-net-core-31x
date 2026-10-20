# Relay requirements for MSST-Net Core 3.1.x

Audience: whoever (human or AI) changes the relay server.  This document
describes exactly what a 3.1.x Core sends to and expects from a relay.  It
is written from the client side; the relay's own internals are up to the
relay.

## Summary of changes from 3.0.x

1. **All peer data is WireGuard**, in a new MSST type **`0x0D`**, which the
   relay must forward by `dst_id` exactly like it forwarded `0x04`.
2. **Plaintext data `0x04` is retired.**  3.1.x clients never send it and
   ignore it.
3. **Unauthenticated discovery (`0x08`, `0x09`, bare IPv4 delivery to
   UDP 21032) is retired.**  Only secure discovery (sdisc v1: `0x0A`,
   `0x0B`, `0x0C`) is used.
4. **sdisc must run in `required` mode**: clients drop any `0x0C` whose
   sender-verified flag (bit 0) is not set.
5. **Every relay must advertise its sdisc `pub_key`** in the coordinator's
   `GET /relays`; without it, clients have no game discovery through that
   relay.

3.0.x clients are not supported.  No compatibility mode is needed.

## Packet format

Every packet is an MSST frame:

```
offset size
0      4    magic "MSST"
4      1    version = 1
5      1    type
6      1    flags (0 unless stated)
7      8    src_id  — sender device ID, big-endian u64 (lower 32 bits used)
15     8    dst_id  — destination device ID, same encoding; 0 when unused
23     N    payload
```

Device IDs are `device-XXXXXXXX` (8 hex digits); the wire value is the hex
number, e.g. `device-a1b2c3d4` → `00 00 00 00 a1 b2 c3 d4`.  The legacy
`dev-` prefix is gone.

## What the client sends and expects

The client's main socket is UDP 21031; its discovery socket is UDP 21032.
Both send to the relay address listed in `GET /relays` (`addr`).

| Type | Name | From → to | Relay must |
|---|---|---|---|
| `0x0E` | sreg register | client:21031 → relay | Only to relays whose `/relays` entry has `"sreg1"` in `features` and a valid `pub_key` (see "Registration" below). Replaces `0x01` and `0x02`. |
| `0x01` | register | client:21031 → relay | Other relays only. Record `src_id` → source address. Sent after every relay selection (and on every coordinator reconnect). Empty payload. |
| `0x02` | keepalive | client:21031 → relay | Other relays only. Refresh the `src_id` → address mapping. Every 25 s by default (user setting 5–30 s). Empty payload. |
| `0x05` | relay ping | client:21031 → relay | **Echo the datagram unchanged** back to its source, from the same socket. Every 5 s; the client measures RTT and matches replies by source address. |
| `0x06` | p2p ping | client → relay → peer | Forward unchanged to the address registered for `dst_id`. 12-byte payload. Used to measure the relay path RTT. |
| `0x07` | p2p pong | peer → relay → client | Same as `0x06`. |
| **`0x0D`** | **WireGuard** | client → relay → peer | **Forward unchanged to the address registered for `dst_id`.** Payload is one WireGuard message, opaque to the relay. |
| `0x0A` | sdisc register | client:21032 → relay | As in `SECURE_DISCOVERY.md` (records the 21032 mapping). |
| `0x0B` | sdisc data | client:21032 → relay | As in `SECURE_DISCOVERY.md` (verify, then fan out to room members as `0x0C`). |
| `0x0C` | sdisc deliver | relay → client:21032 | Only for verified senders: **flags bit 0 must be set**. |

Retired, never sent by 3.1.x clients; the relay may drop them: `0x04`,
`0x08`, `0x09`, and anything without the MSST magic.  Clients never accept
bare IPv4 on UDP 21032 any more.

### Forwarding `0x0D` (the important one)

- Look up `dst_id` in the registrations (`0x0E`, or `0x01` / `0x02`), send the whole
  datagram there, byte for byte (header included).  Do not inspect, modify,
  decrypt or reorder the payload.  Unknown `dst_id` → drop silently.
- **The sender is often not registered with this relay.**  A client sends
  to the *destination peer's* relay (the `relay:host:port` endpoint the
  peer advertised to the coordinator), falling back to its own relay.  So
  the relay must forward frames from any source to its registered
  destinations, and must not require `src_id` to be registered with it.
  The reply comes back through the other peer's own relay.
- Sizes: the payload is the IP packet + 32 bytes, plus the 23-byte header.
  With the default TUN MTU (1280) that is 1335 bytes; with the maximum MTU
  override (1500), 1555 bytes; handshake messages are smaller (148 / 92 /
  64 bytes).  **Accept and forward datagrams of at least 1600 bytes**
  (ideally up to 65 507).
- `0x0D` volume equals the old `0x04` volume plus a few handshake messages
  every 2 minutes per active peer pair; apply the same rate limits as for
  `0x04`.

## Secure discovery

Unchanged except for the mode: follow `SECURE_DISCOVERY.md` and run it in
**`required`** mode.  In `optional` mode the relay would deliver `0x0C`
from unverified senders with bit 0 clear; 3.1.x clients count and drop
those (`GetRelays` → `secure_discovery.drop.unverified_sender`), so such traffic is
wasted.  Relays without a `pub_key` in `GET /relays` get no discovery
traffic at all from 3.1.x clients.

## Coordinator `GET /relays`

Each entry must carry `addr` and `pub_key` (base64 X25519, 32 bytes).
Unchanged otherwise.

## Registration (sreg v1)

Implemented as specified in the relay's `REGISTRATION_AUTH.md`:

- Mode per relay, decided at selection from `GET /relays`: `features`
  contains `"sreg1"` **and** `pub_key` is a valid 32-byte key → `0x0E`;
  otherwise the legacy `0x01` / `0x02`.  A relay that takes `0x0E` never
  gets `0x01` / `0x02`, and the client never falls back at runtime.
- `k_reg` per (relay key, device), salt `msst-sreg-v1`; a low-order relay
  key (all-zero shared secret) makes the relay unusable for registration.
- Counter `max(last + 1, now_ms << 16)`, strictly increasing.
- Schedule after every relay selection or change and every coordinator
  reconnect: immediately, ~1 s, ~3 s, then every keepalive interval.
- Success shows up as relay-path `0x06` / `0x07` round trips through the
  client's own relay (`GetRelays.registration.last_relay_path_ok_at`).

## Recommended (not required by 3.1.x clients)

- Drop non-MSST datagrams and unknown types early, and count them.
- Per-source rate limits on `0x05` and on unknown `dst_id`.

## Acceptance checklist

1. Two 3.1.x clients A and B, registered with **different** relays R_A and
   R_B, in the same room: A pings B's virtual IP and gets replies.  On R_B
   only `0x0D` frames carry data (A → R_B → B), and on R_A, B → R_A → A.
   No `0x04` appears anywhere.
2. Same with both on one relay.
3. A 1500-byte ping (`ping -s 1472` with MTU override 1500) passes.
4. `0x05` is echoed byte for byte.
5. Game discovery (e.g. Minecraft LAN) works between A and B, and every
   `0x0C` has flags bit 0 set.  A client's `GetRelays` shows
   `secure_discovery.active = true` and
   `secure_discovery.drop.unverified_sender = 0`.
6. A `0x0D` frame to an unknown `dst_id` is dropped without error replies.
