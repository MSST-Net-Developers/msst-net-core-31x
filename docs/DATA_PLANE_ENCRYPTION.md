# Data-plane encryption (WireGuard only)

Status: implemented (MSST-Net 3.1.x).

All data between peers is WireGuard-encrypted, on the direct path and
through relays.  There is no plaintext mode, no setting to turn it off and
no fallback: a peer that cannot complete a WireGuard handshake cannot
exchange data.  3.1.x is not wire-compatible with 3.0.x (which sent
plaintext MSST `0x04` frames).

Relay requirements: `docs/RELAY_REQUIREMENTS_3.1.md`.

## Keys

- The WireGuard static key is the device identity key (`private.key`).
- A peer's WireGuard public key is its `public_key` from the coordinator
  (`room_state`, `member_joined`, `/nodes/*`).  keyproof v1 proves to the
  coordinator that the device holds the key it registered.
- A peer without a public key cannot be reached (`GetPathView`:
  `encryption: "no_key"`); sending to it triggers a node fetch.
- A changed public key rebuilds the peer's session.

## Wire format

MSST type **`TYPE_WG = 0x0D`** carries exactly one WireGuard message
(handshake initiation, handshake response, cookie reply or transport data),
unmodified:

```
[MSST header 23 B: "MSST", ver=1, type=0x0D, flags=0, src_id, dst_id][WireGuard message]
```

- Relays forward by `dst_id`, so the same frames work directly and via a
  relay.
- The receiver finds the session by the header's `src_id`.  A forged
  `src_id` only gets the message rejected by WireGuard authentication.
- Overhead: 32 bytes (WireGuard header 16 + tag 16).  With the default TUN
  MTU of 1280 the UDP payload is 1335 bytes; with the maximum MTU override
  (1500), 1555 bytes.
- Retired and ignored: `0x04` (plaintext data), `0x08` / `0x09`
  (unauthenticated discovery), raw IP datagrams.

## Session state (per peer)

```
           packet to the peer, or
           the peer's handshake
  unknown ─────────────────────────► handshaking ──session usable──► encrypted
     ▲                                 │      ▲                         │
     │                     no session  │      │ packet to the peer /    │ idle: keys
     │                     after 15 s  ▼      │ the peer's handshake    │ erased
     │                               failed ──┘                         │
     └──────────────────────────────────────────────────────────────────┘
```

- Handshakes start on demand: the first packet to a peer (or the peer's
  own handshake).  A large node cache causes no handshake storm.
- Packets sent before the session exists wait in boringtun's per-peer
  queue and go out encrypted as soon as it does.
- Retransmission (every 5 s, up to 90 s), rekey, keepalive and expiry are
  boringtun's timers, driven by the 1 s scheduler tick.  When boringtun
  gives up, the queue is dropped; the next packet starts a new handshake.
  Retries are therefore bounded by traffic.
- The initiator's session is usable when the handshake response arrives;
  the responder's when the initiator's first transport packet (the
  keepalive boringtun sends right after the response) arrives.
- `failed` only reports that the last handshake got no answer within 15 s.
- An idle session whose keys boringtun erased goes back to `unknown`.

## Routing

The session is independent of the path (`relay` / `probing` / `direct`): a
path change never rebuilds it.  Every `TYPE_WG` frame to a peer, including
replies to its handshakes, goes to the peer's direct endpoint when the path
is direct, otherwise to the peer's relay, falling back to our own relay.

## Relay-path probe (in-tunnel)

While a peer's path is `probing`, Core measures the round trip data really
takes over the relays — A → B's relay → B → A's relay → A — as the
baseline a direct path must beat.  Plain `0x06` / `0x07` can't do this:
a relay forwards `0x06` only from the address bound to the sender (sreg)
and only to devices registered with it, so across two relays one hop
always drops it.  The probe therefore travels inside the WireGuard session
like data:

- Inner packet: IPv4, protocol 253 (RFC 3692 experimentation), from the
  sender's virtual IPv4 to the receiver's; payload (18 bytes):
  `"MSRP" ‖ kind (1 ping, 2 pong) ‖ 0 ‖ seq (u32 BE) ‖ sent_ms (u64 BE)`.
- Sent every 2 s while probing, only over an established session (a probe
  never starts a handshake), always over the relay route (the peer's
  relay, else ours), never the direct path.
- The receiving Core answers a ping itself over its relay route back to
  the sender and never delivers probes to the TUN; the pong is matched by
  `seq`, and `sent_ms` (the sender's own clock, echoed) gives the RTT.
- Probes pass the same source-binding check as data.
- 0x06 / 0x07 are now used on the direct path only.

## Security rules

1. Peer data is only accepted from `TYPE_WG` frames that decrypt with that
   peer's session.
2. **Source binding**: a decrypted IP packet must carry the peer's own
   virtual IPv4/IPv6 address as its source (WireGuard "AllowedIPs"),
   otherwise it is dropped.  The firewall's source-IP decisions are thus
   backed by the peer's key.
3. Relays see only MSST headers (device IDs, sizes, timing), never content.

## Observability

- `GetPathView`, per peer:
  - `encryption`: `no_key`, `unknown`, `handshaking`, `encrypted` or
    `failed`;
  - `last_handshake_at`: when the current session was established, if any.
- IPC event `EncryptionChanged { device_id, old_state, new_state }` (same
  names, except `no_key`, which is not a session state).
- Planned: `msst_core_wg_sessions_total`, `msst_core_wg_handshakes_total`.
