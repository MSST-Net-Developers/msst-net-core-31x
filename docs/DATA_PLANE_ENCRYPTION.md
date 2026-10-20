# Data-plane encryption (WireGuard, negotiated)

Status: P1 implemented (MSST-Net 3.1.x).  P2/P3 are planned.

Before this, data between peers travelled as plaintext MSST `TYPE_DATA`
frames, directly or through a relay: anyone on the path, the relay
included, could read or forge virtual-LAN traffic, and the inbound
firewall trusted a source IP that anyone could spoof.  boringtun was a
dependency, but no data was ever encrypted with it.

3.1.x does not keep wire compatibility with 3.0.x.  The plaintext
fallback below exists for peers that turned encryption off (and for a
relay that does not forward `TYPE_WG`), not for 3.0.x.

## Goals and constraints

- Relays forward by the MSST header's `dst_id`, so WireGuard messages are
  carried **inside an MSST header**; the direct and relay paths use the
  same format.
- Encryption is its own state dimension, orthogonal to the path mode
  (`relay` / `probing` / `direct`).  A path change never rebuilds a
  WireGuard session.
- The coordinator does not advertise capabilities today, so P1 negotiates
  in-band: the WireGuard handshake itself is the negotiation.
- The WireGuard static key is the device identity key; the coordinator's
  `public_key` is the peer's WireGuard key.  keyproof already proves the
  device holds it.

## Wire format

New MSST type **`TYPE_WG = 0x0D`** (`0x0A`–`0x0C` are secure discovery).
The payload is one unmodified WireGuard message (handshake initiation,
handshake response, cookie reply, or transport data):

```
[MSST header 23 B: "MSST", ver=1, type=0x0D, flags=0, src_id, dst_id][WireGuard message]
```

- The receiver finds the session by the header's `src_id`.  A forged
  `src_id` only gets the packet rejected by WireGuard authentication.
- Overhead: 32 bytes (WireGuard header 16 + tag 16).  With the default
  TUN MTU of 1280 the UDP payload is 1335 bytes.
- The old "any non-MSST datagram → try every WireGuard session" inbound
  branch is gone.

## Negotiation state machine (per peer)

```
               peer has a key, policy ≠ off,
               first packet to the peer
  unknown ─────────────────────────────────────► handshaking ──session usable──► encrypted
     ▲                                                │
     │                                                │ no session after 15 s
     │                                                ▼
     └──── retry due / key change / network ───── plaintext
           change / peer sent us TYPE_WG          (retry 5 min, doubling to 1 h)
```

The state says what we send to the peer:

| State | Outbound data |
|---|---|
| `unknown` | plaintext `TYPE_DATA`; the first packet also starts a handshake |
| `handshaking` | plaintext `TYPE_DATA` while the handshake runs, so connectivity is not interrupted |
| `encrypted` | `TYPE_WG` only, never plaintext |
| `plaintext` | plaintext `TYPE_DATA`; the next packet after `next_retry_at` starts a new handshake |

- Negotiation is started on demand by outbound traffic, not for every
  known node, so a large node cache does not cause handshake storms.
- The initiator's session is usable when the handshake response arrives;
  the responder's when the initiator's first transport packet (the
  keepalive boringtun sends right after the response) arrives.
- Retransmission, rekey and session expiry are boringtun's timers,
  driven by the existing 1 s scheduler tick.
- A peer that sends us any valid `TYPE_WG` message resets the backoff,
  and so does a network change.  A changed public key resets the peer to
  `unknown` with a fresh session.
- Passive side: with policy `prefer` we answer handshakes in any state.

### Sticky encryption (downgrade protection)

Once a session with a peer's current public key has been established,
the peer stays `encrypted` for the lifetime of that key, in memory only:

- outbound data to it is only ever sent through WireGuard; if the session
  expired, boringtun re-handshakes and queues the packet;
- plaintext `TYPE_DATA` from it is dropped.

So a relay or on-path attacker that drops handshakes cannot force an
established peer back to plaintext.  The cost: if that peer turns
encryption off, traffic with it stops until its key changes, our policy
changes, or our Core restarts.  The mark is not persisted.

## Security rules

1. **No plaintext from encrypted peers**: plaintext `TYPE_DATA` whose
   `src_id` is an `encrypted` peer is dropped (otherwise anyone could
   inject frames claiming to be that peer).
2. **Source binding**: a decrypted IP packet must come from the peer's
   own virtual IPv4/IPv6 address, like WireGuard's AllowedIPs, otherwise
   it is dropped.  The firewall's source-IP decisions are then backed by
   the peer's key.
3. Downgrade by dropping handshakes is handled by sticky encryption
   (above) for peers that were encrypted before; a peer never seen
   encrypted can still be kept on plaintext by an on-path attacker until
   P2/P3.

## Policy: network setting `data_encryption`

| Value | Behaviour |
|---|---|
| `prefer` (default) | Opportunistic: encrypt when the peer answers, plaintext otherwise |
| `off` | Never initiate or answer; every peer is plaintext |
| `require` (P2) | Only talk to peers that complete a handshake |

Switching the policy rebuilds every session and forgets sticky marks.

## Observability

- `GetPathView`, per peer:
  - `encryption`: `unknown` / `handshaking` / `encrypted` / `plaintext`;
  - `last_handshake_at`: when the current session was established, if any;
  - `next_retry_at`: in `plaintext`, when a new handshake may start.
- IPC event `EncryptionChanged { device_id, old_state, new_state }`.
- P2: `msst_core_wg_sessions_total`, `msst_core_wg_handshakes_total`.

## Phases

1. **P1** (done): `TYPE_WG`, the state machine, `prefer` / `off`, security
   rules 1 and 2, sticky encryption, diagnostics and the event.
2. **P2**: `require`, metrics.
3. **P3** (needs a coordinator change): `capabilities: ["wg1"]` in
   `register`, forwarded to peers.  A peer known to support WireGuard is
   never downgraded, closing the remaining downgrade gap.

## Open question

Whether deployed relays forward an unknown MSST type (`0x0D`).  If a relay
drops it, handshakes over that relay time out and the peers stay on
plaintext until a direct path exists.
