# IPC protocol 0.4 — changes for Controllers

Core 0.4 stays wire-compatible with 0.3 Controllers: every new envelope
field is optional and omitted when unused, and new requests/events are
additive.  What a Controller **must** know is marked ⚠.

## 1. Permissions (`access`)

Each connection has a role, decided by Core from the OS identity of the
connecting process — no credentials in the protocol.

| Role | May send |
|------|----------|
| `viewer` | queries, `SetLogStream`; receives every event |
| `admin` | everything (all commands) |

Admins: root / LocalSystem, Core's own user, the `sudo` invoker, members of
the local group **`msst-net`** (Linux/macOS) or **`MSST-Net Administrators`**
(Windows), and elevated Administrators (Windows; a non-elevated UAC token
doesn't count).  Other users who may connect (logged-in local users) are
viewers.  Android (embedded Core, app-private socket) is always admin.

- `Health.ipc_role` = `"viewer"` | `"admin"`.
- A request above the role → error `permission_denied`; the connection
  stays open.  Show "read-only" UI instead of failing per action.
- ⚠ **Deployment:** installers must create the group and add the installing
  user to it.  Without that, a desktop user talking to a root/SYSTEM Core
  becomes read-only after upgrading.  Group membership is checked at every
  connect: reconnect after adding the user, no Core restart needed.

## 2. Event `seq` and snapshot point

- Every state event has `"seq"` (envelope field): 1, 2, 3 … per Core run,
  no gaps.  Log lines streamed as `Diagnostic` carry no `seq`.
- Every response has `"event_seq"`: the last `seq` emitted before Core
  read any state for it.

Recommended sync:

1. Connect (you are subscribed from this moment).
2. Send snapshot queries; buffer events meanwhile.
3. For each response, events with `seq <= event_seq` are already
   reflected — skip them; apply the rest idempotently (one just above
   `event_seq` may also be reflected).
4. A gap in `seq` ⇒ events were lost ⇒ re-snapshot.  (Core disconnects a
   client that falls behind, so a gap normally shows up as a reconnect.)

`seq` restarts at 1 when Core restarts; `generation` keeps its 0.3 meaning.

## 3. Concurrency ⚠

- Queries run concurrently (up to 16 per connection); commands run one at
  a time in arrival order per connection.
- ⚠ **Responses may arrive out of order** — correlate strictly by `id`.
- A query sent before an earlier command's response arrived may not see
  that command's effect.  Wait for the response if you need it.
- A slow command (e.g. `CreateRoom`) no longer blocks `Health` or other
  queries on the same connection.

## 4. Async commands (opt-in)

Add `"async": true` to a command request:

```json
{"kind":"request","id":"7","async":true,"body":{"type":"create_room","params":{"room_name":"x","password":null}}}
```

- Response at once: `{"operation_id":"op-3"}` (or an error such as
  `permission_denied` / `busy`).
- Then events `operation_progress {operation_id, stage}` (create/join room:
  `relay_selected`, `room_created`, `join_sent`) and finally
  `operation_completed {operation_id, request_type, result}`, where
  `result` is exactly what the synchronous request would have returned.
  The completion never arrives before the accepted response.
- `GetOperation {operation_id}` → `status` `running` (with `stage`) or
  `completed` (with `result`, `finished_at`).  Finished operations stay
  queryable for 10 minutes (last 64), so a Controller that reconnects
  mid-operation can still get the outcome.
- At most 16 operations run Core-wide; beyond that → `busy`.
- Operations belong to Core: they finish even if the Controller
  disconnects.
- `async` on a query is ignored (answered normally).  Without `async`,
  commands behave exactly as in 0.3.

## 5. Smaller changes

- **Handshake:** on an incompatible major version Core now sends one frame
  before closing: response id `"handshake"`, error `incompatible_version`.
- **Frame limit (1 MiB) on Core's side too:** an oversized response becomes
  error `response_too_large` (same `id`); an oversized event closes the
  connection (reconnect + re-snapshot).
- **`SetLogStream {enabled}`:** stop/start log lines (`Diagnostic` events)
  on this connection; default on.  `GetLogs` is unaffected.
- **New error codes:** `permission_denied`, `busy`, `incompatible_version`,
  `response_too_large`, `invalid_display_name`.
- **Names and handles can be cleared** (`UpdateDisplayName`,
  `UpdateHandle`): a field left out (`null`) is unchanged; `""` (or only
  whitespace) clears it — previously `UpdateHandle` rejected `""` with
  `invalid_handle`.  A cleared value is reported as `null`, like one never
  set, and Core registers the default instead: the device handle becomes
  the device ID (so the ezPlay hostname becomes
  `<device_id>.<user handle or ID>.ezplay.net.msst2031.cn`), the device display
  name becomes `用户<short user ID>的设备`, the user ID without its
  `user-` prefix, at most 8 characters (`user-1a2b3c4d` →
  `用户1a2b3c4d的设备`).  Display names are trimmed and at
  most 64 characters without control characters (else
  `invalid_display_name`).
- **Immediate coordinator sync:** both commands re-register the device
  right away when something changed and add `"synced": bool` to the
  reply.  `false` means the change is saved in Core but the coordinator
  refused or could not be reached (e.g. an unauthenticated device on a
  coordinator with OIDC enabled: `POST /device/register` needs a token);
  it is sent with the next registration (WS reconnect).
- **`PathChanged` mode names are always `relay`, `probing` or `direct`**
  (pong-driven changes used to send Rust debug text such as `Probing` /
  `Direct { endpoint: … }`).  New optional `endpoint` (`"ip:port"`) when
  the new mode is `direct`; `direct` → `direct` means the direct path
  switched to a better endpoint.  The punch-triggered `relay` → `probing`
  transition is now reported too.
- **`GetPathView`:** a direct peer also lists its background-probed
  candidates; a peer whose probes keep failing has `probe_failures` and
  `next_probe_at` (Unix seconds — no probing before then: 30 s after the
  first failed round, doubling up to 10 min; new peer endpoints, a
  `punch_request` or a network change probe at once).
- **Data-plane encryption** (`docs/DATA_PLANE_ENCRYPTION.md`): all peer
  data is WireGuard; there is no setting and no plaintext mode.
  - `GetPathView`: every peer has `encryption` — `no_key` (the
    coordinator gave no public key: the peer is unreachable), `unknown`,
    `handshaking`, `encrypted` or `failed` (last handshake unanswered) —
    and `last_handshake_at` (Unix seconds) while a session exists;
  - new event `EncryptionChanged {device_id, old_state, new_state}` with
    the session states (`unknown`, `handshaking`, `encrypted`, `failed`).
- **Game discovery over WireGuard (Core 3.1.6)** — replaces the
  relay-based secure discovery (`GetRelays.secure_discovery`, removed):
  each discovery datagram goes to every room member separately inside its
  WireGuard session, so the sender is authenticated end to end
  (`docs/SECURITY_3.1.6.md`).  There is no fallback to the relays.
  - `GetRelays.discovery`: `transport` (`"wireguard"`), `tx_messages`
    (one per member per datagram), `tx_skipped_unsupported` (datagrams a
    member didn't get because it doesn't support this), `rx_accepted`
    (datagrams injected), `drop.not_member`, `drop.not_discovery`,
    `drop.rate_limited` (over 10/s per sender or 100/s in total).
  - Room view (`GetSystemState.room.peers[]`, `RoomStateChanged.peers[]`):
    each member has `discovery` (`null` for ourselves): `"ok"`,
    `"unsupported"` (Core 3.1.5 or older, or the embedded Android Core:
    no game discovery with it in either direction — show it, e.g. "该成员
    版本过旧，无法互相发现游戏") or `"unknown"` (no endpoints from it
    yet).
- **`GetRelays.registration`** (relay registration, see
  `docs/RELAY_REQUIREMENTS_3.1.md`): `mode` (`"sreg1"` — authenticated
  `0x0E` — or `"legacy"`), `tx_sreg` (`0x0E` packets sent) and
  `last_relay_path_ok_at` (Unix seconds a relay-path probe — in-tunnel,
  sent while a peer is `probing` — last came back through our relay,
  proving its binding works; `null` if never).  Relay
  list entries may carry `features` (passed through from the coordinator).
- **Guest access** (no valid MSST login): Core connects to the
  Coordinator with a guest token (`POST /auth/guest/token`) — always when
  the device never logged in, and when the Coordinator refuses the stored
  OIDC credentials and the refresh token too.  In the latter case
  `AccessAuthRequired` is emitted as before, but the device stays online in
  room mode instead of retrying the dead token forever.  A new login
  (`AuthPoll`) or a successful refresh reconnects with OIDC at once.
  - dead credentials are dropped: the user ID falls back to the one
    derived from the device key (`user-<8 hex>`, as before the first
    login) and the user handle is cleared (registered as the ID);
    `IdentityChanged` reports this with `is_authenticated: false`.  Device
    fields and the user display name are kept.  A refresh that can't be
    attempted (Coordinator unreachable) keeps the credentials.
  - new `Health.coordinator_credential`: `"oidc"`, `"guest"` or `"none"`
    (disconnected, or a Coordinator without guest tokens);
  - `Health.is_authenticated` is now `false` while the Coordinator refuses
    the stored credentials, even if their expiry time hasn't passed.
  - the OIDC access token (5 minutes on the MSST platform) is refreshed in
    the background before it expires, and a Coordinator API call that
    still gets a 401 refreshes it and retries once.  Previously Core only
    refreshed at startup and on reconnect, so 5 minutes after start every
    API call (endpoint reports, node lookups, rooms, DNS, ACL name
    resolution) failed with `access_auth_invalid` while the WebSocket stayed
    up.  A refused refresh ends the login when the token expires (guest
    mode and `AccessAuthRequired`, as above).  Only MSST-IAS refusing the
    refresh token (`invalid_grant`) counts as refused; when MSST-IAS fails
    or can't be reached (Coordinator 502, or older Coordinators' 401 with
    `server_error` etc.), rate limiting and 5xx, Core keeps the login and
    retries.
- **Interactive authorization:**
  - an unanswered request times out 60 s after it was raised
    (`AccessRequestTimeout` within about a second; it used to take up to
    another minute).  `AuthDecision` for an expired request fails with
    `not_found`, even before the timeout event — so a Controller whose
    countdown reached 0 can close the prompt;
  - at most 3 requests per source device and 16 in total are pending at
    once.  Beyond that no prompt is raised; the access log records
    `silent_deny` with reason `{"type": "interactive_auth_limit"}`;
  - if applying a decision fails (e.g. `persist_failed` when saving the
    rule), the request stays pending and can be answered again; no
    `AccessRequestResolved` is sent for the failed attempt.
- **Rooms** (`docs/ROOM_RELAY_3.1.md`):
  - one room at a time: `CreateRoom` / `JoinRoom` while in a room fail
    with the new code `already_in_room` (leave first); the Coordinator
    enforces it too and its refusal maps to the same code.  Room
    operations (create, join, leave) run one after another;
  - room passwords are still given to Core in plain text, but leave
    Core only as Argon2id verifiers.  `JoinRoom` without `password` for a
    room that has one fails with the new code `room_password_required`
    before anything is sent; a password given for a room without one is
    ignored.  An unknown or malformed room ID fails with `room_rejected`.
  - **room relay**: `CreateRoom` takes optional `relay` — a connection
    string `msst-relay://host:port#<key>[?pw=1]` or an official relay's
    address — and `relay_password` (sent only as an Argon2id verifier).
    New codes: `invalid_relay` (not a valid link, or an address that is
    not an official relay), `relay_password_required` (the link says the
    relay has a password and none was given — checked before anything is
    sent; the Coordinator also returns it), and from the Coordinator
    `relay_offline`, `relay_unsupported`, `relay_password_wrong`,
    `room_password_required` (the relay requires a room password).  Other
    Coordinator refusals stay `room_create_failed`;
  - our own entry in the room view's `peers` has the default device
    display name (`用户<short user ID>的设备`, what peers see) when none is
    set, instead of `null`;
  - the room view (`GetSystemState`) and `RoomStateChanged` carry
    `room_relay`: `{address, self_hosted, state}` with `state` `probing`,
    `ok` (room traffic uses it) or `down` (fallback to preferred
    relays), or `null`.  `RoomStateChanged` is also sent when the state
    changes.  `GetRelays.room_relay` adds `addr` (resolved) and `tx_sreg`.
- **Relay addresses keep their host names:** `Health.relay`, the room
  view's `relay` and `GetRelays.current` are the relay's address as
  listed by the Coordinator or configured as the preferred relay (e.g.
  `relay1.msst-net.msst2031.cn:7000`), no longer the IP it resolved to.  Peers get the
  name in our `relay:` endpoint and resolve it themselves (in their own
  address family); `room-relay:` likewise carries the room relay's
  address.  Core caches a lookup for 60 s.
- **Other VPNs on the same host** (desktop Core):
  - new setting `bypass_other_vpns` (`GetNetSettings` / `SetNetSettings`,
    boolean, default `true`, applies immediately; Linux): Core's own
    traffic — UDP to peers and relays, and the Coordinator connections
    (WebSocket and HTTP) — uses the main routing table instead of another
    VPN's full tunnel (Tailscale exit node, wg-quick, Clash TUN…).  Other
    programs' traffic is not affected.  Turn it off when relays or the
    Coordinator are only reachable through such a VPN.
    A non-boolean is `invalid_settings`;
  - new setting `block_other_vpns_over_msst` (boolean, default `true`,
    applies immediately; Linux): other VPNs may not use MSST-Net as their
    path.  Tailscale advertises MSST-Net's address as an endpoint and,
    between two machines on MSST-Net, otherwise tunnels through MSST-Net
    (WireGuard inside WireGuard).  Only tailscaled's own packets to the
    MSST-Net ranges are
    refused (it marks its sockets); Tailscale then uses its other paths.
    Turn it off to let Tailscale use MSST-Net when that path is faster.  Not
    for ZeroTier (use its `interfacePrefixBlacklist`).  A non-boolean is
    `invalid_settings`;
  - on Linux the MSST-Net ranges are routed to the MSST-Net interface ahead of
    other VPNs' policy rules — unless another interface has a route inside
    a range (e.g. a Docker network on `172.22.0.0/16`): then that is
    reported instead;
  - new `GetSystemState.network_warnings` (Linux, macOS; checked at
    start and every minute, a change advances `generation`): a list of
    `{kind, range, interface, route}` — `kind` `route_conflict` (another
    interface's route `route`, e.g. `172.22.0.0/16 dev br-1a2b table
    main`, lies inside the MSST-Net range `range`) or `route_hijacked`
    (traffic to an address in `range` leaves through `interface`; `route`
    is `null`).  Empty when all is well, and always empty on Windows,
    Android and without a TUN.
- **Removed from `Health`:** `local_device_id` and `local_user_id`
  (3.1.0-alpha aliases); use `device_id` and `user_id`.
- **Peers' empty names / handles** are `null` in `GetNodes`, `NodeAdded`
  and `NodeStateChanged` (previously `""` was passed through); a peer
  without a device ID is ignored instead of failing the whole
  `room_state`.
- **`StartDiagPing` measures the path the peer's traffic takes:** its
  active direct endpoint (P2P ping) while the path is direct, otherwise a
  probe inside the WireGuard session through the relays, answered by the
  peer's Core (a handshake is started if there is no session, so the
  first result may include it).  It used to always ping the first
  announced direct endpoint, which timed out for every relayed peer and
  sent direct packets with P2P disabled.  `GetDiagPingResult` adds
  `path`: `"direct"` | `"relay"`.
- **Typed bodies** (`msst_ipc_protocol::views`): `Health`, `GetNodes`
  (`Nodes`), `GetNode` (`NodeDetail`), `OperationAccepted`,
  `OperationView`.  JSON is unchanged; Rust Controllers can decode with
  these types (the contract vectors are checked against them).

## Vectors

`crates/msst-ipc-protocol/tests/vectors/*.json` now show `seq` /
`event_seq` (normalized to 1) and `Health.ipc_role`.
