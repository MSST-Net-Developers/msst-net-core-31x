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
  `<device_id>.<user handle or ID>.ezplay.msst.net`), the device display
  name becomes `用户<user_id>的设备`.  Display names are trimmed and at
  most 64 characters without control characters (else
  `invalid_display_name`).
- **Immediate coordinator sync:** both commands re-register the device
  right away when something changed and add `"synced": bool` to the
  reply.  `false` means the change is saved in Core but the coordinator
  refused or could not be reached (e.g. an unauthenticated device on a
  coordinator with OIDC enabled: `POST /device/register` needs a token);
  it is sent with the next registration (WS reconnect).
- **Peers' empty names / handles** are `null` in `GetNodes`, `NodeAdded`
  and `NodeStateChanged` (previously `""` was passed through); a peer
  without a device ID is ignored instead of failing the whole
  `room_state`.
- **Typed bodies** (`msst_ipc_protocol::views`): `Health`, `GetNodes`
  (`Nodes`), `GetNode` (`NodeDetail`), `OperationAccepted`,
  `OperationView`.  JSON is unchanged; Rust Controllers can decode with
  these types (the contract vectors are checked against them).

## Vectors

`crates/msst-ipc-protocol/tests/vectors/*.json` now show `seq` /
`event_seq` (normalized to 1) and `Health.ipc_role`.
