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

## Vectors

`crates/msst-ipc-protocol/tests/vectors/*.json` now show `seq` /
`event_seq` (normalized to 1) and `Health.ipc_role`.
