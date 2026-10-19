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
