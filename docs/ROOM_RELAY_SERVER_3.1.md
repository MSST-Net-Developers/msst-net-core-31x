# 房间中转与自托管中转：Coordinator 与中转实施要点

2026-10-20 · 客户端基线：msst-net-core-31x `f31b54d` · Coordinator：msstnetCoordinator31x `ff1afdc` · 中转：msstnetRelay31x `f5cd369`

设计与已定决策（D1–D14）见客户端仓库 `docs/ROOM_RELAY_3.1.md`。本文只列 Coordinator 与中转要做的事，以及接口格式、错误码、测试向量、上线顺序与验收清单。客户端第 3 步（双中转注册、回退、选路）在本文各项上线后再做；在此之前客户端不会在建房时携带 `relay`，也会忽略 `room_state.relay`，所以本文各项可以先行部署。

## 一览

| 编号 | 组件 | 事项 |
|---|---|---|
| P1 | Coordinator | 前置：`SERVER_FOLLOWUPS_3.1.md` 的 C6、C7、C8（C7、C8 必须与客户端 `f31b54d` 同时上线） |
| CR1 | Coordinator | 官方中转改用每台独立的预共享密钥；`GET /relays` 只列官方中转 |
| CR2 | Coordinator | 自托管中转登记：质询-应答、令牌、心跳 |
| CR3 | Coordinator | 自托管中转的凭据范围：只限指定了它的房间 |
| CR4 | Coordinator | 建房时指定房间中转：校验与错误码 |
| CR5 | Coordinator | `room_state` 下发房间中转 |
| RR1 | 中转 | `relay.mode: self_hosted`：登记、心跳、令牌 |
| RR2 | 中转 | 自托管模式强制 `register_auth: required` |
| RR3 | 中转 | 自托管模式下 `0x0D` 只接受已注册的发送方 |
| RR4 | 中转 | 中转密码与 `require_room_password` |
| RR5 | 中转 | 打印连接串 |
| RR6 | 中转 | 拉取 `discovery-peers` / `device-keys` 时使用自托管令牌 |

## Coordinator

### CR1 官方中转：每台独立的预共享密钥

现状：全体中转共用一个 `relay_secret`，而且 `relay_secret` 为空时 `checkRelaySecret` 放行一切请求（`relay.go`）。

- 配置改为按中转列出密钥的哈希：

  ```yaml
  official_relays:
    - id: relay-hk-1
      secret_sha256: "<hex>"     # SHA-256(密钥)，Coordinator 不保存明文
  ```

- `X-Relay-Secret` 先算 SHA-256，再与列表做常数时间比较，从而确定是哪一台中转。`/relay/register` 与 `/relay/heartbeat` 请求体中的 `id` 必须与之一致，否则返回 403。
- 删除“密钥为空即放行”。如需本地开发，用显式的 `relay_auth: off`，启动时打印警告。
- 迁移：可以保留旧的共用 `relay_secret` 一段时间（配置开关 `legacy_relay_secret`），两种都接受；全部中转换上独立密钥后删除。
- `GET /relays` 只列官方中转，自托管中转永不出现。

### CR2 自托管中转登记

自托管中转用它的 X25519 密钥（`discovery.auth_key_file`）证明身份，方法与设备 keyproof v1 相同，只换了标签和输入。**登记本身不授予任何权限**，权限只来自“有房间指定了它”（CR3）。

**1. 取质询**

```
POST /relay/self-hosted/challenge
{"pub_key": "<base64，32 字节>"}
→ 200 {"challenge_id": "<32 位小写十六进制>", "server_pub": "<base64>"}
```

- 每个质询使用一个新的临时 X25519 密钥，60 秒有效，只能使用一次。
- 每个 `pub_key` 同时最多一个未用质询；全局未用质询设上限（例如 10000）。
- 按来源 IP 限流（例如每分钟 10 次）。
- 公钥是低阶点（共享密钥全零）时返回 400。

**2. 登记**

```
POST /relay/self-hosted/register
{
  "pub_key": "<base64>",
  "addr": "relay.example.com:7000",
  "features": ["sdisc1", "sreg1"],
  "password_verifier": "<base64，32 字节；没设密码时省略>",
  "require_room_password": true,
  "proof": {"challenge_id": "<hex>", "mac": "<base64，32 字节>"}
}
→ 200 {"relay_id": "self-<16 位 hex>", "token": "<base64url>", "expires_at": <unix 秒>}
```

证明的计算方法：

```
shared = X25519(relay_sk, server_pub)            # 全零则拒绝
k      = HKDF-SHA256(ikm = shared, salt = "msst-relay-keyproof-v1",
                     info = relay_pub (32) ‖ server_pub (32), L = 32)
mac    = HMAC-SHA256(k, "msst-relay-keyproof-v1" ‖ challenge_id 的原始 16 字节)
```

校验与处理：

- 证明不对或质询已过期：401，`code: "key_proof_invalid"`。
- `features` 不同时含 `sdisc1` 与 `sreg1`：400，`code: "relay_unsupported"`（D7）。
- `addr` 必须是 `host:port`；它就是下发给客户端的地址，应是公网可达的地址。
- 与某台官方中转公钥相同：409。
- 同一公钥再次登记会覆盖原记录（地址、密码校验值等），旧令牌作废。
- `relay_id` 取 `"self-"` 加上 SHA-256(公钥) 的前 8 字节（16 位十六进制）。
- 保存 `SHA-256(password_verifier)`，不保存校验值本身。
- 令牌是 32 字节随机数（base64url 编码），只保存 SHA-256(令牌)；有效期与在线状态绑定（见下）。
- 全局最多保存若干自托管中转（例如 10000），超出返回 503。

**3. 心跳**

```
POST /relay/heartbeat
Authorization: Bearer <token>
→ 200 {"expires_at": <unix 秒>}
```

- 与官方中转相同：30 秒没有心跳就移除，令牌随之失效。中转收到 401 时重新走质询与登记。
- 自托管中转的登记与令牌都只在内存中。Coordinator 重启后，中转的下一次心跳得到 401，随即重新登记。

### CR3 自托管中转的凭据范围

自托管中转带 `Authorization: Bearer <token>` 访问以下接口（官方中转继续用 `X-Relay-Secret`）：

| 接口 | 自托管中转能拿到的内容 |
|---|---|
| `GET /room/{id}/discovery-peers` | 仅当该房间的房间中转公钥等于它的公钥；否则 403 |
| `POST /relay/device-keys` | 只返回“指定了它的房间”的**当前成员**的公钥；其他设备省略（中转按 `key_unknown` 处理） |

房间解散后范围自动收回。

### CR4 建房时指定房间中转

`POST /room/create` 新增可选字段 `relay`（与 C7 的 `password` 并列）：

```json
{
  "room_name": "…",
  "password": {"salt": "…", "verifier": "…"},
  "relay": {
    "pub_key": "<base64>",
    "password_verifier": "<base64；仅带密码的自托管中转>"
  }
}
```

**按中转公钥**查找已登记（在线）的中转，官方中转和自托管中转都可以。房间中转的地址使用中转**登记时上报的** `addr`，不取客户端提交的地址：连接串里的地址与登记地址来自同一份中转配置，以登记地址为准可以避免两者不一致。

按以下顺序校验，失败时返回 `{"error": "…", "code": "…"}`：

| 顺序 | 条件 | HTTP | `code` |
|---|---|---|---|
| 1 | `pub_key` 不是合法的 32 字节 base64 | 400 | `invalid_relay` |
| 2 | 没有在线的中转使用该公钥 | 409 | `relay_offline` |
| 3 | 中转的 `features` 不同时含 `sdisc1`、`sreg1` | 409 | `relay_unsupported` |
| 4 | 中转设了密码，请求没带 `password_verifier` | 401 | `relay_password_required` |
| 5 | `password_verifier` 不匹配（常数时间比较） | 403 | `relay_password_wrong` |
| 6 | 中转 `require_room_password` 为真，但没有房间密码 | 400 | `room_password_required` |

- 第 5 项按“来源 IP + 中转”限流（例如每分钟 10 次），防止在线穷举中转密码。
- 访客也可以指定（D4）：不检查令牌类型。
- 建房成功后，`Room.Relay` 保存 `{addr, pub_key, features, self_hosted}`，此后**不能修改**（D5）。中转后来下线不影响房间（客户端自行回退，D3）。
- `docs/ROOM_RELAY_3.1.md` 第 4 节原列的 `relay_unknown` 不再使用：已过期的中转会被移除，Coordinator 无法区分“从未登记”与“已下线”，两者都返回 `relay_offline`。

### CR5 `room_state` 下发房间中转

`roomStateRelay` 目前只有 `address`，而且从不填写。改为：

```json
"relay": {
  "address": "relay.example.com:7000",
  "pub_key": "<base64>",
  "features": ["sdisc1", "sreg1"],
  "self_hosted": true
}
```

没有指定房间中转时为 `null`。每次 `room_state` 都携带（加入、重连后重新加入）。

## 中转

### RR1 `relay.mode: self_hosted`

新增配置（默认 `official`，行为与现在相同，只是 `control.relay_secret` 改为这台中转自己的密钥，见 CR1）：

```yaml
relay:
  mode: self_hosted
  password: ""                 # 可选；见 RR4
  require_room_password: true  # 默认 true（D9）
control:
  server_url: https://coord.example.com   # 必填；必须是 https
```

自托管模式下：

- 不使用 `control.relay_secret`。如果配置了，启动时报错，避免把官方密钥带到第三方机器上。
- 启动流程：载入密钥 → 计算密码校验值（RR4）→ 取质询 → 登记 → 每 10 秒心跳一次。收到 401 时重新取质询并登记，按指数退避重试。
- 令牌只放在内存中，不写日志。
- 登记失败（例如 `relay_unsupported`）时打印明确的错误并持续重试；在登记成功之前，中转照常运行，只是没有房间能指定它。

### RR2 自托管模式强制 `register_auth: required`

自托管模式下，`relay.register_auth` 不是 `required` 就拒绝启动（配置校验错误），`discovery.auth` 本来就只支持 `required`。否则任何人都能用未认证的 `0x01` 注册，绕开中转密码使用这台中转。

### RR3 自托管模式下 `0x0D` 只接受已注册的发送方

官方中转按 `dst_id` 转发 `0x0D`，不要求发送方在本中转注册（跨中转转发需要这样，见 `RELAY_REQUIREMENTS_3.1.md`）。自托管中转只服务指定了它的房间，因此：

- 只有当来源地址等于头部 `src_id` 当前绑定的地址（经 `0x0E` 注册）时才转发，否则丢弃，并计入 `drop{unregistered_src}`。
- 客户端只在“自己的房间中转可用、并且对方也上报了 `room-relay:`”时才经房间中转发送（`ROOM_RELAY_3.1.md` 5.3 节），这时双方都已在该中转注册，所以正常流量不受影响。
- `0x05`（RTT ping）照常回显（保留现有限流）。客户端用它判断房间中转是否可用，判断的时候可能还没有注册。

### RR4 中转密码与 `require_room_password`

设了 `relay.password` 时，启动时计算一次：

```
verifier = Argon2id(password, salt = "msst-relay-pw-v1" ‖ relay_pub (32 字节原始值),
                    t = 2, m = 19 MiB, p = 1, 输出 32 字节)
```

Go 实现：`golang.org/x/crypto/argon2` 的 `argon2.IDKey(password, salt, 2, 19*1024, 1, 32)`（中转需要新增这个依赖）。校验值随登记上报（`password_verifier`），连同 `require_room_password` 一起上报。修改密码后重启中转即可；已建的房间不受影响（D10）。

密码只出现在配置文件里，不写日志；配置文件权限建议设为 0600，与密钥文件相同。

### RR5 连接串

启动时打印（另提供 `-print-link` 参数，只打印连接串后退出）：

```
msst-relay://<node.addr>#<公钥的 base64url 编码，无填充>[?pw=1]
```

- `node.addr` 必须是客户端可以访问的公网 `host:port`；它也是 RR1 登记时上报的 `addr`。
- `?pw=1` 只在设了密码时出现，提示建房界面让房主输入中转密码。
- 例（公钥取自 2×32 私钥，没设密码）：`msst-relay://relay.example.com:7000#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk`

### RR6 拉取 `discovery-peers` / `device-keys` 时使用自托管令牌

自托管模式下，`coordinatorPeerFetcher`（`discovery.go`）和 `/relay/device-keys` 的拉取（`sreg.go`）改用 `Authorization: Bearer <token>`，不再发送 `X-Relay-Secret`。

- `discovery-peers` 返回 403（不在授权范围内）：当作空列表缓存，按 `room_cache_ttl` 重试，计入 `drop{room_unknown}`。
- 返回 401（令牌过期，或者 Coordinator 重启过）：通知登记模块重新登记，本次拉取按失败处理。
- `device-keys` 省略的设备：沿用现有的 `key_unknown` 处理。

## 测试向量

**中转 keyproof**（CR2；用 Python `cryptography` 计算）：

```
relay_sk     = 32 × 0x02
relay_pub    = ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59
server_sk    = 32 × 0x03
server_pub   = 5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22
shared       = 7c425a51f6a7f2e60012b0a34dd6511017807708b502ee66a2a247f171fda96c
challenge_id = 16 × 0x11（十六进制 "11111111111111111111111111111111"）
mac          = 6fb95d31d70d3d66953314fb80497d8d21261b770235dd5dfa38e6f83cc373d3
```

**中转密码校验值**（RR4；用客户端的 Argon2id 实现计算，该实现已与参考实现核对过）：

```
password = "relay secret"
salt     = "msst-relay-pw-v1" ‖ relay_pub（上面的 ce8d3a…7d59）
verifier = 7a8ef8ff39824ac7476ecbe76264a5b16cc0376d6e5f805bea3436060f3af9a3
```

**房间密码校验值**（C7）：见 `ROOM_RELAY_3.1.md` 第 3 节。

## 上线顺序

1. **P1**：Coordinator C6、C7、C8，与客户端 `f31b54d` **同时**上线。
2. **CR1**：Coordinator 开启 `legacy_relay_secret`，同时接受旧密钥与独立密钥 → 逐台给官方中转换上独立密钥 → 关闭 `legacy_relay_secret`。
3. **CR2–CR5** 与 **RR1–RR6**：先上线 Coordinator，再发布支持自托管模式的中转。旧客户端不受影响：它们不会在建房时携带 `relay`，也会忽略 `room_state.relay`。
4. **客户端第 3 步**：双中转注册、健康检测与回退、`room-relay:` 上报、游戏发现目标、IPC 与 Controller 界面。

## 验收清单

- [ ] 关闭 `legacy_relay_secret` 后，用旧的共用密钥登记中转返回 401；每台官方中转用自己的密钥登记、心跳均成功；密钥对上但 `id` 不符返回 403。
- [ ] `relay_secret` 为空且没有 `relay_auth: off` 时，Coordinator 拒绝启动。
- [ ] 自托管中转启动后完成登记，`GET /relays` 中**没有**它；用错误的 MAC 登记返回 `key_proof_invalid`；`features` 缺 `sreg1` 时返回 `relay_unsupported`。
- [ ] 测试向量通过（中转 keyproof、中转密码校验值）。
- [ ] 重启 Coordinator：自托管中转在一次心跳周期内重新登记成功。
- [ ] 建房按 CR4 表格的每一行返回对应的错误码；中转密码连续输错超过限流阈值后被限流。
- [ ] 指定自托管中转建房成功后，加入者收到的 `room_state.relay` 含正确的 `address`、`pub_key`、`self_hosted: true`；未指定时为 `null`。
- [ ] 自托管中转的令牌：请求“指定了它”的房间的 `discovery-peers` 得到 200，其他房间得到 403；`device-keys` 只返回这些房间当前成员的公钥。
- [ ] 自托管中转配置 `register_auth: optional` 时拒绝启动；配置了 `control.relay_secret` 时拒绝启动。
- [ ] 自托管中转上，未注册的来源发出的 `0x0D` 被丢弃（`drop{unregistered_src}` 增加）；已注册的两台设备之间 `0x0D` 正常转发；`0x05` 对任何来源都回显。
- [ ] `require_room_password: true` 的中转：不设房间密码的建房返回 `room_password_required`；中转改密码并重启后，已建的房间照常使用，新建房需要新密码。
- [ ] 连接串与配置一致：`-print-link` 输出的公钥（base64url 解码后）等于中转公钥。
