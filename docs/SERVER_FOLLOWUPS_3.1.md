# MSST-Net 3.1 服务端跟进

2026-10-20 · 客户端基线：msst-net-core-31x `837efdf` + 房间密码重入修复 · 中转：msstnetRelay31x `f5cd369` · Coordinator：msstnetCoordinator31x `ff1afdc`

客户端 3.1 已经只走 WireGuard、只用安全发现、支持带认证的中转注册，并改用隧道内探测测中转路径 RTT。本文列出 Coordinator 与中转还要做什么、按什么顺序上线、如何验收。每一项都已对照两个仓库的当前代码核对过状态。

## 一览

| 编号 | 组件 | 事项 | 状态 |
|---|---|---|---|
| C1 | Coordinator | `POST /relay/device-keys` | 已完成（`356e399`） |
| C2 | Coordinator | `features` 存储与透传 | 已完成（`356e399`） |
| C3 | Coordinator | `device_key_proof` 改为 `required` | 待做 |
| C4 | Coordinator | 客户端依赖的现有行为 | 无需改动，请保持 |
| C5 | Coordinator | 访客设备的端点上报 `/device/endpoint` | 已完成（`54d0d04`） |
| C6 | Coordinator | 快速重连时旧连接的清理覆盖新连接 | 待做 |
| C7 | Coordinator | 房间密码改用 Argon2id 校验值 | 待做（与客户端同时上线） |
| C8 | Coordinator | 一台设备同一时间只在一个房间 | 待做（与客户端同时上线） |
| C9 | Coordinator | 未认证注册只能使用由设备公钥推导的用户 ID | 待做（建议） |
| C10 | Coordinator | `/relays` 列出中转域名 | 可选 |
| K1 | 客户端 | 带密码房间：建房加入与重连重入带上密码 | 已修复 |
| K2 | 客户端 | 成员分处不同中转时的游戏发现 | 已修复 |
| R1 | 中转 | 退役 `0x06`/`0x07` 转发 | 已完成（`f5cd369`） |
| R2 | 中转 | 退役 `0x03` | 已完成（`f5cd369`） |
| R3 | 中转 | `relay.register_auth` 改为 `required` | 待做（最后一步） |
| R4 | 中转 | 3.1 协议约定、sdisc、sreg | 已完成 |

## Coordinator

### C1 批量查询设备公钥 `POST /relay/device-keys` — 已完成（`356e399`）

部署即可。中转（sreg）首次见到某设备时靠它取公钥；没有它，所有 `0x0E` 都会因 `key_unknown` 被丢弃。

- 用与 `discovery-peers` 相同的 `X-Relay-Secret` 校验，错误或缺失返回 401。
- `device_ids` 最多 256 个；空数组、超出、不是 `device-` 加 8 位小写十六进制时返回 400；请求体约 16 KB 上限。
- 未知设备直接省略，不报错。返回注册时固定（pin）的公钥；设备删除后不再返回。
- 只走 HTTPS。每个中转最多约 10 次/秒，低于默认每 IP 30 次/秒的限流。

### C2 中转 `features` 存储与透传 — 已完成（`356e399`）

`sanitizeRelayFeatures` 已提交，`GET /relays` 返回 `features`。部署即可。

- 只保留形如 `[a-z0-9]{1,16}` 的项，去重，最多 16 个。
- 客户端判定规则：`features` 含 `"sreg1"` **且** `pub_key` 是合法的 32 字节密钥，才用 `0x0E`；否则用 `0x01`/`0x02`。字段缺失按空数组处理。

部署 C1 之前不要部署 C2：客户端一看到 `sreg1` 就会切到 `0x0E`，而中转此时还取不到公钥。

### C3 `device_key_proof`：`off` → `optional` → `required` — 待做

当前默认 `off`。3.1 客户端每次 WS 注册都会附带 keyproof v1，所以可以先切到 `optional` 观察，再切到 `required`。

原因：中转用的设备公钥来自 Coordinator。在 `required` 之前，谁先注册某个设备 ID，谁就决定它的公钥；设备 ID 只有 32 位，约 2^32 次尝试就能为未注册的 ID 找到匹配密钥。

### C4 客户端依赖的现有行为 — 无需改动，请保持

- `registered` 的 `hostname`、`ipv4`、`ipv6`、`user_handle`、`user_display_name` 不要加 `omitempty`：客户端已改为必填，缺字段会导致注册消息解析失败。
- `member_joined` / `member_left` 的 `room_id` 放在外层 `WSMessage.RoomID`，客户端从外层读取。
- `room_state`、`member_joined` 和 `/nodes/*` 为每台设备返回 `public_key`。它就是 WireGuard 公钥，缺失时客户端无法与该设备通信（路径视图显示 `no_key`）。
- `GET /relays` 每项带 `pub_key`。没有 `pub_key` 的中转对客户端来说既没有游戏发现，也不能用 `0x0E` 注册。

### C5 访客设备的端点上报 — 已完成（`54d0d04`）

已按下面的建议实现：通过 WS 注册设备的访客令牌与该设备绑定，可以上报它的端点；OIDC 注册会解除绑定。以下为原始描述，供核对。


客户端在没有有效 MSST 登录时改用访客令牌（`POST /auth/guest/token`）接入：WS、`/nodes/*` 都正常。但 `/device/endpoint` 会核对“令牌的用户 ID 就是设备的所有者”：访客令牌的用户 ID 是 `guest-<8hex>`，而设备注册时上报的是它自己的 `user-<hash>`，于是返回 403，访客设备的 P2P 端点无法上报，只能走中转。

建议：WS 连接用访客令牌注册设备时，记下“这个访客令牌可以代表这台设备”，`/device/endpoint` 收到访客令牌时按这条记录放行（令牌过期或 Coordinator 重启后自然失效）。不建议让客户端改用 `guest-<8hex>` 作为用户 ID：它每 24 小时或 Coordinator 重启就会变，会连带改变 ezPlay 主机名和按用户 ID 写的规则。

另：`POST /device/register` 只认 OIDC 令牌，访客设备通过 HTTP 改名不会立即同步（`synced: false`），会在下次 WS 注册时生效。这是现有行为，可按需放开。

### C6 快速重连时，旧连接的清理覆盖新连接 — 待做

同一设备建立新的 WS 连接时，`Hub.register` 会关闭旧连接；旧连接的 `readPump` 随后退出并调用 `unregister(old)`。`unregister` 只在删除 `h.clients` 条目时检查 `cur == c`，其余步骤不检查，照常执行：

1. 让设备离开 `GetDeviceRooms` 中的所有房间，并广播 `member_left`；
2. `SetNodeOffline` 并广播 `node_updated`；
3. `delete(h.discovery, deviceID)`。

这三步通常发生在新连接已经处理完 `register`、`join`、`discovery_join` 之后，于是把新连接刚建立的状态一并清掉。客户端此时认为自己仍在房间里，不会再次 `join`，结果是：

- 设备掉出房间，其他成员收到 `member_left`；它自己也不再收到房间事件；
- 设备被标记为离线，直到下一次心跳；
- 设备从 `discovery-peers` 中消失，中转丢弃它的 `0x0A`/`0x0B`（`not in room`），也不再把发现包转给它，游戏发现失效。

网络切换、NAT 超时等让旧连接半开的情况下，客户端会在服务端察觉之前重连，最容易触发。

修法：`unregister` 判断旧连接已被取代（`h.clients[deviceID]` 存在且不是 `c`）时，只关闭这条连接，跳过上面三步。建议补一个测试：同一设备连续建立两条连接，新连接 `join` 和 `discovery_join` 之后关闭旧连接，设备仍是房间成员、仍在线，并且仍在 `GetDiscoveryPeers` 中。

### C7 房间密码改用 Argon2id 校验值 — 待做（与客户端同时上线）

完整规范见客户端仓库 `docs/ROOM_RELAY_3.1.md` 第 3 节“房间密码”（含测试向量）。Coordinator 侧：

- `POST /room/create`：接受 `password: {salt, verifier}`（base64），取代 `password_hash`；保存 `salt` 与 `SHA-256(verifier)`。不再接受 `password_hash`。
- 新增 `GET /room/{id}/password-salt`：有密码返回 `{"salt": "<base64>"}`，无密码返回 `{"salt": null}`，房间不存在返回 404。访问控制与 `/room/create` 相同（无令牌、访客令牌、OIDC 均可）。
- `join`：读取 `password_verifier`（base64），计算 SHA-256 后与保存值做常数时间比较；取代 `password_hash`。
- 对错误密码限流：同一设备、同一来源 IP，例如每分钟 10 次；超出时返回错误，客户端显示为 `room_rejected`。
- Coordinator 不运行 Argon2，不会因此增加负载。

客户端从本次提交起只发送新字段，所以 C7 必须与客户端同时上线；否则带密码的房间建房会被拒或者不带密码，加入一律失败。

### C8 一台设备同一时间只在一个房间 — 待做（与客户端同时上线）

设备已是某个房间的成员时，`join` **另一个**房间返回 WS `error`，`code` 为 `already_in_room`；客户端把它映射为同名 IPC 错误码。对**同一**房间重复 `join` 仍是无操作（客户端重连后会重新 `join`）。

客户端自己也会先检查，所以正常情况下不会触发；Coordinator 这一侧防的是旧客户端或异常状态。注意与 C6 的关系：旧连接的清理若在新连接 `join` 之后执行，会把设备移出房间，客户端下次重连 `join` 时才回来。

### C9 未认证注册只能使用由设备公钥推导的用户 ID — 待做（建议）

客户端变化：接入认证凭据过期时（OIDC 令牌被拒，刷新令牌也被拒），客户端丢弃凭据，以访客身份重新注册。注册时用户 ID 回退为由设备公钥推导的 `user-<SHA-256(pub_key) 前 4 字节的十六进制>`，用户助记符留空，因此注册时 `user.handle` 等于该 ID。设备 ID、设备助记符和设备显示名不变。未设置设备显示名时，注册的默认名改为 `用户<去掉 user- 前缀的 ID，最多 8 个字符>的设备`，例如 `用户1a2b3c4d的设备`。

Coordinator 现状（`hub.go` `handleRegister`）：只对 OIDC 连接校验 `user.id`（`user_id_mismatch`）。访客或无令牌的连接可以报任意用户 ID。`RegisterAll` 会用这次注册的用户助记符和显示名覆盖 `userRecords[userID]`。也就是说，旧客户端在凭据过期后仍报 OIDC 用户 ID，会改写该账户的用户记录，并让这台设备继续挂在该账户下。

建议：

- 非 OIDC 的 `register` 和 `POST /device/register`：要求 `user.id` 等于由 `device.pub_key` 推导的 ID，否则返回 `user_id_mismatch`。这样访客无法冒用 OIDC 账户的用户 ID。
- 同一设备的用户 ID 变化时（OIDC 用户 → 推导 ID，或者反过来），把设备从旧用户的索引中移出。现有的第 5 步“清理旧索引”已经处理 `userDevHandles[old.UserID]`，请确认旧用户记录在没有设备后不会残留错误的助记符占用。

本次客户端已经只在凭据有效时上报 OIDC 用户 ID，所以第一条可以随时上线。

### C10 `/relays` 列出中转域名 — 可选

客户端不再把中转地址解析成 IP 保存。`/relays` 中 `addr` 写什么，客户端就显示什么、在端点 `relay:` 里上报什么。对端会自行解析这个名字，选择它自己能用的地址族。客户端对解析结果缓存 60 秒，解析失败时继续使用上次的地址。若希望用户看到域名，并且在 DNS 变更后客户端自动跟随，请把官方中转的 `addr` 配成 `relayN.msst.net:端口`。Coordinator 不需要解析这些地址：它对端点的处理只做字符串透传，自托管中转的 `validateRelayAddr` 已接受域名。

## 客户端

### K1 带密码的房间：建房加入与重连重入带上密码 — 已修复

Coordinator 的 `handleJoin` 在每次 `join` 时都核对 `password_hash`（这是正确行为，无需改动）。原来的客户端（3.0.x 和 3.1.x 都是）有两处不带密码：

- 建房后创建者加入时不带密码，于是创建带密码的房间时总是返回“密码错误”，建房失败；
- 与 Coordinator 重连后重新加入房间时不带密码，`join` 被拒，随后 `discovery_join` 也因 “not a member” 被拒。房间成员事件和游戏发现都停止，但客户端仍显示在房间里。

现在客户端把已加入房间的密码校验值只保存在内存中，建房加入和每次重连重入都带上它；离开房间时清除，不写入磁盘。此后房间密码改为 Argon2id 校验值（见 C7）。

### K2 成员分处不同中转时的游戏发现 — 已修复

中转只把发现包（`0x0C`）转给在本中转注册过发现的房间成员，而每个成员各自选择延迟最低的中转。现有两台中转，成员分处两台时，数据照常（`0x0D` 跨中转转发），游戏发现却互相不可见。

现在客户端在房间内向“房间成员用到的所有中转”注册发现（`0x0A`）并发送发现包（`0x0B`）：自己的中转，加上每个成员 `relay:` 端点所指的中转；后者按地址在 `GET /relays` 中查到公钥（遇到列表中没有的中转时最多每 60 秒重新拉取一次，另每 15 分钟刷新）。同一个包经两台中转各到一次时，接收端只注入一次（`GetRelays.secure_discovery.drop.duplicate` 计数）。`secure_discovery.relays` 列出当前发往的中转。

中转与 Coordinator 无需改动：中转按房间成员列表认证 `0x0A`/`0x0B`，不要求发送方在本中转注册数据通道。发现流量随中转台数成倍增加（目前两台）。不在 `GET /relays` 中、或没有 `pub_key` 的中转上的成员仍然收不到发现包。

“房间中转”（房主指定后，房间内所有中转流量都走它）是后续功能，届时房间成员都在同一台中转上，不再需要向多台发送。

## 中转

### R1 退役 `0x06`/`0x07` 转发 — 已完成（`f5cd369`）

客户端从 `2be46a5` 起不再经中转发送 `0x06`/`0x07`。中转路径 RTT 改由加密隧道内的探测测量，外层就是普通的 `0x0D`，中转不需要任何新逻辑；`0x06`/`0x07` 只在客户端之间直连使用。

- 把 `typP2PPing` / `typP2PPong` 归入退役类型：丢弃并计入 `dropRetired`。
- 随之删除 `forwardProbe` 与 `probeLimit`。`relay.go` 里“the client sends it to its own relay”的注释已不成立。

原因：sreg 的来源检查让跨两台中转的 `0x06` 总有一跳被丢弃，客户端因此改用隧道内探测。现在留着这条转发路径只会多一个可被滥用的反射面。

### R2 退役 `0x03` — 已完成（`f5cd369`）

中转目前把 `0x03`（3.0.x 打洞）当作注册处理。3.1 客户端从不发送它（打洞用的是直接发往对端的 `0x06`），它只剩一条未认证注册路径的作用。建议同样归入退役类型。

### R3 `relay.register_auth`：`optional` → `required` — 待做（最后一步）

在 C1–C3 上线、客户端全部升级之后再切。需要先定一个可观测的标准，例如连续 7 天 `reg_drop{unauth}` 只来自攻击流量。`required` 需要配置 `control.server_url`，中转启动时会检查。

### R4 已完成，供核对

- `0x0D` 按 `dst_id` 整包原样转发，不要求发送方在本中转注册；`dst == src` 时丢弃以切断两中转环路；接收缓冲 65535 字节。
- 退役 `0x04`、`0x08`、`0x09`，丢弃并计数。
- `discovery.auth` 只支持 `required`；只投递标记了“发送方已验证”的 `0x0C`。
- sreg v1：接收 `0x0E`，向 Coordinator 批量拉取公钥，注册时上报 `features: ["sdisc1","sreg1"]`。
- `0x05` 原样回显（客户端用来测量到中转的 RTT）。

## 上线顺序

1. **中转** `f5cd369`（含 R1、R2）。`register_auth` 保持 `optional`。不影响任何现有客户端。
2. **Coordinator** 部署 C1，然后部署 C2（同在 `356e399` 中，部署一次即可，但中转第 1 步必须先完成）。C5、C6 随时可部署。C2 生效后，3.1 客户端会在下次选择中转或重连时自动切到 `0x0E`。
3. **客户端** 推送 3.1（`2be46a5` 或更新）。在中转支持 `0x0D` 之前，客户端经中转的流量全部不通，只有直连可用，所以第 1 步必须先完成。
4. **Coordinator** C3：`device_key_proof` 先 `optional`，确认无误后 `required`。
5. **中转** R3：`register_auth: required`。

## 验收清单

中转计数来自周期性 `stats:` 日志；客户端状态来自 IPC `GetRelays` 和 `GetPathView`。

- [ ] 带正确 `X-Relay-Secret` 调用 `POST /relay/device-keys`：已知设备返回 pin 住的公钥，未知设备不出现；密钥错误返回 401。
- [ ] `GET /relays` 的每一项都带 `pub_key` 和 `features: ["sdisc1","sreg1"]`。
- [ ] 客户端连上后，`GetRelays.registration.mode` 为 `"sreg1"`，`tx_sreg` 在增长；中转 `reg_new` 增加，每台设备启动时至多一次 `key_unknown`，`auth` 与 `replay` 为 0。
- [ ] A、B 注册在**不同**中转上：互 ping 虚拟 IP 成功；两台中转上承载数据的只有 `0x0D`；`GetPathView` 中对方的 `encryption` 为 `"encrypted"`。
- [ ] A、B 处于 `probing` 时，`GetRelays.registration.last_relay_path_ok_at` 持续更新（隧道内探测经本机中转回来）；中转上看不到 `0x06`/`0x07`。
- [ ] MTU 覆盖设为 1500 时，`ping -s 1472` 通过（中转转发 1555 字节的 `0x0D`）。
- [ ] 游戏发现（如 Minecraft 局域网）在 A、B 间可用；`GetRelays.secure_discovery.active` 为 `true`，`drop.unverified_sender` 为 0。
- [ ] A、B 在**不同**中转上（例如分别把首选中转设为两台）且同在一个房间：双方 `secure_discovery.relays` 都列出两台中转，游戏发现双向可用；两台中转的 `0x0A`/`0x0B` 计数都在增长（K2）。
- [ ] 创建带密码的房间成功；A 断网约 10 秒后恢复，重连后仍在房间里，B 没有收到 A 的 `member_left`，A、B 间游戏发现仍然可用（K1、C6）。
- [ ] A 在旧连接尚未超时时切换网络（例如从 Wi-Fi 换到热点）：Coordinator 上 A 仍是房间成员且在线，`discovery-peers` 仍列出 A（C6）。
- [ ] 从另一台主机用 A 的设备 ID 发 `0x01`：中转 `reg_drop{unauth}` 增加，A 的流量不中断。
- [ ] 重放抓到的 `0x0E`：`reg_drop{replay}` 增加，绑定不变。
- [ ] A 切换网络（NAT 地址变化）：下一个 `0x0E` 后中转 `rebind` 增加，流量恢复。
- [ ] 停掉 Coordinator：已注册客户端至少 1 小时内照常；全新设备无法用 `0x0E` 注册（预期）。

## 参考：3.1 客户端发给中转的报文

| 类型 | 用途 | 何时发送 |
|---|---|---|
| `0x0E` | 带认证的注册（sreg v1），47 字节 | 中转声明 `sreg1` 且有合法 `pub_key` 时：选定/更换中转、重连 Coordinator 后立即、约 1 秒、约 3 秒各一次，之后按保活间隔（默认 25 秒，可设 5–30 秒） |
| `0x01` / `0x02` | 未认证注册 / 保活 | 只发给没有声明 `sreg1` 的中转 |
| `0x05` | 中转 RTT | 每 5 秒，发给本机中转和对端所在中转 |
| `0x0D` | 一条 WireGuard 消息：数据、握手、隧道内中转路径探测 | 随流量；发往对端所在中转，没有则发往本机中转 |
| `0x0A` / `0x0B` | 安全发现注册 / 数据 | 在房间内，从 UDP 21032 发往本机中转和每个房间成员所在的中转 |

完整规范：客户端仓库 `docs/RELAY_REQUIREMENTS_3.1.md`、`docs/DATA_PLANE_ENCRYPTION.md`；中转仓库 `REGISTRATION_AUTH.md`、`SECURE_DISCOVERY.md`。

## 开放问题

- 是否引入带认证的注册确认包（如 `0x0F`）。它能让客户端直接知道注册是否生效，省掉 1 秒和 3 秒的早期重发，代价是双方再改一次协议。
- 三台及以上中转之间的 `0x0D` 转发环路。`required` 模式下伪造绑定需要设备私钥，风险基本消除；在 `optional` 期间是否需要额外防护（例如拒绝绑定到其他中转的地址）待定。

---

依据：客户端 msst-net-core-31x、中转 msstnetRelay31x、Coordinator msstnetCoordinator31x 截至 2026-10-19 的代码，以及《MSST-Net Relay 3.1.x 注册认证：Coordinator 与客户端跟进实施指南》。
