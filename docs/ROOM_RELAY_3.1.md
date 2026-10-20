# 房间中转与自托管中转（方案草案）

状态：**方案已确认，待实施**。2026-10-20。涉及客户端（msst-net-core-31x）、Coordinator（msstnetCoordinator31x）、中转（msstnetRelay31x）。

房主建房时可以指定一台中转（官方或自托管）作为**房间中转**：房间内需要经中转的流量都走它。默认“不指定”，各成员仍用自己的偏好中转（游戏发现已能跨中转，见 `SERVER_FOLLOWUPS_3.1.md` K2）。

## 已定决策

| # | 决策 |
|---|---|
| D1 | 房间中转只对**房间流量**生效（发往同房间成员的数据、隧道内探测、游戏发现）。同时是房间成员和大型局域网节点的设备，按房间成员处理。 |
| D2 | 自托管中转与官方中转是同一个程序，区别是 Coordinator **不公布**它（不出现在 `GET /relays`）。只有持预共享密钥的官方中转能登记为公开中转。 |
| D3 | 房间中转连不上时（官方或自托管），一律回退到成员各自的偏好中转。 |
| D4 | 访客（未登录）建的房间也可以指定房间中转，包括自托管中转。 |
| D5 | 房间中转在建房时确定，之后**不能修改**。 |
| D6 | 使用自托管中转的房间，只向成员**提示**，成员不能拒绝。 |
| D7 | 房间中转必须支持 `sreg1` 与 `sdisc1`（有合法 `pub_key`），否则不能被指定。 |
| D8 | 自托管中转可以设置**中转密码**；房主选用带密码的中转时，建房需提供中转密码。其他成员只需房间密码（如有），不需要中转密码。 |
| D9 | `relay.require_room_password` 默认**开启**。 |
| D10 | 中转改密码**不影响**已建房间。 |
| D11 | 中转密码与房间密码都用 Argon2id 校验值（客户端新增依赖 `argon2`）。 |
| D12 | 房间中转连续 3 次 ping 无应答（约 15 秒）判定不可用并回退，连续正常 30 秒后切回。 |
| D13 | 一台设备同一时间只在一个房间里，因此同一时间最多一个房间中转。 |
| D14 | D13 由 Core 与 Coordinator 双方强制：已在房间里时建房或加入另一个房间，返回错误 `already_in_room`（Controller 提示先离开）。 |

## 1. 中转身份

中转的身份是它已有的 X25519 公钥（`discovery.auth_key_file`，sdisc 与 sreg 都用它）。地址可以变，公钥不变。

**连接串**：自托管中转启动时打印，房主粘贴到建房界面：

```
msst-relay://relay.example.com:7000#<base64 公钥>[?pw=1]
```

`pw=1` 只是提示“此中转设了密码”，密码本身不进连接串。公钥由房主提供，客户端不必向中转索取（那样只能首次信任）；有人在同一地址冒充，也拿不出对应的私钥。

## 2. 中转向 Coordinator 登记

| | 官方中转 | 自托管中转 |
|---|---|---|
| 认证 | 预共享密钥，**每台一个**（建议替换现有的全体共用 `relay_secret`，泄露一台不牵连全部） | 用中转私钥做质询-应答（与设备 keyproof 同法） |
| `GET /relays` | 公布 | 不公布 |
| 凭据范围 | 全部房间（现状） | 仅限**指定了该公钥**的房间：这些房间的 `discovery-peers`，以及这些房间当前成员的 `device-keys` |
| 登记时上报 | 地址、区域、公钥、`features` | 地址、公钥、`features`、中转密码校验值（如设了密码，见第 3 节） |

自托管中转启动即登记（不必等被选中），之后按心跳续期。这样房主建房时 Coordinator 就能判断“这个公钥的中转在线、支持 `sreg1`/`sdisc1`、是否需要密码”，当场报错，而不是建好房才发现不可用。登记本身不赋予任何权限，权限只来自“有房间指定了它”；Coordinator 应对登记限流、限制同一来源的登记数量。

房间解散后，相应凭据范围自动收回。

## 3. 中转密码（D8）

### 谁需要提供什么

| | 房主建房 | 其他成员加入 |
|---|---|---|
| 房间密码（如有） | 提供 | 提供（现状） |
| 中转密码（如有） | 提供 | **不需要**（建议） |

理由：中转密码授权的是“这个**房间**可以用我的中转”，房间密码授权的是“这个**人**可以进这个房间”。两者叠加就够了：

- 成员只需要记一个密码（房间密码），中转密码不必在朋友间流传，泄露面小；
- 中转主人信任房主，由房主决定谁能进房间（设不设房间密码、发给谁），与“自托管中转给自己和熟人用”的定位一致；
- 要求每个成员都输中转密码，等于把中转密码变成第二个房间密码，用户体验差，安全上也没有多得什么。

不设房间密码的房间，任何拿到房间 ID 的人都能进来使用该中转。因此中转配置 `relay.require_room_password` 默认开启（D9）：Coordinator 拒绝为指定它、但没有房间密码的房间建房。中转主人可以显式关闭。

### 校验方式

不在网络和 Coordinator 上存明文：

```
verifier = Argon2id(password, salt = "msst-relay-pw-v1" ‖ relay_pub_key)    # 32 字节
```

- 中转登记时上报 `verifier`；Coordinator 只保存 `SHA-256(verifier)`。
- 房主客户端在本地算出 `verifier`，随建房请求提交；Coordinator 做常数时间比较。
- 数据库泄露后，离线猜密码要逐个过 Argon2id，代价高；`salt` 含中转公钥，同一密码在不同中转上不同。
- 中转改密码：重新登记新的 `verifier`。已建房间不受影响（D10），只影响之后的建房。

Argon2id 参数（两种密码相同）：`m = 19 MiB, t = 2, p = 1`，输出 32 字节（OWASP 推荐的下限，手机上约几十毫秒）。Argon2 只在客户端计算；Coordinator 只做 SHA-256 与比较，不会因此被拖慢。客户端依赖 `argon2`（RustCrypto）。

### 房间密码（D11）

现在房间密码以不加盐的 `SHA-256(password)` 传输和保存：Coordinator 收到的哈希就等于密码，数据库泄露后可以直接拿去加入房间，常见密码也能查表反推。改为：

```
salt     = 16 字节随机数，建房时由房主客户端生成
verifier = Argon2id(password, salt = "msst-room-pw-v1" ‖ salt)            # 32 字节
```

- **建房**：`POST /room/create` 提交 `password: {salt, verifier}`（取代 `password_hash`）；Coordinator 保存 `salt` 与 `SHA-256(verifier)`。
- **取盐**：新增 `GET /room/{id}/password-salt`，有密码时返回 `{salt}`，无密码时返回 `{salt: null}`，房间不存在时返回 404。盐不是秘密。
- **加入**：客户端先取盐，在本地算出 `verifier`，在 `join` 中以 `password_verifier` 提交；Coordinator 做常数时间比较。
- **重入**：Core 在内存中保存 `verifier`（取代 K1 保存的 SHA-256 哈希），重连时直接带上，不必重新计算。
- **限流**：Coordinator 对同一设备、同一来源 IP 的错误密码尝试限流（例如每分钟 10 次），防止在线穷举。
- 3.1 不兼容 3.0.x 协议，房间又是临时的，因此不需要迁移：Coordinator 只接受新方案。
- 编码：`salt` 与 `verifier` 在 JSON 中都用标准 base64（带填充）。`GET /room/{id}/password-salt` 返回 `{"salt": "<base64>"}` 或 `{"salt": null}`。

测试向量（与参考实现 `argon2` 20190702 核对过；客户端 `src/passwords.rs` 固定了它）：

```
password = "correct horse"，salt = 16 × 0x5a
Argon2id 的 salt 输入 = "msst-room-pw-v1ZZZZZZZZZZZZZZZZ"（31 字节）
verifier = 71e7aa44e64ecd1cb0ddbc6049b81a191738151aa8e662402735e1a6a6224dab
```

这一项不依赖房间中转，可以先行实施。

## 4. 建房与下发

**建房**（`POST /room/create`）新增可选字段：

```json
{
  "room_name": "…",
  "password_hash": "…",
  "relay": {
    "address": "relay.example.com:7000",
    "pub_key": "<base64>",
    "password_verifier": "<base64，仅带密码的中转>"
  }
}
```

Coordinator 校验：公钥对应的中转已登记且在线、`features` 含 `sreg1` 与 `sdisc1`、密码校验通过、满足 `require_room_password`。任一不满足就拒绝建房，并返回可区分的错误码：`invalid_relay`、`relay_offline`、`relay_unsupported`、`relay_password_required`、`relay_password_wrong`、`room_password_required`。中转按公钥查找，房间中转的地址取中转登记时上报的地址。接口细节、校验顺序与 HTTP 状态见 `ROOM_RELAY_SERVER_3.1.md` CR4。

官方中转同样可以被指定，此时只需地址（或中转 ID）与公钥，没有密码。

**下发**：`room_state` 的 `relay` 字段（已存在，目前从不填）改为：

```json
"relay": { "address": "…", "pub_key": "<base64>", "features": ["sdisc1","sreg1"], "self_hosted": true }
```

未指定时为 `null`。房间存续期间不变（D5）。

## 5. 客户端

### 5.1 同时注册两台中转

Core 现在只维护一个中转注册。进入指定了房间中转的房间后，同时维护：

- **偏好中转**：非房间流量，也是回退目标（始终保持注册）；
- **房间中转**：房间流量。

两台各自做 sreg 注册（0 / 1 / 3 秒，然后按保活间隔）和 RTT 测量（`0x05`）。离开房间后注销房间中转。

### 5.2 房间中转的健康状态

```
          进房            ping 连续 3 次无应答（约 15 s）
 unknown ───► probing ──► ok ────────────────────────► down
                 │          ▲                           │
                 │          └── 连续 30 s 正常 ──────────┘
                 └── 首次探测失败 ──────────────────────► down
```

- `ok` 才使用房间中转；`down` 就回退（D3），并持续探测，恢复后经过一段稳定期再切回，避免抖动。
- 只能测到“连得通”，测不到“注册已生效”（sreg 没有确认包）。一台回 ping 但不转发的中转无法据此察觉。可选的补强：用隧道内探测的结果作为辅助信号，或者以后引入注册确认包（见 `SERVER_FOLLOWUPS_3.1.md` 开放问题）。

### 5.3 上报与选路

成员各自判断房间中转是否可用，所以可能出现部分成员回退。每个成员上报自己的实际状态：房间中转为 `ok` 时，在端点列表中加一项 `room-relay:<IP:port>`，否则不加。（现有解析器会忽略不认识的前缀；`relay:` 仍是偏好中转。）

发往房间成员 B 的帧：

1. 有直连路径就直连（不变）；
2. B 上报了 `room-relay:`，且本机房间中转为 `ok`：发往房间中转；
3. 否则发往 B 的偏好中转（B 始终在那里注册）。

非房间成员的流量不受影响。

### 5.4 游戏发现

沿用 K2 的跨中转逻辑，只改“目标中转”的计算：

- **注册（`0x0A`）**：向本机注册着的每一台中转注册（偏好中转，以及状态为 `ok` 的房间中转），使回退中的成员也能把发现包送到我这里。
- **发送（`0x0B`）**：房间中转（本机为 `ok` 时），加上“未上报 `room-relay:`、或者本机连不上房间中转”的成员所在的偏好中转。
- 自托管房间中转的公钥来自 `room_state`，不再依赖 `GET /relays`。
- 重复到达照旧只注入一次。

### 5.5 IPC（新增字段，待定的协议版本号）

- `CreateRoom`：新增可选的 `relay`（连接串，或者官方中转的地址）与 `relay_password`。中转密码只在 Core 内存中用于计算 `verifier`，不保存、不写日志。房间密码的 IPC 接口不变（仍是明文 `password`，经本机 IPC 传给 Core），由 Core 计算校验值。
- 房间视图（`GetSystemState` / `RoomStateChanged`）：新增 `room_relay`，形如 `{address, self_hosted, state: "probing"|"ok"|"down"}`；未指定时为 `null`。
- 新错误码：与第 4 节 Coordinator 返回的错误码一一对应，供 Controller 显示。
- Controller 在房间界面显示“此房间使用自托管中转 <地址>”（D6），以及回退状态。

## 6. 中转改动

1. **自托管模式**（例如 `relay.mode: self_hosted`）：用私钥向 Coordinator 登记；不使用 `relay_secret`；可选 `relay.password` 与 `relay.require_room_password`。
2. 自托管模式下强制 `register_auth: required`（D7）。否则任何人都能用未认证的 `0x01` 注册，绕开密码使用这台中转。
3. 自托管模式下，`0x0D` 只接受**已在本中转注册的发送方**（按绑定地址检查来源）。按 5.3 的规则，发往房间中转的一定是在那里注册了的成员，所以不影响正常流量，却能防止外人借它转发。
4. 启动时打印连接串（第 1 节）。
5. `discovery-peers` 与 `device-keys` 改用自托管凭据；被拒（不在授权范围内）时按 `key_unknown` 处理。

## 7. Coordinator 改动

1. 官方中转改为每台独立的预共享密钥；只有官方中转出现在 `GET /relays`。
2. 自托管中转登记：质询-应答（与设备 keyproof 同法）、心跳、限流；保存地址、公钥、`features`、`SHA-256(verifier)`、`require_room_password`。
3. `POST /room/create` 接受 `relay` 并按第 4 节校验；`Room.Relay` 改为保存 `{address, pub_key, features, self_hosted}`。
4. `room_state` 下发 `relay`。
5. `discovery-peers` 与 `device-keys` 对自托管中转按房间限定范围（第 2 节）。
6. 房间密码改用 Argon2id 校验值（第 3 节“房间密码”）：`POST /room/create` 的 `password: {salt, verifier}`、`GET /room/{id}/password-salt`、`join` 的 `password_verifier`、错误密码限流。
7. 单房间（D14）：设备已是某房间成员时，`join` 另一个房间返回错误，`code` 为 `already_in_room`（重复 `join` 同一房间仍是无操作，供重连重入使用）。

## 8. 安全考量

- 数据有 WireGuard 加密，自托管中转看不到内容；但它能看到全体成员的设备 ID、公网地址、流量时序，以及游戏发现的明文内容（例如 MOTD）。这是 D6“提示”要表达的内容。
- 恶意的自托管中转能做的只有丢包、延迟、观察元数据，不能伪造成员数据（WireGuard），也不能伪造发现包的发送方（sdisc 由中转签名，但只有本房间成员的公钥能通过它的验证；它能对本房间成员伪造发现包——这与官方中转的信任程度相同，见 `SECURE_DISCOVERY.md` 的非目标）。
- 回退保证房间中转出问题时房间仍然可用（D3）；代价是回退期间房间流量走官方中转。
- 中转密码只防“未经许可指定这台中转”。中转主人还需自己保管连接串与密码；`require_room_password` 防止“拿到房间 ID 就能用”。

## 9. 实施顺序（建议）

0. 房间密码改用 Argon2id，以及单房间强制（D14）（Coordinator 与客户端同时上线；与房间中转无关，可先做）。
1. Coordinator：中转登记（官方独立密钥、自托管质询-应答）、建房校验、`room_state` 下发、凭据范围。
2. 中转：自托管模式、强制 `register_auth: required`、`0x0D` 来源检查、连接串。
3. 客户端：双中转注册、健康状态与回退、`room-relay:` 上报与选路、游戏发现目标、IPC。
4. Controller：建房界面（连接串、中转密码）、房间界面提示与状态。
