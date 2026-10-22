# MSST-Net 3.1.6 安全修复与核查记录

2026-10-22 · Core 3.1.6 · 中转：msstnetRelay31x `aab6541` · Coordinator：msstnetCoordinator31x `0f4388c`

本文记录 3.1.5 审查后在 3.1.6 中修复的问题、sdisc 发送者认证的信任边界，以及广播投递与转发行为的实测结果。

## 1. 修复一览

| 编号 | 问题 | 修复 | 提交 |
|---|---|---|---|
| S1 | 对端包只校验源地址、不校验目的地址；ACL 只按协议和端口匹配。开启 IP 转发时，对端可以经本机访问本机所连的其他网络（局域网、其他对端），用的是 ACL 对它开放的端口和 ICMP。 | WireGuard 解密后的包必须发往本机虚拟 IPv4/IPv6（`inbound::from_peer_to_us`），否则丢弃。 | `d70c8e7` |
| S2 | 游戏发现（`0x0C`）注入 TUN 前只看目的地址是否为广播或组播，协议、端口、源地址都不检查；中转也只检查 IPv4 版本号。房间成员或房间中转可以绕过 ACL 注入任意 IPv4 包，伪造源地址，还能利用其他网段的 `x.x.x.255`（在更大的网段里是单播地址，会被转发）。 | 只接受普通 IPv4/UDP（无选项、无分片、长度一致），目的地址限于 `172.22.255.255` / `255.255.255.255`（端口不限）以及 `224.0.2.60:4445`、`224.0.0.251:5353`；发送者必须是本房间成员；按发送者的虚拟地址重建数据包后再注入。发送端套用同一规则。 | `8e802cc` |
| S3 | 接收端只做去重，不限速：恶意房间中转可以绕过中转侧的限速直接灌包。 | 去重之后先按发送者限速（10 个/秒），再全局限速（100 个/秒）。先按发送者限速，是为了让单个狂发者被拒的包不消耗全局额度。丢弃计入 `GetRelays` 的 `rate_limited`。 | `8e802cc`，本版 |
| S4 | Linux 上若 `net.ipv4.conf.<TUN>.bc_forwarding=1`，注入的 `172.22.255.255` 不在本机投递，而是被内核从 TUN 原样发回（见第 3 节），本机收不到局域网发现，发回的包还会被当作本机广播再发回房间，形成回环。 | Core 创建 TUN 后把该接口的 `bc_forwarding` 置 0（由入接口的值决定，`all` 为 1 时同样有效）；发送端不再发送源地址在 MSST-Net 网段内、但不是本机的发现包（任何平台上被系统弹回的别人的包都不会再发回房间）。 | 本版 |
| — | 物理网卡广播捕获的回环：成员伪造“源地址 = 本机局域网 IP、目的地址 = 255.255.255.255”的包，注入后会被本机的原始套接字当作本机广播再发回房间。 | S2 的重建使注入包的源地址总是发送者的虚拟地址，捕获时被忽略（测试 `injected_broadcasts_are_not_captured_again`）。 | `8e802cc` |

## 2. sdisc 的发送者认证：由中转声明，不是端到端

密钥派生（`src/sdisc.rs`，规范见中转仓库 `SECURE_DISCOVERY.md`）：

```text
shared = X25519(device_sk, relay_pk)
k_c2r ‖ k_r2c = HKDF-SHA256(shared, "msst-sdisc-v1", device_id ‖ device_pk ‖ relay_pk)
```

- 发送者用 `k_c2r` 给 `0x0B` 加标签，**只有它和中转**能验证。
- 中转向每个接收者发送 `0x0C`，用该接收者的 `k_r2c` 加标签。`src_id`（原始发送者）和标志位 bit 0（“发送者已验证”）都由**中转写入**。
- 接收者能验证的只有“这个包来自我信任的中转”，**无法验证原始发送者**。

因此认证是逐跳的，发送者身份只是中转的声明。能做出这种声明的有：

- 官方中转：密钥由 Coordinator 经 HTTPS 下发并固定（`GET /relays` 的 `pub_key`），中转本身被攻破时成立。
- 房间中转：建房人在连接串 `msst-relay://host:port#<key>` 中指定，可以是任何人自建的服务器。**恶意建房人运营的中转就是这种情况**，门槛最低。

### 恶意中转在 3.1.6 下仍能做到

- 以**任意当前房间成员**的名义向任意成员投递发现包（Core 检查发送者是否为房间成员，但成员 ID 是中转声明的）。
- 内容是任意 UDP 载荷，发往 MSST-Net 广播地址的任意端口，或两个组播组的固定端口。例如以成员 A 的名义伪造一个“A 开的 Minecraft 局域网世界”，玩家点进去后连接的是 A 的地址和伪造的端口，仍要经过 A 的入站 ACL。
- 选择性丢弃或只投给部分成员（拒绝服务）。这在任何转发方案下都无法避免。

### 3.1.6 下已经做不到

- 单播、非 UDP、IP 选项、分片。
- 伪造房间成员以外的源地址，或伪造某个成员的任意源地址（注入前一律按声明的发送者的虚拟地址重建）。
- 让包被本机转发到其他网络（只允许 MSST-Net 广播地址、受限广播和两个组播组，见第 3 节）。
- 超过每个发送者 10 个/秒、合计 100 个/秒。

### 进一步修复的选项（协议变更，待决定）

1. **发现包改走 WireGuard（推荐）。** 发送端把发现包作为隧道内数据，逐个发给房间成员，不再经中转扇出。发送者由 WireGuard 端到端认证，内容也加密了，不需要新的密钥类型，也不依赖中转的 `pub_key`。代价：每个广播发 N 份（N 为成员数，发现包小且约每秒一次）；要先与每个成员建立会话；接收端的目的地址检查（S1）需要对这类包放行 MSST-Net 广播地址；新旧客户端混用期间需要兼容方案。
2. **逐接收者 MAC。** 发送者用 `X25519(sender_sk, recipient_pk)` 为每个接收者计算标签，中转原样转发。包长随人数增加（16 字节 × N），房间人数不设上限，需要分片或分组。
3. **签名。** 每台设备增加 Ed25519 密钥，由 Coordinator 分发。改动最大。

在采用其中之一之前，第 1 节的限制使恶意中转的伪造能力停留在“以成员名义发送局域网广播”。

## 3. 广播投递与转发的实测

脚本：`scripts/netns-broadcast/matrix.sh`（无需 root，每轮使用新的用户和网络命名空间）。拓扑：

- 运行 Core 的主机：`msst0`（TUN，172.22.0.1/16）、`veth0`（192.168.1.1/24 与 10.0.0.1/16），`ip_forward=1`。
- 局域网主机：192.168.1.2/24 与 10.0.0.255/16（后者在 /16 中是普通单播地址）。
- 向 `msst0` 写入源地址为成员地址 172.22.0.7 的 UDP 包，相当于 Core 注入。两台主机都在 4000 端口监听，并在 4445 端口加入 224.0.2.60 组播组。

环境：Linux 7.2.8（Arch）。原始输出：

```text
## ip_forward=1 rp_filter=0 bc_forwarding all/veth0=0 msst0=0
core-host 4000 lan-directed-bcast from 172.22.0.7
core-host 4000 limited-bcast from 172.22.0.7
core-host 4000 msst-bcast from 172.22.0.7
core-host 4445 mc-java from 172.22.0.7
lan-host 4000 lan-unicast from 172.22.0.7
lan-host 4000 slash16-dot255 from 172.22.0.7
tun-out msst-not-bcast to 172.22.1.255

## ip_forward=1 rp_filter=1 bc_forwarding all/veth0=0 msst0=0
（与上一组相同）

## ip_forward=1 rp_filter=2 bc_forwarding all/veth0=0 msst0=0
（与上一组相同）

## ip_forward=1 rp_filter=0 bc_forwarding all/veth0=1 msst0=1
core-host 4000 limited-bcast from 172.22.0.7
core-host 4445 mc-java from 172.22.0.7
lan-host 4000 lan-directed-bcast from 172.22.0.7
lan-host 4000 lan-unicast from 172.22.0.7
lan-host 4000 slash16-dot255 from 172.22.0.7
tun-out msst-bcast to 172.22.255.255
tun-out msst-not-bcast to 172.22.1.255

## ip_forward=1 rp_filter=0 bc_forwarding all/veth0=1 msst0=0
core-host 4000 lan-directed-bcast from 172.22.0.7
core-host 4000 limited-bcast from 172.22.0.7
core-host 4000 msst-bcast from 172.22.0.7
core-host 4445 mc-java from 172.22.0.7
lan-host 4000 lan-unicast from 172.22.0.7
lan-host 4000 slash16-dot255 from 172.22.0.7
tun-out msst-not-bcast to 172.22.1.255
```

| 注入的目的地址 | 默认（`bc_forwarding=0`，任意 `rp_filter`） | `bc_forwarding=1`（含 msst0） | 3.1.6 是否放行 |
|---|---|---|---|
| `172.22.255.255`（MSST-Net 广播） | 本机投递，不转发 | **不在本机投递，被发回 TUN**（S4） | 放行；Core 将 msst0 的 `bc_forwarding` 置 0 |
| `255.255.255.255`（受限广播） | 本机投递，不转发 | 本机投递，不转发 | 放行 |
| `224.0.2.60:4445`（组播） | 本机投递，不转发 | 本机投递，不转发 | 放行 |
| `192.168.1.255`（局域网定向广播） | 本机投递（本机服务可收到） | 转发到局域网 | 发现通道不放行；WireGuard 数据也不放行（S1） |
| `192.168.1.2`（局域网单播） | **转发到局域网** | 转发到局域网 | 不放行（S1、S2） |
| `10.0.0.255`（/16 中的单播主机） | **转发到局域网** | 转发到局域网 | 不放行（3.1.5 的发现通道曾放行任意 `*.*.*.255`） |
| `172.22.1.255`（/16 中的单播，其他对端） | 发回 TUN（即转给另一个对端） | 同左 | 不放行（S1、S2） |

结论：3.1.6 放行的三类目的地址在 Linux 上只会在本机投递，不会被转发；Core 会关闭 `msst0` 的 `bc_forwarding`，`bc_forwarding=1` 的情况也已覆盖。这里模拟的是 Core 的注入，Core 本身并未在命名空间中运行；`no_broadcast_forwarding` 写入的值与最后一组相同。

### 未验证的平台

以下平台需要在真机上验证（方法同上：让一个成员发送 `172.22.255.255` 广播，观察本机是否收到、局域网另一台主机是否收到、TUN 上是否出现回发）：

- **Windows：** IP 路由默认关闭（`IPEnableRouter=0`），开启“Internet 连接共享”、Hyper-V NAT 或移动热点后可能开启。需要确认：Wintun 上的子网广播是否在本机投递、开启共享后是否转发或回发。
- **macOS：** `net.inet.ip.forwarding` 默认 0，“互联网共享”会开启。
- **Android：** 网络共享（热点、USB）会开启转发，Core 运行在 VpnService 的 TUN 上。

在这些平台上，S1、S2 和发送端过滤（不发送他人的包）不依赖操作系统行为，同样生效；尚未确认的只有“放行的广播在本机是否会被转发或回发”。即使回发，发送端过滤也会阻止它回到房间。

## 4. 测试结果（3.1.6，提交前）

- `cargo test --workspace`：全部通过（msst-net-core 262、msst-core-state 232、msst-acl-engine 47、msst-ipc-protocol 22、IPC 契约向量 2、文档测试 1）。
- `cargo clippy --workspace --all-targets`：与 3.1.5 相比没有新增告警。
- 新增测试：
  - S1：`runtime::tests::peers_talk_wireguard_through_a_relay` 中发往 `192.168.1.10` 的包不进入 TUN（去掉检查后该断言失败，已验证）。
  - S2：`discovery::tests` 中的 `discovery_is_udp_broadcast_or_known_multicast`、`injected_packets_come_from_the_room_member_itself`、`injected_broadcasts_are_not_captured_again`。
  - S3：`each_sender_is_rate_limited_on_receive`、`all_senders_together_are_rate_limited_on_receive`。
  - S4：`another_members_packet_is_never_sent_again`，以及第 3 节的命名空间实测。

## 5. 遗留问题

- 恶意中转可以冒充房间成员发送局域网广播（第 2 节），彻底解决需要选定进一步修复的方案。
- 中转侧尚未校验内层包（只检查 IPv4 版本号），建议与 Core 采用同样的规则，在源头丢弃。
- 服务端 C3（`device_key_proof` 改为 `required`）、R3（中转 `register_auth` 改为 `required`）仍待上线，见 `SERVER_FOLLOWUPS_3.1.md`。
- 3.1.5 审查中的低危项（身份文件权限、P2P pong 泄露设备 ID、对端公布的直连地址未过滤、网页端登录限速）尚未处理。
