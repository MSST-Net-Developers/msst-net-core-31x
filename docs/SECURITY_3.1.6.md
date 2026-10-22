# MSST-Net 3.1.6 安全修复与核查记录

2026-10-22 · Core 3.1.6 · 中转：msstnetRelay31x `aab6541` · Coordinator：msstnetCoordinator31x `0f4388c`

本文记录 3.1.5 审查后在 3.1.6 中修复的问题、sdisc 发送者认证的信任边界以及为此改用 WireGuard 的设计，还有广播投递与转发行为的实测结果。

## 1. 修复一览

| 编号 | 问题 | 修复 | 提交 |
|---|---|---|---|
| S1 | 对端包只校验源地址、不校验目的地址；ACL 只按协议和端口匹配。开启 IP 转发时，对端可以经本机访问本机所连的其他网络（局域网、其他对端），用的是 ACL 对它开放的端口和 ICMP。 | WireGuard 解密后的包必须发往本机虚拟 IPv4/IPv6（`inbound::from_peer_to_us`），否则丢弃。 | `d70c8e7` |
| S2 | 游戏发现（`0x0C`）注入 TUN 前只看目的地址是否为广播或组播，协议、端口、源地址都不检查；中转也只检查 IPv4 版本号。房间成员或房间中转可以绕过 ACL 注入任意 IPv4 包，伪造源地址，还能利用其他网段的 `x.x.x.255`（在更大的网段里是单播地址，会被转发）。 | 只接受普通 IPv4/UDP（无选项、无分片、长度一致），目的地址限于 `172.22.255.255` / `255.255.255.255`（端口不限）以及 `224.0.2.60:4445`、`224.0.0.251:5353`；发送者必须是本房间成员；按发送者的虚拟地址重建数据包后再注入。发送端套用同一规则。 | `8e802cc` |
| S3 | 接收端只做去重，不限速：恶意房间中转可以绕过中转侧的限速直接灌包。 | 先按发送者限速（10 个/秒），再全局限速（100 个/秒）。先按发送者限速，是为了让单个狂发者被拒的包不消耗全局额度。改走 WireGuard（S5）后保留不变，丢弃计入 `GetRelays.discovery.drop.rate_limited`。 | `8e802cc`，本版 |
| S4 | Linux 上若 `net.ipv4.conf.<TUN>.bc_forwarding=1`，注入的 `172.22.255.255` 不在本机投递，而是被内核从 TUN 原样发回（见第 3 节），本机收不到局域网发现，发回的包还会被当作本机广播再发回房间，形成回环。 | Core 创建 TUN 后把该接口的 `bc_forwarding` 置 0（由入接口的值决定，`all` 为 1 时同样有效）；发送端不再发送源地址在 MSST-Net 网段内、但不是本机的发现包（任何平台上被系统弹回的别人的包都不会再发回房间）。 | 本版 |
| S5 | sdisc 的发送者只由中转声明（第 2 节）：恶意中转（例如建房人运营的房间中转）可以冒充任意房间成员发送发现包。 | 采用方案一：发现包经 WireGuard 逐成员发送，发送者端到端认证；sdisc 完全退役（不再发送、不再接受，关闭 UDP 21032），不支持新协议的成员不降级到中转，而是不发送、不接收，并在房间视图中标为 `unsupported`。接收端的成员资格检查、广播规则、按发送者重建和双层限速保留不变。 | 本版 |
| — | 物理网卡广播捕获的回环：成员伪造“源地址 = 本机局域网 IP、目的地址 = 255.255.255.255”的包，注入后会被本机的原始套接字当作本机广播再发回房间。 | S2 的重建使注入包的源地址总是发送者的虚拟地址，捕获时被忽略（测试 `injected_broadcasts_are_not_captured_again`）。 | `8e802cc` |

## 2. sdisc 的发送者认证：由中转声明，不是端到端（已由 S5 解决）

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

以下两小节描述的是 S1–S4 修复后、S5 之前的状态，作为改用 WireGuard 的依据保留。

### 恶意中转在 S5 之前仍能做到

- 以**任意当前房间成员**的名义向任意成员投递发现包（Core 检查发送者是否为房间成员，但成员 ID 是中转声明的）。
- 内容是任意 UDP 载荷，发往 MSST-Net 广播地址的任意端口，或两个组播组的固定端口。例如以成员 A 的名义伪造一个“A 开的 Minecraft 局域网世界”，玩家点进去后连接的是 A 的地址和伪造的端口，仍要经过 A 的入站 ACL。
- 选择性丢弃或只投给部分成员（拒绝服务）。这在任何转发方案下都无法避免。

### S1–S4 之后已经做不到

- 单播、非 UDP、IP 选项、分片。
- 伪造房间成员以外的源地址，或伪造某个成员的任意源地址（注入前一律按声明的发送者的虚拟地址重建）。
- 让包被本机转发到其他网络（只允许 MSST-Net 广播地址、受限广播和两个组播组，见第 3 节）。
- 超过每个发送者 10 个/秒、合计 100 个/秒。

### 采用的方案：发现包经 WireGuard 逐成员发送（S5）

候选方案有三个：经 WireGuard 逐成员发送；逐接收者 MAC（包长随人数增长，16 字节 × N）；每台设备增加 Ed25519 签名密钥（需要 Coordinator 分发，改动最大）。最终选择第一种，具体设计如下：

- **消息格式**（`src/discovery.rs` 的 `Message`）：一个发往接收者虚拟 IPv4 的 IPv4 包，协议号 253，载荷为 `"MSDM" ‖ 版本 1 ‖ 0 ‖ 目的地址(4) ‖ 源端口(2) ‖ 目的端口(2) ‖ UDP 载荷`。它和普通数据一样经 WireGuard 加密，走该成员当前的路径（直连或中转），中转只转发密文。由于发往本机地址，它照常通过“对端包必须发给本机”（S1）的检查，不需要开例外。中转路径探测也用协议号 253（魔数 `MSRP`），两者靠魔数区分。
- **发送者认证**：由 WireGuard 会话保证。接收方只按会话对应的设备认定发送者，并且只认它自己的虚拟地址（S1）。
- **能力声明**：Core 在端点列表中上报 `feature:wgdisc1`。它不是地址，Coordinator 原样下发，旧客户端会忽略。只有实际运行游戏发现的 Core 才声明；内嵌的 Android Core 没有游戏发现（与 3.0.x 一致），所以不声明。
- **拒绝静默降级**：成员公布的端点里没有该标记时（Core 3.1.5 及以前），不给它发、也收不到它的（它只会发 sdisc，而 sdisc 已退役），房间视图中该成员的 `discovery` 显示为 `"unsupported"`，`GetRelays.discovery.tx_skipped_unsupported` 计数。任何情况下都不经中转转发发现包。
- **发现权限**（独立于入站 ACL）：发送方必须是本房间成员；载荷按发送者的虚拟地址重建，并且必须符合广播规则（UDP；MSST-Net 广播或受限广播的任意端口，或两个发现组播组的固定端口；UDP 载荷不超过 1200 字节）；接收端每个发送者 10 个/秒、合计 100 个/秒。
- **代价**：每个广播发 N 份（N 为支持该协议的成员数）。第一次发送时会触发与各成员的 WireGuard 握手，消息在握手期间排队。
- **sdisc 退役**：不再向中转注册（`0x0A`）、不再发送（`0x0B`）、不再接受投递（`0x0C`），UDP 21032 不再监听。中转仍可为旧客户端提供 sdisc，客户端只是不再使用。

测试：`discovery::tests`（格式往返、与探测包互不混淆、重建与规则、双层限速、能力判定），`runtime::tests::discovery_goes_to_each_member_end_to_end`（两个 Core 经模拟中转：投递、只有 WireGuard 帧经过中转、非成员被丢弃），`runtime::tests::no_discovery_to_a_member_without_support`（不支持的成员什么也收不到，中转上也没有任何包）。

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

## 3a. 恶意中转与恶意对端：第二轮核查

威胁模型：
- **恶意中转**：官方中转被攻破，或建房人运营的房间中转。它知道本机的地址，能向 UDP 21031 发送任意数据包，也能丢弃、延迟、重放经过它的数据。
- **恶意对端**：房间成员，或同一 Coordinator 下认识本机的设备。它能发送任意 WireGuard 内层数据，能通过 Coordinator 公布任意端点。

Coordinator 仍是信任根（下发公钥、中转列表、房间状态），但它下发的、本来就由对端自己决定的内容（端点、`relay:`）以及对端地址不再被当作可信输入直接使用。

| 编号 | 问题 | 修复 | 测试 |
|---|---|---|---|
| T1 | 对端的虚拟地址来自 Coordinator，只检查能否解析成 IP。地址不在 MSST-Net 网段时，对端发来的包会被当作来自那个地址（可冒充 `8.8.8.8` 之类访问本机服务）；和其他设备或本机重复时，可接管别人的流量。 | `nodes::peer_addresses_ok`：IPv4、IPv6 必须在 MSST-Net 网段，不能是本机地址，也不能是其他已知设备的地址，否则忽略该对端。 | `nodes::tests::peers_get_only_their_own_msst_net_addresses` |
| T2 | 对端公布的直连候选（以及 Coordinator 的打洞请求）可以是环回、未指定、组播、广播、链路本地地址，数量也不限：本机会照着去探测和打洞，包括本机自己的服务。 | `ip::is_valid_candidate` 过滤这些地址，去重，每个对端最多 16 个候选；打洞请求套用同一规则。 | `ip::tests::candidate_addresses`、`endpoints::tests::candidates_never_point_at_this_host_or_beyond_a_link`、`candidates_are_capped` |
| T3 | 对端发来的 ICMP 不经 ACL：除回显请求外全部放行，包括重定向，以及引用本机其他连接的差错报文（例如对本机到某个网站的 TCP 连接伪造“需要分片”或“不可达”）。 | `packet::icmp`：只放行回显应答、回显请求（仍受 ping 开关控制），以及引用“本机发给该对端的包”的差错报文；ICMPv6 同理，邻居发现、MLD 等一律丢弃。 | `packet::icmp::tests`、`inbound::tests::icmp_from_a_peer_is_limited_to_what_it_may_send` |
| T4 | 对端公布的 `relay:` 会被本机每 5 秒 ping 一次、做 DNS 解析，并作为发往该对端数据的目标：恶意对端可以让所有认识它的设备持续向任意主机发包，也能让开了“禁用 P2P”的用户把公网 IP 暴露给它指定的服务器。 | 只认 Coordinator 官方列表里的中转（`NetState::official_relays`，每次选择中转时更新，拉取失败则沿用上一次的列表）；其余忽略，改用本机自己的中转，也不再 ping。房间中转另行校验（T5）。首选中转从设计上就只支持官方中转（主要用于大内网模式），3.1.5 及以前对列表之外的首选中转“不带密钥照用”的行为与设计不符，一并改为：选择中转时忽略并自动选择，`SetNetSettings` 在列表已知时直接拒绝（`invalid_settings`）；按地址匹配到的官方中转改用其列表名称，保证其他设备能认出它。 | `runtime::tests::a_peer_can_only_name_an_official_relay`、`relay::tests::only_an_official_relay_can_be_preferred`、`ipc::handler::tests::only_an_official_relay_can_be_preferred` |
| T5 | 房间中转地址由建房人指定，没有任何校验：可以让所有成员向他们自己局域网或本机的任意地址注册、ping、发数据。 | `room_relay::acceptable_addr`：房间中转必须是公网单播地址（拒绝环回、私有、CGNAT、链路本地、唯一本地、组播、文档、保留地址以及 MSST-Net 网段），数字地址在解析 `room_state` 时检查，域名在每次解析后检查。 | `ip::tests::public_unicast_addresses`、`room_relay` 的 `from_room_state` 测试 |
| T6 | 任何人（包括恶意中转）向 21031 发一个 P2P ping，本机都会回 pong，pong 里带着本机设备 ID，可用于识别本机；伪造的 ping 也会被反射。 | 只应答发给本机设备 ID、且来自已知对端的 ping。 | `runtime::tests::p2p_pings_are_answered_only_from_known_peers_to_us` |
| T7 | 每个带陌生 `src_id` 的 WireGuard 帧都会触发一次向 Coordinator 的查询，没有频率上限；查不到的设备会进入负缓存，过期条目从不清理。伪造帧可以让本机持续查询 Coordinator（并被限流），负缓存还会无限增长。 | 这类“未经请求”的查询每秒最多 5 次；负缓存超过 1024 条时清理过期条目。 | `nodes::tests::unsolicited_fetches_are_rate_limited`、`negative_results_of_forged_ids_dont_pile_up` |
| T8 | sdisc 退役后，加入房间和重连时仍向 Coordinator 发送 `discovery_join` / `discovery_leave`。 | 不再发送。 | `rooms`、`coordinator` 的重连测试（只剩 `register`、`join`） |

综合测试 `runtime::tests::a_malicious_relay_can_neither_inject_nor_impersonate`：模拟中转向本机发送伪造的 sdisc 投递、冒充已知对端的 WireGuard 握手和数据、来自未知设备或发给别人的 P2P ping、500 个虚构设备的握手；结果是没有任何东西进入 TUN，加密会话状态不变，没有 pong 泄露设备 ID，握手暂存表不超过上限，只有已知对端的 ping 得到应答。

核查后确认没有问题的部分：
- 伪造的 WireGuard 消息（握手、数据）在认证失败时不改变任何会话状态；握手洪泛由 boringtun 的 cookie 机制限速。
- STUN 响应按随机事务 ID 匹配，中转 RTT 应答按来源地址匹配，伪造的只能影响发包方自己。
- 中转路径探测、游戏发现消息都在 WireGuard 会话内，只能由该对端自己产生；游戏发现另有成员资格检查和限速。
- DNS 只在 `*.msst.net` 域内应答，对端主机名不能劫持外部域名。
- TLS：没有关闭证书校验的配置。

仍然依赖 Coordinator 的部分：对端公钥、官方中转列表及其公钥、房间状态和成员关系。Coordinator 被攻破时这些都会受影响；服务端的 C3、R3 上线后，设备 ID 抢注和中转注册冒充这两条路径会被堵上。

## 4. 测试结果（3.1.6，提交前）

- `cargo test --workspace`：全部通过（msst-net-core 260、msst-core-state 236、msst-acl-engine 47、msst-ipc-protocol 22、IPC 契约向量 2、文档测试 1）。
- `cargo clippy --workspace --all-targets`：与 3.1.5 相比没有新增告警。
- 新增测试：
  - S1：`runtime::tests::peers_talk_wireguard_through_a_relay` 中发往 `192.168.1.10` 的包不进入 TUN（去掉检查后该断言失败，已验证）。
  - S2：`discovery::tests` 中的 `discovery_is_udp_broadcast_or_known_multicast`、`message_round_trip`（含按发送者地址重建）、`injected_broadcasts_are_not_captured_again`。
  - S3：`receive_limits_per_sender_then_in_total`、`outbound_dedup_and_rate_limit`。
  - S4：`another_members_packet_is_never_sent_again`，以及第 3 节的命名空间实测。
  - S5：见第 2 节末尾。
  - IPC 契约向量更新：房间视图的成员新增 `discovery` 字段（没有其他变化）。

## 5. 遗留问题

- 与 Core 3.1.5 及以前、以及内嵌 Android Core 的成员之间没有游戏发现（会显示为 `unsupported`）。这是“拒绝静默降级”的直接结果。
- 中转侧：sdisc 可在旧客户端退出后退役；Coordinator 创建房间时对房间中转 `sdisc1` 的要求可以取消（见 `SERVER_FOLLOWUPS_3.1.md`）。
- 服务端 C3（`device_key_proof` 改为 `required`）、R3（中转 `register_auth` 改为 `required`）仍待上线。
- Windows、macOS、Android 上放行的广播是否会被转发或回发，尚待真机验证（第 3 节）。
- 3.1.5 审查中的低危项（身份文件权限、P2P pong 泄露设备 ID、对端公布的直连地址未过滤、网页端登录限速）尚未处理。
