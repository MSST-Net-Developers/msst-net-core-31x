//! Core runtime — orchestrates all background tasks.
//!
//! The `CoreRuntime` owns the lifecycle of every background task the Core
//! daemon needs: inbound packet processing, scheduler tick, housekeeping,
//! and more.

mod task_handle;

use crate::coordinator::{CoordinatorClient, CoordinatorConfig, CoordinatorEvent};
use crate::state::CoreState;
pub use task_handle::{TaskHandle, cancel_all};

use msst_core_state::nat::stun;
use msst_core_state::net::msst_packet;
use msst_core_state::net::relay::{self, classify_packet};
use msst_core_state::encryption::Outbound;
use msst_core_state::packet::{self, PipelineVerdict, StaticPingPolicy};
use msst_core_state::scheduler::actions::SchedulerAction;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

// ---------------------------------------------------------------------------
// CoreRuntime
// ---------------------------------------------------------------------------

/// The Core runtime — owns all background tasks and the shared state.
pub struct CoreRuntime {
    pub state: Arc<CoreState>,
    tasks: Vec<TaskHandle>,
}

impl CoreRuntime {
    pub fn new(state: Arc<CoreState>) -> Self {
        CoreRuntime {
            state,
            tasks: Vec::new(),
        }
    }

    pub fn spawn(&mut self, name: &'static str, future: impl std::future::Future<Output = ()> + Send + 'static) {
        let handle = tokio::spawn(future);
        self.tasks.push(TaskHandle::new(name, handle));
        debug!("spawned task: {}", name);
    }

    /// Start the inbound packet processing loop.
    pub fn start_inbound(
        &mut self,
        udp: Arc<tokio::net::UdpSocket>,
        tun_tx: mpsc::Sender<Vec<u8>>,
    ) {
        let state = self.state.clone();
        self.spawn("inbound", async move {
            inbound_loop(udp, state, tun_tx).await;
        });
    }

    /// Start the P2P scheduler tick (1-second cycle).
    pub fn start_scheduler_tick(&mut self) {
        let state = self.state.clone();
        self.spawn("scheduler-tick", async move {
            scheduler_tick_loop(state).await;
        });
    }

    /// Start the housekeeping loop (periodic cleanup).
    pub fn start_housekeeping(&mut self) {
        let state = self.state.clone();
        self.spawn("housekeeping", async move {
            housekeeping_loop(state).await;
        });
    }

    /// Start the Coordinator WebSocket client and event handler.
    ///
    /// Connects to the Coordinator, registers the device, and dispatches
    /// incoming events to the P2P scheduler and Core state.
    pub fn start_coordinator(&mut self, config: CoordinatorConfig, preferred_relay: Option<String>) {
        let state = self.state.clone();

        // Create the coordinator client and event channel.
        let (event_tx, mut event_rx) = mpsc::channel::<CoordinatorEvent>(64);
        let client = Arc::new(CoordinatorClient::new(config.clone(), event_tx));
        let _ = state.coordinator.set(client.clone());

        // Spawn the WS connection loop.
        let client_for_ws = client.clone();
        let state_for_ws = state.clone();
        self.spawn("coordinator-ws", async move {
            client_for_ws.run(state_for_ws).await;
        });

        // Keep the short-lived OIDC access token fresh.
        let client_for_refresh = client.clone();
        let state_for_refresh = state.clone();
        self.spawn("coordinator-token-refresh", async move {
            client_for_refresh.refresh_loop(state_for_refresh).await;
        });

        // Spawn the event handler (dispatches coordinator events to Core).
        let client_for_handler = client.clone();
        self.spawn("coordinator-events", async move {
            coordinator_event_loop(client_for_handler, &mut event_rx, &state, preferred_relay).await;
        });
    }

    /// Start the on-demand node fetcher.
    pub fn start_fetcher(&mut self) {
        let handle = crate::nodes::spawn_fetcher(self.state.clone());
        self.tasks.push(TaskHandle::new("node-fetcher", handle));
    }

    /// Start the local DNS resolver (+ system split-DNS) and the game
    /// discovery proxy.  Requires the TUN (`iface`).
    pub async fn start_dns_and_discovery(&mut self, iface: &str, tun_tx: mpsc::Sender<Vec<u8>>) {
        let resolver = crate::dns::DnsResolver::new(&self.state);
        let _ = self.state.dns.set(resolver.clone());
        let mode = self.state.net_settings.read().await.linux_dns_mode;
        let (fell_back, handle) = crate::dns::start(resolver, iface, mode).await;
        if let Some(h) = handle {
            self.tasks.push(TaskHandle::new("dns", h));
        }
        if fell_back {
            // Remember the fallback (3.0.x): resolvectl isn't available.
            let mut s = self.state.net_settings.write().await;
            s.linux_dns_mode = crate::net_settings::LinuxDnsMode::IptablesOnly;
            if let Err(e) = s.save(&self.state.data_dir) {
                warn!("dns: failed to persist iptables fallback: {}", e);
            }
        }
        let (disc_tx, handles) = crate::discovery::start(self.state.clone(), tun_tx).await;
        let _ = self.state.discovery_tx.set(disc_tx);
        for h in handles {
            self.tasks.push(TaskHandle::new("discovery", h));
        }
    }

    /// Start the outbound loop (TUN → route → UDP).
    pub fn start_outbound(&mut self, tun_rx: mpsc::Receiver<Vec<u8>>) {
        let state = self.state.clone();
        self.spawn("outbound", async move {
            outbound_loop(tun_rx, state).await;
        });
    }

    /// Start relay keepalive (network setting `keepalive_secs`) and relay RTT pings
    /// (every 5 s).
    pub fn start_relay_tasks(&mut self) {
        let state = self.state.clone();
        self.spawn("relay-keepalive", async move {
            relay_keepalive_loop(state).await;
        });
        let state = self.state.clone();
        self.spawn("relay-rtt", async move {
            relay_rtt_loop(state).await;
        });
    }

    /// Cancel all background tasks in reverse spawn order.
    pub async fn shutdown(self) {
        info!("shutting down {} background task(s)", self.tasks.len());
        cancel_all(self.tasks).await;
        info!("all background tasks stopped");
    }
}

// ---------------------------------------------------------------------------
// Inbound loop — packet classification + ACL pipeline
// ---------------------------------------------------------------------------

async fn inbound_loop(
    udp: Arc<tokio::net::UdpSocket>,
    state: Arc<CoreState>,
    tun_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; 65536];
    info!("inbound loop started");

    loop {
        let (len, src) = match udp.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                error!("UDP recv error: {}", e);
                continue;
            }
        };

        let data = &buf[..len];
        let now = current_unix();

        match classify_packet(data) {
            // ── MSST protocol packet ──────────────────────────────────────
            relay::ReceivedPacket::Msst(pkt) => {
                match pkt.packet_type {
                    msst_packet::TYPE_WG => {
                        // WireGuard message from a peer (direct or via relay):
                        // the only way peer data is accepted.
                        let src_id = msst_packet::decode_id(pkt.src_id);
                        if !state.encryption.lock().await.has_peer(&src_id) {
                            // No key for it yet: learn it for the retransmission.
                            if !src_id.is_empty() && !state.net.read().await.peer_list.contains(&src_id) {
                                crate::nodes::demand(&state, crate::nodes::FetchDemand::ByDevice(src_id));
                            }
                            continue;
                        }
                        let (res, changes) = {
                            let mut enc = state.encryption.lock().await;
                            (enc.inbound(&src_id, &pkt.payload, now), enc.take_changes())
                        };
                        state.emit_encryption_changes(changes);
                        // Replies take the same route as data to the peer
                        // (its direct endpoint or its relay), else go back
                        // the way the message came.
                        if !res.reply.is_empty() {
                            let target = peer_target(&state, &src_id).await.unwrap_or(src);
                            send_wg(&state, &src_id, target, &res.reply).await;
                        }
                        if let Some(ip) = res.packet {
                            if !crate::inbound::from_peer_address(&state, &src_id, &ip).await {
                                debug!("inbound: dropped WireGuard packet from {} with a foreign source address", src_id);
                            } else if let Some(probe) = crate::tunnel_probe::Probe::decode(&ip) {
                                // Relay-path probe: Core's own, never the TUN's.
                                on_tunnel_probe(&state, &src_id, probe, src).await;
                            } else {
                                crate::inbound::deliver_inbound(&state, &tun_tx, ip).await;
                            }
                        }
                    }
                    msst_packet::TYPE_P2P_PING => {
                        // Echo the payload back as a pong so the sender can
                        // measure the direct path's RTT.
                        if pkt.payload.len() < msst_packet::PING_PAYLOAD_LEN { continue; }
                        // P2P disabled: unanswered, so the peer's direct
                        // path to us goes back to the relay as well.
                        if state.net_settings.read().await.disable_p2p { continue; }
                        let local_id = state.net.read().await.local_device_id.clone();
                        if local_id.is_empty() { continue; }
                        let pong = msst_packet::build_p2p_pong(&local_id, &msst_packet::decode_id(pkt.src_id), &pkt.payload);
                        let _ = udp.send_to(&pong, relay::map_send_addr(src)).await;
                    }
                    msst_packet::TYPE_P2P_PONG => {
                        // Process pong for path upgrade.
                        let peer_id = msst_packet::decode_id(pkt.src_id);
                        let (seq, sent_ms) = match msst_packet::decode_ping_payload(&pkt.payload) {
                            Some(v) => v,
                            None => continue,
                        };
                        let rtt_ms = (current_time_ms().saturating_sub(sent_ms)) as f64;
                        let src_addr = msst_core_state::net::relay::unmap_addr(src);
                        let relay_rtt = {
                            let net = state.net.read().await;
                            net.relay_rtt.for_peer(net.relay_for_peer(&peer_id), net.relay_addr.as_deref())
                        };
                        let mut sched = state.scheduler.lock().await;
                        let actions = sched.handle_pong(&peer_id, src_addr, seq, rtt_ms, relay_rtt, now);
                        drop(sched);
                        for action in actions {
                            execute_scheduler_action(&action, &state, &udp).await;
                        }
                    }
                    msst_packet::TYPE_RELAY_PING => {
                        // The relay echoed one of our RTT pings; match by source.
                        let src = msst_core_state::net::relay::unmap_addr(src);
                        let now_i = std::time::Instant::now();
                        let change = {
                            let mut net = state.net.write().await;
                            let Some((addr, ewma)) = net.relay_rtt.on_reply(src, now_i) else { continue };
                            debug!("relay RTT {} EWMA {:.1}ms", addr, ewma);
                            net.room_relay
                                .as_mut()
                                .filter(|r| r.addr.as_deref() == Some(addr.as_str()))
                                .and_then(|r| r.health.reply(now_i))
                        };
                        if let Some(change) = change {
                            room_relay_health_changed(&state, change).await;
                        }
                    }
                    _ => {
                        debug!("inbound: unhandled MSST type 0x{:02x}", pkt.packet_type);
                    }
                }
            }

            relay::ReceivedPacket::Raw(data) => {
                if stun::is_stun_response(data) {
                    // STUN response — hand it to the waiting endpoint detector.
                    crate::endpoints::on_stun_response(&state, data);
                } else {
                    trace!("inbound: unrecognized non-MSST packet ({} bytes)", data.len());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler tick loop (1-second cycle)
// ---------------------------------------------------------------------------

async fn scheduler_tick_loop(state: Arc<CoreState>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    info!("scheduler tick loop started");

    loop {
        ticker.tick().await;

        let now = current_unix();
        let now_ms = current_time_ms();

        // Collect peer endpoints and relay info from NetState.
        // The scheduler tracks endpoints internally via punch_request events.
        // Here we only collect relay info for routing decisions.
        let (endpoints, relay_routed, device_id) = {
            let net = state.net.read().await;
            let ep = net.peer_endpoints.clone();
            // Peers with a relay route (theirs, else ours): the relay path
            // can be measured (in-tunnel probe, `crate::tunnel_probe`).
            let routed: std::collections::HashSet<String> = net
                .peer_list
                .device_ids()
                .filter(|id| net.relay_addr.is_some() || net.relay_for_peer(id).is_some())
                .map(str::to_string)
                .collect();
            (ep, routed, net.local_device_id.clone())
        };

        if device_id.is_empty() { continue; }

        // Run the scheduler tick.
        let actions = {
            let mut sched = state.scheduler.lock().await;
            sched.tick(now, now_ms, &endpoints, &relay_routed)
        };

        // Execute all returned actions.
        let udp = &state.udp_socket;
        for action in &actions {
            execute_scheduler_action(action, &state, udp).await;
        }

        // Unanswered interactive-auth requests time out on time (60 s).
        crate::inbound::expire_auth_requests(&state, now).await;

        // WireGuard timers (retransmit, rekey, keepalive) and negotiation
        // timeouts; messages go over each peer's current path.
        let (msgs, changes) = {
            let mut enc = state.encryption.lock().await;
            (enc.tick(now), enc.take_changes())
        };
        state.emit_encryption_changes(changes);
        for (peer_id, msg) in msgs {
            if let Some(target) = peer_target(&state, &peer_id).await {
                send_wg(&state, &peer_id, target, std::slice::from_ref(&msg)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Housekeeping loop (60-second cycle)
// ---------------------------------------------------------------------------

async fn housekeeping_loop(state: Arc<CoreState>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut ticks: u64 = 0;
    info!("housekeeping loop started");

    loop {
        ticker.tick().await;
        let now = current_unix();

        // 1. Peer cache: refresh rule references, evict expired peers,
        //    persist every 5 minutes.
        crate::peer_cache::sync_rule_refs(&state).await;
        crate::peer_cache::evict_expired(&state).await;
        ticks += 1;
        if ticks % 5 == 0 {
            crate::peer_cache::save(&state).await;
        }

        // 2. ACL rule expiry (removes, persists, emits AclChanged).
        crate::acl::expire_rules(&state, now).await;

        // 3. Contacts: prune stale entries and persist changes.
        state.contacts.lock().unwrap_or_else(|e| e.into_inner()).prune(now);
        state.save_contacts();

        // 4. Connection-tracking and fragment-verdict expiry.
        state.conn_track.lock().unwrap_or_else(|e| e.into_inner()).cleanup(now);
        state.frag_track.lock().unwrap_or_else(|e| e.into_inner()).cleanup(now);

        // 5. Host routing check (other VPNs / networks on the MSST-Net ranges).
        crate::routing::check(&state).await;

        debug!("housekeeping: tick complete");
    }
}

// ---------------------------------------------------------------------------
// Coordinator event handler
// ---------------------------------------------------------------------------

/// Dispatch coordinator events to Core state and P2P scheduler.
async fn coordinator_event_loop(
    client: Arc<CoordinatorClient>,
    event_rx: &mut mpsc::Receiver<CoordinatorEvent>,
    state: &Arc<CoreState>,
    preferred_relay: Option<String>,
) {
    info!("coordinator event handler started");

    while let Some(event) = event_rx.recv().await {
        match event {
            // ── (Re)connected: (re)select and register a relay ────────────
            CoordinatorEvent::Connected => {
                spawn_relay_selection(state.clone(), client.clone(), preferred_relay.clone());
                // Learn our own other devices and every node our rules name.
                let uid = state.net.read().await.local_user_id.clone();
                if !uid.is_empty() {
                    crate::nodes::demand(state, crate::nodes::FetchDemand::ByUser(uid));
                }
                crate::nodes::demand_rule_targets(state).await;
                // Retry migrating 3.0.x mnemonic rules now that the
                // coordinator is reachable.
                let st = state.clone();
                tokio::spawn(async move { crate::acl::migrate_pending(&st).await });
            }

            // ── Registration confirmed ────────────────────────────────────
            CoordinatorEvent::Registered {
                hostname, ipv4, ipv6: _, user_handle, user_display_name,
            } => {
                info!("coordinator: registered hostname={} ipv4={}", hostname, ipv4);
                let mut guard = state.identity.write().await;
                if let Some(id) = guard.as_mut() {
                    if crate::coordinator::apply_registered(
                        id, &hostname, &ipv4, &user_handle, &user_display_name,
                    ) {
                        if let Err(e) = crate::identity::save(&state.data_dir, id) {
                            warn!("coordinator: failed to persist identity: {}", e);
                        }
                        drop(guard);
                        state.next_generation();
                        crate::account::emit_identity_changed(state).await;
                    }
                }
            }

            // ── Room state update ─────────────────────────────────────────
            CoordinatorEvent::RoomState { room_id, room_name, peers, relay } => {
                info!("coordinator: room_state room={} ({}), {} peer(s)", room_id, room_name, peers.len());

                let now = current_unix();

                {
                    let mut contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
                    for peer in &peers {
                        contacts.update_room_contact(&peer.device_id, None, now);
                    }
                }

                // Current co-members of this room.
                let ids: Vec<String> = peers.iter().map(|p| p.device_id.clone()).collect();
                state.net.write().await.room_peers = ids.iter().cloned().collect();
                crate::inbound::revoke_room_flows(state).await;
                crate::peer_cache::on_room_members(state, &ids).await;

                // Peer list, scheduler, WireGuard.
                for peer in &peers {
                    crate::nodes::apply_peer(state, room_peer_data(peer)).await;
                }
                apply_room_relay(state, &room_id, relay.as_ref()).await;

                // Complete a pending join.
                crate::rooms::notify_room_waiter(state, Ok(serde_json::json!({
                    "room_id": room_id,
                    "room_name": room_name,
                })));

                crate::rooms::emit_room_state(state).await;
            }

            // ── Member joined ─────────────────────────────────────────────
            CoordinatorEvent::MemberJoined { room_id, peer } => {
                let device_id = peer.device_id.clone();
                info!("coordinator: member_joined room={} device={}", room_id, device_id);
                crate::nodes::apply_peer(state, room_peer_data(&peer)).await;
                crate::peer_cache::on_member_joined(state, &device_id).await;
                state.net.write().await.room_peers.insert(device_id.clone());
                crate::rooms::emit_room_state(state).await;
                state.contacts.lock().unwrap_or_else(|e| e.into_inner())
                    .update_room_contact(&device_id, None, current_unix());
                let mut net = state.net.write().await;
                net.room_peers.insert(device_id.clone());
                let own = net.local_device_id == device_id;
                drop(net);
                if !own {
                    state.scheduler.lock().await.ensure_peer(&device_id);
                }
            }

            // ── Member left ───────────────────────────────────────────────
            CoordinatorEvent::MemberLeft { room_id, device_id } => {
                info!("coordinator: member_left room={} device={}", room_id, device_id);
                let mut net = state.net.write().await;
                net.room_peers.remove(&device_id);
                drop(net);
                crate::inbound::revoke_room_flows(state).await;
                // Kept for the room grace period, then evicted by housekeeping.
                crate::peer_cache::on_member_left(state, &device_id).await;
                crate::rooms::emit_room_state(state).await;
            }

            // ── Node added / updated (authenticated devices) ──────────────
            CoordinatorEvent::NodeAdded { device_id, endpoints, status, .. }
            | CoordinatorEvent::NodeUpdated { device_id, endpoints, status, .. } => {
                debug!("coordinator: node event {} status={}", device_id, status);
                let (known, referenced) = {
                    let net = state.net.read().await;
                    let referenced = net.acl_rules.iter().any(|r| matches!(&r.permission_group,
                        msst_acl_engine::PermissionGroup::Devices { ids } if ids.contains(&device_id)));
                    (net.peer_list.contains(&device_id), referenced)
                };
                if known {
                    let mut net = state.net.write().await;
                    if let Some(relay) = crate::relay::extract_relay(&endpoints) {
                        net.peer_list.update_relay(&device_id, &relay);
                    }
                    if !endpoints.is_empty() {
                        net.set_peer_on_room_relay(&device_id, crate::room_relay::reports_room_relay(&endpoints));
                        net.set_peer_candidates(&device_id, crate::endpoints::direct_candidates(&endpoints));
                    }
                } else if referenced {
                    // A node we care about is online: fetch it even if a
                    // recent lookup found nothing.
                    let d = crate::nodes::FetchDemand::ByDevice(device_id);
                    state.fetch_gate.lock().unwrap_or_else(|e| e.into_inner()).clear_negative(&d);
                    crate::nodes::demand(state, d);
                }
            }

            // ── Punch request (NAT traversal) ─────────────────────────────
            CoordinatorEvent::PunchRequest { peer_id, endpoints } => {
                info!("coordinator: punch_request for {} ({} endpoints)", peer_id, endpoints.len());
                let parsed_eps: Vec<std::net::SocketAddr> = endpoints
                    .iter()
                    .filter_map(|ep| ep.parse().ok())
                    .collect();
                if parsed_eps.is_empty() {
                    warn!("coordinator: punch_request for {} with no valid endpoints", peer_id);
                    continue;
                }

                let now = current_unix();
                let now_ms = current_time_ms();

                // Remember the endpoints as the peer's direct candidates (3.0.x).
                state.net.write().await.peer_endpoints.insert(peer_id.clone(), crate::endpoints::direct_candidates(&endpoints));

                // Ensure the peer is tracked.
                state.scheduler.lock().await.ensure_peer(&peer_id);

                // Dispatch to scheduler.
                let actions = {
                    let mut sched = state.scheduler.lock().await;
                    sched.handle_punch_request(&peer_id, &parsed_eps, now, now_ms)
                };

                // Execute scheduler actions (send punch packets).
                let udp = &state.udp_socket;
                for action in &actions {
                    execute_scheduler_action(action, state, udp).await;
                }
            }

            // ── Coordinator error ─────────────────────────────────────────
            CoordinatorEvent::Error { message, code } => {
                warn!("coordinator error: {}", message);
                let room_gone = code.is_none() && message == crate::rooms::ROOM_NOT_FOUND_MESSAGE;
                // Fail a pending join fast (e.g. wrong room password).
                let was_join = crate::rooms::notify_room_waiter(state, Err(crate::rooms::JoinRefused { code, message }));
                if room_gone && !was_join {
                    crate::rooms::on_rooms_gone(state).await;
                }
            }
        }
    }

    info!("coordinator event handler exited");
}

// ---------------------------------------------------------------------------
// Outbound loop (TUN → route → UDP)
// ---------------------------------------------------------------------------

async fn outbound_loop(mut tun_rx: mpsc::Receiver<Vec<u8>>, state: Arc<CoreState>) {
    info!("outbound loop started");
    // Bounds concurrent TUN-intercepted DNS resolutions (3.0.x: 32).
    let dns_sem = Arc::new(tokio::sync::Semaphore::new(32));
    while let Some(pkt) = tun_rx.recv().await {
        // Linux iptables DNS mode: queries DNAT'ed to 172.22.0.1:21053.
        if crate::dns::tun_interception_enabled(&state) && crate::dns::is_tun_dns_query(&pkt) {
            if let (Some(resolver), Some(tun_tx)) = (state.dns.get().cloned(), state.tun_tx.get().cloned()) {
                let Ok(permit) = dns_sem.clone().acquire_owned().await else { continue };
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(reply) = crate::dns::intercept_tun_dns(&resolver, &pkt).await {
                        let _ = tun_tx.send(reply).await;
                    }
                });
            }
            continue;
        }
        // Game discovery broadcasts go to the proxy while in a room.
        if crate::discovery::is_ipv4_discovery_packet(&pkt) {
            if let Some(tx) = state.discovery_tx.get() {
                if !state.net.read().await.joined_rooms.is_empty() {
                    let _ = tx.send(pkt).await;
                    continue;
                }
            }
        }
        route_outbound_packet(&pkt, &state).await;
    }
    info!("outbound loop exited (TUN reader closed)");
}

/// Route one IP packet read from the TUN to its peer.
///
/// Directly to the peer's endpoint when the path is direct, otherwise via
/// the peer's relay, falling back to our own.  Always encrypted with
/// WireGuard (`TYPE_WG`, see `docs/DATA_PLANE_ENCRYPTION.md`); the first
/// packets wait in the session's queue during the handshake.  Returns the
/// UDP target.
async fn route_outbound_packet(pkt: &[u8], state: &Arc<CoreState>) -> Option<std::net::SocketAddr> {
    route_packet(pkt, state, true).await
}

/// Send a Core-synthesized IP packet (e.g. a TCP RST) to the peer owning
/// its destination address.  Unlike TUN traffic it is *not* recorded in
/// connection tracking — otherwise the rejected peer's retry would match
/// the "related" fast path and bypass authorization.
pub(crate) async fn send_to_peer(pkt: &[u8], state: &Arc<CoreState>) -> Option<std::net::SocketAddr> {
    route_packet(pkt, state, false).await
}

async fn route_packet(pkt: &[u8], state: &Arc<CoreState>, track: bool) -> Option<std::net::SocketAddr> {
    let parsed = parse_ip_packet(pkt)?;
    let now = current_unix();

    // Record the flow so replies pass the inbound firewall ("related" path).
    // Later fragments have no ports; their datagram's flow is recorded from
    // its first fragment.
    if track && !parsed.is_later_fragment() && matches!(parsed.proto, packet::parsed::TransportProtocol::Tcp | packet::parsed::TransportProtocol::Udp) {
        state.conn_track.lock().unwrap_or_else(|e| e.into_inner()).record_outbound(
            parsed.src_ip, parsed.src_port,
            parsed.dst_ip, parsed.dst_port,
            parsed.proto.number(), now,
        );
    }

    let dst_device_id = {
        let net = state.net.read().await;
        let Some(dev) = net.peer_list.lookup_device_id_by_ip(&parsed.dst_ip) else {
            if crate::ip::is_msst_ip(&parsed.dst_ip) {
                debug!("outbound: no route for {} (peer unknown), fetching", parsed.dst_ip);
                crate::nodes::demand(state, crate::nodes::FetchDemand::ByIp(parsed.dst_ip));
            }
            return None;
        };
        dev.to_string()
    };

    let Some(target) = peer_target(state, &dst_device_id).await else {
        debug!("outbound: no reachable path for {} ({})", dst_device_id, parsed.dst_ip);
        return None;
    };
    let (out, changes) = {
        let mut enc = state.encryption.lock().await;
        (enc.outbound(&dst_device_id, pkt, now), enc.take_changes())
    };
    state.emit_encryption_changes(changes);
    match out {
        Outbound::Send(msg) => {
            if !send_wg(state, &dst_device_id, target, std::slice::from_ref(&msg)).await {
                return None;
            }
        }
        Outbound::Queued => {}
        Outbound::NoKey => {
            // Nothing is ever sent unencrypted: learn the peer's key.
            debug!("outbound: no public key for {}, dropped", dst_device_id);
            crate::nodes::demand(state, crate::nodes::FetchDemand::ByDevice(dst_device_id));
            return None;
        }
    }
    if track {
        crate::diagnostics::traffic(state, &dst_device_id).tx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Some(target)
}

/// Where frames to a peer go now: its direct endpoint, else its relay,
/// else ours.
async fn peer_target(state: &Arc<CoreState>, device_id: &str) -> Option<std::net::SocketAddr> {
    match state.scheduler.lock().await.direct_endpoint(device_id) {
        Some(ep) => Some(ep),
        None => relay_target(state, device_id).await,
    }
}

/// The relay route to a peer: the room relay or its preferred relay
/// (`NetState::relay_for_peer`), else ours.
async fn relay_target(state: &Arc<CoreState>, device_id: &str) -> Option<std::net::SocketAddr> {
    let (peer_relay, own_relay) = {
        let net = state.net.read().await;
        (net.relay_for_peer(device_id).map(str::to_string), net.relay_addr.clone())
    };
    if let Some(addr) = match &peer_relay { Some(r) => crate::relay::resolve_addr(r).await, None => None } {
        return Some(addr);
    }
    match &own_relay { Some(r) => crate::relay::resolve_addr(r).await, None => None }
}

/// Send a relay-path probe (ping or pong) to a peer inside its WireGuard
/// session, over the relay route — never the direct path.  Only with an
/// established session: a probe must not start a handshake (or wait for
/// one, which would inflate the measured RTT).
async fn send_tunnel_probe(state: &Arc<CoreState>, device_id: &str, probe: &crate::tunnel_probe::Probe) {
    use msst_core_state::encryption::EncState;
    if state.encryption.lock().await.state(device_id) != Some(EncState::Encrypted) {
        return;
    }
    let Some(target) = relay_target(state, device_id).await else { return };
    let out = state.encryption.lock().await.outbound(device_id, &probe.encode(), current_unix());
    if let Outbound::Send(msg) = out {
        send_wg(state, device_id, target, std::slice::from_ref(&msg)).await;
    }
}

/// Send a diagnostic ping (`crate::diagnostics`) to a peer inside its
/// WireGuard session over the relay route.  Unlike the relay-path probe it
/// may start a handshake: the probe waits in boringtun's queue, as a ping
/// from the TUN would.  Returns false if it could not be sent or queued.
pub(crate) async fn send_diag_probe(state: &Arc<CoreState>, device_id: &str, seq: u32) -> bool {
    let (Some(src), Some(dst)) = (vpn_ipv4(state).await, peer_ipv4(state, device_id).await) else { return false };
    let Some(target) = relay_target(state, device_id).await else { return false };
    let probe = crate::tunnel_probe::Probe { kind: crate::tunnel_probe::Kind::Ping, src, dst, seq, sent_ms: current_time_ms() };
    let (out, changes) = {
        let mut enc = state.encryption.lock().await;
        (enc.outbound(device_id, &probe.encode(), current_unix()), enc.take_changes())
    };
    state.emit_encryption_changes(changes);
    match out {
        Outbound::Send(msg) => send_wg(state, device_id, target, std::slice::from_ref(&msg)).await,
        Outbound::Queued => true,
        Outbound::NoKey => {
            crate::nodes::demand(state, crate::nodes::FetchDemand::ByDevice(device_id.to_string()));
            false
        }
    }
}

/// Answer or account for a relay-path probe that arrived in `device_id`'s
/// session from `src` (the relay it came through).
async fn on_tunnel_probe(state: &Arc<CoreState>, device_id: &str, probe: crate::tunnel_probe::Probe, src: std::net::SocketAddr) {
    use crate::tunnel_probe::Kind;
    match probe.kind {
        Kind::Ping => send_tunnel_probe(state, device_id, &probe.pong()).await,
        Kind::Pong => {
            if crate::diagnostics::on_probe_pong(state, device_id, probe.seq) {
                return;
            }
            let src = msst_core_state::net::relay::unmap_addr(src);
            let now = current_unix();
            let rtt_ms = current_time_ms().saturating_sub(probe.sent_ms) as f64;
            let relay_rtt = {
                let net = state.net.read().await;
                // Back through our own relay: its binding for us works.
                if net.relay_addr.as_deref().and_then(crate::relay::cached_addr).map(relay::unmap_addr) == Some(src) {
                    state.relay_path_ok_at.store(now, std::sync::atomic::Ordering::Relaxed);
                }
                net.relay_rtt.for_peer(net.relay_for_peer(device_id), net.relay_addr.as_deref())
            };
            let actions = state.scheduler.lock().await.handle_pong(device_id, src, probe.seq, rtt_ms, relay_rtt, now);
            for action in actions {
                execute_scheduler_action(&action, state, &state.udp_socket).await;
            }
        }
    }
}

/// Our virtual IPv4 address.
async fn vpn_ipv4(state: &CoreState) -> Option<std::net::Ipv4Addr> {
    state.identity.read().await.as_ref()?.virtual_ips().0.parse().ok()
}

/// A peer's virtual IPv4 address.
async fn peer_ipv4(state: &CoreState, device_id: &str) -> Option<std::net::Ipv4Addr> {
    match state.net.read().await.peer_list.get(device_id)?.ipv4 {
        std::net::IpAddr::V4(a) => Some(a),
        _ => None,
    }
}

/// Send WireGuard messages to a peer as `TYPE_WG` frames.  Returns false if
/// a send failed.
async fn send_wg(state: &Arc<CoreState>, device_id: &str, target: std::net::SocketAddr, msgs: &[Vec<u8>]) -> bool {
    if msgs.is_empty() {
        return true;
    }
    let local_id = state.net.read().await.local_device_id.clone();
    for m in msgs {
        let frame = msst_packet::build_wg(&local_id, device_id, m);
        if let Err(e) = state.udp_socket.send_to(&frame, relay::map_send_addr(target)).await {
            warn!("encryption: send to {} via {} failed: {}", device_id, target, e);
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Relay: selection, keepalive, RTT
// ---------------------------------------------------------------------------

/// Attempts per relay selection (bounded; the next reconnect starts over).
const RELAY_SELECT_ATTEMPTS: u32 = 3;
const RELAY_SELECT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

/// Select the best relay and register with it, in the background.
///
/// Runs on every coordinator (re)connect.  Uses `relay_epoch` so a slow,
/// older selection can never overwrite the result of a newer one.
fn spawn_relay_selection(
    state: Arc<CoreState>,
    client: Arc<CoordinatorClient>,
    preferred: Option<String>,
) {
    use std::sync::atomic::Ordering;
    let epoch = state.relay_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    tokio::spawn(async move {
        // Let the register round-trip complete first.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let device_id = state.net.read().await.local_device_id.clone();
        // The persisted network setting wins over the config file.
        let preferred = state.net_settings.read().await.preferred_relay.clone().or(preferred);

        for attempt in 1..=RELAY_SELECT_ATTEMPTS {
            if state.relay_epoch.load(Ordering::SeqCst) != epoch {
                debug!("relay: selection epoch {} superseded", epoch);
                return;
            }
            match crate::relay::select_best_relay(client.http(), client.coord_url(), &device_id, preferred.as_deref()).await {
                Ok(selected) => {
                    if state.relay_epoch.load(Ordering::SeqCst) != epoch {
                        debug!("relay: discarding result of superseded selection {}", epoch);
                        return;
                    }
                    let addr = selected.addr.clone();
                    let changed = {
                        let mut net = state.net.write().await;
                        let changed = net.relay_addr.as_deref() != Some(addr.as_str())
                            || net.relay_pub_key != selected.pub_key
                            || net.relay_sreg != selected.sreg;
                        net.relay_addr = Some(addr.clone());
                        net.relay_pub_key = selected.pub_key;
                        net.relay_sreg = selected.sreg;
                        changed
                    };
                    if changed {
                        state.next_generation();
                    }
                    info!("relay: using {}", addr);
                    register_with_relay(&state, &addr, &device_id).await;
                    // Announce our endpoints (now including the relay).
                    crate::endpoints::spawn_detect_and_report(state.clone());
                    return;
                }
                Err(e) => {
                    warn!("relay: selection attempt {}/{} failed: {}", attempt, RELAY_SELECT_ATTEMPTS, e);
                    if attempt < RELAY_SELECT_ATTEMPTS {
                        tokio::time::sleep(RELAY_SELECT_RETRY_DELAY).await;
                    }
                }
            }
        }
        warn!("relay: no relay selected; relay-routed traffic unavailable until next coordinator reconnect");
    });
}

/// Select and register a relay right now (room create/join), superseding
/// any background selection.  Bounded by the probe timeouts (~10 s).
pub(crate) async fn select_relay_now(state: &Arc<CoreState>, client: &CoordinatorClient) -> Result<String, String> {
    use std::sync::atomic::Ordering;
    let epoch = state.relay_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    let device_id = state.net.read().await.local_device_id.clone();
    let preferred = state.net_settings.read().await.preferred_relay.clone();
    let selected = crate::relay::select_best_relay(client.http(), client.coord_url(), &device_id, preferred.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    let addr = selected.addr;
    if state.relay_epoch.load(Ordering::SeqCst) == epoch {
        let mut net = state.net.write().await;
        net.relay_addr = Some(addr.clone());
        net.relay_pub_key = selected.pub_key;
        net.relay_sreg = selected.sreg;
        drop(net);
        state.next_generation();
    }
    register_with_relay(state, &addr, &device_id).await;
    Ok(addr)
}

/// (Re)register with our relay: the first packet now, the rest from
/// [`relay_keepalive_loop`] (sreg v1: again 1 s and 3 s later, then every
/// keepalive interval — see `crate::sreg`).
async fn register_with_relay(state: &Arc<CoreState>, relay_addr: &str, device_id: &str) {
    let Some(target) = crate::relay::resolve_addr(relay_addr).await else {
        warn!("relay: cannot resolve {}", relay_addr);
        return;
    };
    let sreg = state.net.read().await.relay_sreg;
    state.relay_reg.lock().unwrap_or_else(|e| e.into_inner()).restart(current_time_ms(), sreg);
    let Some(pkt) = relay_registration_packet(state, device_id, true).await else { return };
    match state.udp_socket.send_to(&pkt, relay::map_send_addr(target)).await {
        Ok(_) => info!("relay: registered with {} ({})", relay_addr, if sreg { "sreg1" } else { "legacy" }),
        Err(e) => warn!("relay: register with {} failed: {}", relay_addr, e),
    }
}

/// The next registration packet for our relay: `0x0E` (sreg v1), else the
/// legacy `0x01` register (`first`) or `0x02` keepalive.  A relay that
/// takes `0x0E` never gets `0x01`/`0x02` (it would drop them).
async fn relay_registration_packet(state: &Arc<CoreState>, device_id: &str, first: bool) -> Option<Vec<u8>> {
    if device_id.is_empty() {
        return None;
    }
    let (sreg, relay_pk) = {
        let net = state.net.read().await;
        (net.relay_sreg, net.relay_pub_key)
    };
    if !sreg {
        return Some(if first { relay::build_relay_register(device_id) } else { relay::build_relay_keepalive(device_id) });
    }
    let sk = state.identity.read().await.as_ref()?.secret_key;
    let pkt = state
        .relay_reg
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .packet(&sk, crate::sdisc::wire_id(device_id), &relay_pk?, current_time_ms());
    if pkt.is_none() {
        warn!("relay: the relay's key is invalid (low-order) — cannot register");
    }
    pkt
}

/// Keep the relay's binding for us alive: checks every second whether the
/// registration schedule (`crate::sreg::Registration::due`) wants a packet.
async fn relay_keepalive_loop(state: Arc<CoreState>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        // Re-read every cycle so a settings change applies without restart.
        let interval_ms = state.net_settings.read().await.relay_keepalive_secs().max(1) * 1000;
        let (relay_addr, device_id) = {
            let net = state.net.read().await;
            (net.relay_addr.clone(), net.local_device_id.clone())
        };
        if let Some(relay_addr) = relay_addr {
            if state.relay_reg.lock().unwrap_or_else(|e| e.into_inner()).due(current_time_ms(), interval_ms) {
                if let (Some(target), Some(pkt)) = (crate::relay::resolve_addr(&relay_addr).await, relay_registration_packet(&state, &device_id, false).await) {
                    if let Err(e) = state.udp_socket.send_to(&pkt, relay::map_send_addr(target)).await {
                        warn!("relay: keepalive to {} failed: {}", relay_addr, e);
                    }
                }
            }
        }
        // The room relay, on the same schedule (kept up while it is down,
        // so the binding is there when it comes back).
        let Some((addr, relay_pk)) = room_relay_registration_target(&*state.net.read().await) else { continue };
        if state.room_relay_reg.lock().unwrap_or_else(|e| e.into_inner()).due(current_time_ms(), interval_ms) {
            send_room_relay_registration(&state, &addr, &relay_pk, &device_id).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Room relay (`crate::room_relay`, docs/ROOM_RELAY_3.1.md)
// ---------------------------------------------------------------------------

/// Take the room relay from a `room_state`.  It never changes, so a repeated
/// `room_state` (e.g. after a reconnect) keeps its health and registration.
/// An unusable one (bad key, no `sreg1`/`sdisc1`) is ignored: everyone
/// then uses their preferred relays.
pub(crate) async fn apply_room_relay(state: &Arc<CoreState>, room_id: &str, relay: Option<&crate::coordinator::messages::RoomStateRelay>) {
    use crate::room_relay::RoomRelay;
    let new = match relay.map(|r| RoomRelay::from_room_state(room_id, r)) {
        None => None,
        Some(Ok(r)) => Some(r),
        Some(Err(e)) => {
            warn!("room relay of {} is unusable ({}): using preferred relays", room_id, e);
            None
        }
    };
    {
        let net = state.net.read().await;
        let unchanged = match (&net.room_relay, &new) {
            (Some(a), Some(b)) => a.same_as(b),
            (None, None) => true,
            _ => false,
        };
        if unchanged {
            return;
        }
    }
    let new = match new {
        Some(mut r) => {
            if r.addr.is_none() {
                r.addr = crate::relay::resolve_addr(&r.address).await.map(|a| relay::unmap_addr(a).to_string());
            }
            info!("room relay: {} ({}) for {}", r.address, if r.self_hosted { "self-hosted" } else { "official" }, room_id);
            Some(r)
        }
        None => None,
    };
    state.net.write().await.room_relay = new;
    register_with_room_relay(state).await;
    room_relay_updated(state).await;
}

/// Where to register for the room relay: its address and key, unless it is
/// our own relay (registered already) or its address is unresolved.
fn room_relay_registration_target(net: &crate::state::NetState) -> Option<(String, [u8; 32])> {
    let r = net.room_relay.as_ref()?;
    let addr = r.addr.clone()?;
    let own = net.relay_addr.as_deref();
    let ours = own == Some(r.address.as_str())
        || own.and_then(crate::relay::cached_addr).map(|a| relay::unmap_addr(a).to_string()).as_deref() == Some(addr.as_str());
    (!ours).then_some((addr, r.pub_key))
}

/// (Re)register with the room relay: the first packet now, the rest from
/// [`relay_keepalive_loop`] (again 1 s and 3 s later, then every keepalive
/// interval).  A room relay always takes `0x0E`.
async fn register_with_room_relay(state: &Arc<CoreState>) {
    let (target, device_id) = {
        let net = state.net.read().await;
        (room_relay_registration_target(&net), net.local_device_id.clone())
    };
    let Some((addr, relay_pk)) = target else { return };
    state.room_relay_reg.lock().unwrap_or_else(|e| e.into_inner()).restart(current_time_ms(), true);
    send_room_relay_registration(state, &addr, &relay_pk, &device_id).await;
}

async fn send_room_relay_registration(state: &Arc<CoreState>, addr: &str, relay_pk: &[u8; 32], device_id: &str) {
    if device_id.is_empty() {
        return;
    }
    let Some(sk) = state.identity.read().await.as_ref().map(|i| i.secret_key) else { return };
    let pkt = state.room_relay_reg.lock().unwrap_or_else(|e| e.into_inner()).packet(&sk, crate::sdisc::wire_id(device_id), relay_pk, current_time_ms());
    let Some(pkt) = pkt else {
        warn!("room relay: its key is invalid (low-order) — cannot register");
        return;
    };
    let Some(target) = crate::relay::resolve_addr(addr).await else { return };
    if let Err(e) = state.udp_socket.send_to(&pkt, relay::map_send_addr(target)).await {
        debug!("room relay: register with {} failed: {}", addr, e);
    }
}

/// The room relay appeared, went, or changed health: re-announce our
/// endpoints (`room-relay:`), and tell Controllers.
async fn room_relay_updated(state: &Arc<CoreState>) {
    state.next_generation();
    crate::rooms::emit_room_state(state).await;
    crate::endpoints::spawn_detect_and_report(state.clone());
}

/// Apply a room relay health transition.
async fn room_relay_health_changed(state: &Arc<CoreState>, (old, new): (crate::room_relay::HealthState, crate::room_relay::HealthState)) {
    use crate::room_relay::HealthState;
    match new {
        HealthState::Down => warn!("room relay: {} → down — room traffic falls back to preferred relays", old.as_str()),
        _ => info!("room relay: {} → {}", old.as_str(), new.as_str()),
    }
    if new == HealthState::Ok && old == HealthState::Down {
        // Rebind quickly: the relay may have lost our registration.
        register_with_room_relay(state).await;
    }
    room_relay_updated(state).await;
}

/// Every 5 s, ping our relay and every relay our peers are registered with,
/// so path upgrades compare against the relay path the traffic really takes.
async fn relay_rtt_loop(state: Arc<CoreState>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let (relays, device_id, health_change, unresolved_room_relay) = {
            let mut net = state.net.write().await;
            net.relay_rtt.purge_stale(std::time::Instant::now());
            let mut relays: Vec<String> = net.relay_addr.iter().cloned().collect();
            for id in net.peer_list.device_ids() {
                if let Some(r) = net.peer_list.get(id).and_then(|e| e.preferred_relay.clone()) {
                    if !relays.contains(&r) {
                        relays.push(r);
                    }
                }
            }
            // The room relay's pings also drive its health.
            let (mut change, mut unresolved) = (None, None);
            if let Some(r) = net.room_relay.as_mut() {
                change = r.health.tick();
                match &r.addr {
                    Some(a) if !relays.contains(a) => relays.push(a.clone()),
                    Some(_) => {}
                    None => unresolved = Some(r.address.clone()),
                }
            }
            (relays, net.local_device_id.clone(), change, unresolved)
        };
        if let Some(change) = health_change {
            room_relay_health_changed(&state, change).await;
        }
        if let Some(address) = unresolved_room_relay {
            // Its name didn't resolve yet: retry (pinged from the next round).
            if let Some(a) = crate::relay::resolve_addr(&address).await {
                if let Some(r) = state.net.write().await.room_relay.as_mut().filter(|r| r.address == address) {
                    r.addr = Some(relay::unmap_addr(a).to_string());
                }
                register_with_room_relay(&state).await;
            }
        }
        if device_id.is_empty() {
            continue;
        }
        let pkt = relay::build_relay_rtt_ping(&device_id);
        for addr in relays {
            let Some(target) = crate::relay::resolve_addr(&addr).await else { continue };
            let target = relay::unmap_addr(target);
            if !state.net.write().await.relay_rtt.begin(&addr, target, std::time::Instant::now()) {
                continue;
            }
            if let Err(e) = state.udp_socket.send_to(&pkt, relay::map_send_addr(target)).await {
                debug!("relay: RTT ping to {} failed: {}", addr, e);
            }
        }
    }
}

fn room_peer_data(p: &crate::coordinator::messages::RoomStatePeer) -> crate::nodes::PeerData<'_> {
    crate::nodes::PeerData {
        device_id: &p.device_id,
        ipv4: &p.ipv4,
        ipv6: &p.ipv6,
        hostname: Some(&p.hostname),
        display_name: p.device_display_name.clone(),
        user_display_name: p.user_display_name.clone(),
        public_key: &p.public_key,
        endpoints: &p.endpoints,
        is_authenticated: p.is_authenticated,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Scheduler action execution
// ---------------------------------------------------------------------------

/// Execute a single `SchedulerAction` from the P2P scheduler.
async fn execute_scheduler_action(
    action: &SchedulerAction,
    state: &Arc<CoreState>,
    udp: &Arc<tokio::net::UdpSocket>,
) {
    match action {
        SchedulerAction::UdpSend { data, target } => {
            if let Err(e) = udp.send_to(data, relay::map_send_addr(*target)).await {
                debug!("scheduler: UDP send to {} failed: {}", target, e);
            }
        }
        SchedulerAction::PathModeChanged { peer_id, old_mode, new_mode, endpoint } => {
            // Logged by the scheduler.  Traffic counters describe one path.
            crate::diagnostics::reset_traffic(state, peer_id);
            if let Some(m) = state.metrics.get() {
                let (relay, probing, direct) = state.scheduler.lock().await.mode_counts();
                m.update_path_modes(relay as i64, probing as i64, direct as i64);
            }
            state.next_generation();
            state.emit_ipc_event(msst_ipc_protocol::IpcEvent::PathChanged {
                device_id: peer_id.clone(),
                old_mode: old_mode.clone(),
                new_mode: new_mode.clone(),
                endpoint: endpoint.map(|e| e.to_string()),
            });
        }
        SchedulerAction::RelayPathProbe { peer_id, seq, sent_ms } => {
            let (Some(src), Some(dst)) = (vpn_ipv4(state).await, peer_ipv4(state, peer_id).await) else { return };
            let probe = crate::tunnel_probe::Probe { kind: crate::tunnel_probe::Kind::Ping, src, dst, seq: *seq, sent_ms: *sent_ms };
            send_tunnel_probe(state, peer_id, &probe).await;
        }
        SchedulerAction::DetectEndpoints => {
            // Periodic (5 min) re-detection.  Skipped until a relay exists:
            // relay selection triggers the first report itself.
            if state.net.read().await.relay_addr.is_some() {
                crate::endpoints::spawn_detect_and_report(state.clone());
            }
        }
        SchedulerAction::ReportEndpoints { .. } => {
            // Superseded by `endpoints::detect_and_report`.
        }
        SchedulerAction::IpcEvent { event_json } => {
            // Forward raw event JSON to IPC.
            debug!("scheduler: IPC event: {}", event_json);
        }
    }
}

// ---------------------------------------------------------------------------
// IP packet parsing (shared by inbound loop)
// ---------------------------------------------------------------------------

/// Parse the IP header (and, for IPv6, the extension header chain) and the
/// transport ports.
///
/// Fails closed: `None` (the caller drops the packet) for anything the
/// firewall could not evaluate correctly — a truncated header or header
/// chain, a first fragment without the complete TCP/UDP header (RFC 7112),
/// a TCP fragment at offset 1 (RFC 1858), more than one IPv6 Fragment
/// header, or an over-long IPv6 extension header chain.
pub(crate) fn parse_ip_packet(data: &[u8]) -> Option<packet::parsed::ParsedPacket> {
    parse_ip_packet_at(data).map(|(p, _)| p)
}

/// [`parse_ip_packet`], plus the offset of the upper-layer header (after
/// the IPv4 header / the IPv6 extension header chain).
pub(crate) fn parse_ip_packet_at(data: &[u8]) -> Option<(packet::parsed::ParsedPacket, usize)> {
    if data.is_empty() { return None; }
    let version = data[0] >> 4;
    match version {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8]) -> Option<(packet::parsed::ParsedPacket, usize)> {
    if data.len() < 20 { return None; }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl { return None; }
    let src_ip = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let flags_offset = u16::from_be_bytes([data[6], data[7]]);
    let (offset, more) = (flags_offset & 0x1FFF, flags_offset & 0x2000 != 0);
    let fragment = (offset != 0 || more).then(|| packet::parsed::Fragment {
        id: u16::from_be_bytes([data[4], data[5]]) as u32,
        offset,
        more,
    });
    let (proto, src_port, dst_port, is_echo) = parse_transport(data[9], &data[ihl..], fragment, 1, 8)?;
    Some((packet::parsed::ParsedPacket {
        src_ip: std::net::IpAddr::V4(src_ip), dst_ip: std::net::IpAddr::V4(dst_ip),
        proto, src_port, dst_port, is_icmp_echo_request: is_echo, fragment,
    }, ihl))
}

/// Extension headers walked before giving up (RFC 8200 recommends a
/// bounded chain; real traffic uses one or two).
const MAX_IPV6_EXT_HEADERS: usize = 8;

fn parse_ipv6(data: &[u8]) -> Option<(packet::parsed::ParsedPacket, usize)> {
    if data.len() < 40 { return None; }
    let src_ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
    let dst_ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);

    // Walk the extension headers to the upper-layer header.  Without this,
    // e.g. a TCP SYN behind a Destination Options or (atomic) Fragment
    // header would look like "other protocol" and bypass the ACL.
    let (mut next, mut off, mut fragment) = (data[6], 40usize, None);
    let mut seen_fragment_header = false;
    for walked in 0.. {
        let len = match next {
            // Hop-by-Hop, Routing, Destination Options: (len + 1) * 8.
            0 | 43 | 60 => (*data.get(off + 1)? as usize + 1) * 8,
            // Authentication Header: (len + 2) * 4.
            51 => (*data.get(off + 1)? as usize + 2) * 4,
            44 => {
                if seen_fragment_header { return None; }
                seen_fragment_header = true;
                8
            }
            _ => break,
        };
        if walked == MAX_IPV6_EXT_HEADERS { return None; }
        let h = data.get(off..off + len)?;
        let mut later_fragment = false;
        if next == 44 {
            let fo = u16::from_be_bytes([h[2], h[3]]);
            let (offset, more) = (fo >> 3, fo & 1 != 0);
            // An atomic fragment (offset 0, no more) is a whole packet (RFC 6946).
            if offset != 0 || more {
                fragment = Some(packet::parsed::Fragment {
                    id: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
                    offset,
                    more,
                });
            }
            later_fragment = offset != 0;
        }
        next = h[0];
        off += len;
        // A later fragment carries no further headers, only data.
        if later_fragment { break; }
    }
    let (proto, src_port, dst_port, is_echo) = parse_transport(next, data.get(off..)?, fragment, 58, 128)?;
    Some((packet::parsed::ParsedPacket {
        src_ip: std::net::IpAddr::V6(src_ip), dst_ip: std::net::IpAddr::V6(dst_ip),
        proto, src_port, dst_port, is_icmp_echo_request: is_echo, fragment,
    }, off))
}

/// Transport fields from the upper-layer header `l4` (protocol `proto`).
/// `icmp`/`echo_request` are the ICMP protocol number and echo-request type
/// of the IP family.  Later fragments have no transport header: ports 0.
fn parse_transport(
    proto: u8,
    l4: &[u8],
    fragment: Option<packet::parsed::Fragment>,
    icmp: u8,
    echo_request: u8,
) -> Option<(packet::parsed::TransportProtocol, u16, u16, bool)> {
    use packet::parsed::TransportProtocol;
    let transport = match proto {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        p if p == icmp => TransportProtocol::Icmp,
        n => TransportProtocol::Other(n),
    };
    if let Some(f) = fragment.filter(|f| f.offset != 0) {
        // Offset 1 would overwrite the TCP flags of the first fragment.
        if transport == TransportProtocol::Tcp && f.offset == 1 { return None; }
        return Some((transport, 0, 0, false));
    }
    let ports = |min: usize| -> Option<(u16, u16)> {
        (l4.len() >= min).then(|| (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]])))
    };
    Some(match transport {
        TransportProtocol::Tcp => { let (s, d) = ports(20)?; (transport, s, d, false) }
        TransportProtocol::Udp => { let (s, d) = ports(8)?; (transport, s, d, false) }
        TransportProtocol::Icmp => (transport, 0, 0, l4.first() == Some(&echo_request)),
        TransportProtocol::Other(_) => (transport, 0, 0, false),
    })
}

pub(crate) fn current_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_tcp() {
        let mut data = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0,
                           1, 2, 3, 4, 5, 6, 7, 8];
        data.extend_from_slice(&[0x30, 0x39, 0x00, 0x50]);
        data.extend_from_slice(&[0u8; 16]);
        let pkt = parse_ip_packet(&data).unwrap();
        assert_eq!(pkt.proto, packet::parsed::TransportProtocol::Tcp);
        assert_eq!(pkt.src_port, 12345);
        assert_eq!(pkt.dst_port, 80);
    }

    #[test]
    fn parse_ipv4_icmp_echo() {
        let data = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0,
                        10, 0, 0, 1, 10, 0, 0, 2, 8, 0, 0, 0];
        let pkt = parse_ip_packet(&data).unwrap();
        assert!(pkt.is_icmp_echo_request);
    }

    #[test]
    fn parse_too_short() {
        assert!(parse_ip_packet(&[]).is_none());
        assert!(parse_ip_packet(&[0x45]).is_none());
    }

    /// IPv4 172.22.1.1 → 172.22.0.1, protocol `proto`, id 7, fragment
    /// `offset` (8-byte units) / `more`.
    fn ipv4(proto: u8, offset: u16, more: bool, body: &[u8]) -> Vec<u8> {
        let fo = offset | if more { 0x2000 } else { 0 };
        let len = (20 + body.len()) as u16;
        let mut p = vec![0x45, 0, (len >> 8) as u8, len as u8, 0, 7, (fo >> 8) as u8, fo as u8, 64, proto, 0, 0,
                         172, 22, 1, 1, 172, 22, 0, 1];
        p.extend_from_slice(body);
        p
    }

    /// IPv6 ::b → ::1 with next header `next` and the given header chain + payload.
    fn ipv6(next: u8, rest: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, (rest.len() >> 8) as u8, rest.len() as u8, next, 64];
        p.extend_from_slice(&"fd22:2222:2222:2222::b".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"fd22:2222:2222:2222::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(rest);
        p
    }

    /// A 20-byte TCP SYN header 40000 → `port`.
    fn tcp_syn(port: u16) -> Vec<u8> {
        let mut t = vec![0x9c, 0x40, (port >> 8) as u8, port as u8, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0];
        t.truncate(20);
        t
    }

    /// An IPv6 Fragment header: next `next`, `offset` (8-byte units), `more`, id 9.
    fn frag_hdr(next: u8, offset: u16, more: bool) -> Vec<u8> {
        let fo = (offset << 3) | more as u16;
        vec![next, 0, (fo >> 8) as u8, fo as u8, 0, 0, 0, 9]
    }

    #[test]
    fn ipv6_extension_headers_are_walked_to_the_transport_header() {
        use packet::parsed::TransportProtocol::*;
        // Destination Options (8 bytes, PadN) then TCP.
        let mut chain = vec![6, 0, 1, 4, 0, 0, 0, 0];
        chain.extend(tcp_syn(22));
        let p = parse_ip_packet(&ipv6(60, &chain)).unwrap();
        assert_eq!((p.proto, p.src_port, p.dst_port, p.fragment), (Tcp, 40000, 22, None));

        // Hop-by-Hop, Routing (16 bytes), AH (len 1 → 12 bytes), then TCP.
        let mut chain = vec![43, 0, 1, 4, 0, 0, 0, 0];
        chain.extend([51, 1].iter().chain(&[0u8; 14]));
        chain.extend([6, 1].iter().chain(&[0u8; 10]));
        chain.extend(tcp_syn(25565));
        let p = parse_ip_packet(&ipv6(0, &chain)).unwrap();
        assert_eq!((p.proto, p.dst_port), (Tcp, 25565));

        // An atomic fragment is a whole packet.
        let mut chain = frag_hdr(6, 0, false);
        chain.extend(tcp_syn(22));
        let p = parse_ip_packet(&ipv6(44, &chain)).unwrap();
        assert_eq!((p.proto, p.dst_port, p.fragment), (Tcp, 22, None));

        // ICMPv6 echo request behind Hop-by-Hop.
        let mut chain = vec![58, 0, 1, 4, 0, 0, 0, 0];
        chain.extend([128, 0, 0, 0]);
        let p = parse_ip_packet(&ipv6(0, &chain)).unwrap();
        assert!(p.proto == Icmp && p.is_icmp_echo_request);
    }

    #[test]
    fn ipv6_fragments() {
        use packet::parsed::{Fragment, TransportProtocol::*};
        let mut first = frag_hdr(17, 0, true);
        first.extend([0x13, 0x88, 0x63, 0xdd, 0, 40, 0, 0]);
        let p = parse_ip_packet(&ipv6(44, &first)).unwrap();
        assert_eq!((p.proto, p.dst_port, p.fragment), (Udp, 25565, Some(Fragment { id: 9, offset: 0, more: true })));
        assert!(!p.is_later_fragment());

        // A later fragment: data only (here bytes that look like ports).
        let mut later = frag_hdr(17, 1, false);
        later.extend([0, 22, 0, 22, 0, 0, 0, 0]);
        let p = parse_ip_packet(&ipv6(44, &later)).unwrap();
        assert_eq!((p.proto, p.src_port, p.dst_port), (Udp, 0, 0));
        assert!(p.is_later_fragment());
    }

    #[test]
    fn unevaluable_ipv6_packets_are_rejected() {
        let mut syn = tcp_syn(22);
        // Two Fragment headers.
        let mut chain = frag_hdr(44, 0, false);
        chain.extend(frag_hdr(6, 0, false));
        chain.extend(&syn);
        assert!(parse_ip_packet(&ipv6(44, &chain)).is_none());
        // An extension header chain longer than the limit.
        let n = MAX_IPV6_EXT_HEADERS + 1;
        let mut chain: Vec<u8> = (0..n).flat_map(|i| [if i + 1 == n { 6 } else { 60 }, 0, 1, 4, 0, 0, 0, 0]).collect();
        chain.extend(&syn);
        assert!(parse_ip_packet(&ipv6(60, &chain)).is_none());
        chain.drain(..8);
        assert!(parse_ip_packet(&ipv6(60, &chain)).is_some(), "exactly the limit is fine");
        // Truncated extension header; truncated TCP header (first fragment).
        assert!(parse_ip_packet(&ipv6(60, &[6, 1, 0, 0])).is_none());
        let mut chain = frag_hdr(6, 0, true);
        syn.truncate(12);
        chain.extend(&syn);
        assert!(parse_ip_packet(&ipv6(44, &chain)).is_none());
    }

    #[test]
    fn ipv4_fragments() {
        use packet::parsed::{Fragment, TransportProtocol::*};
        let p = parse_ip_packet(&ipv4(17, 0, true, &[0x13, 0x88, 0x63, 0xdd, 0, 40, 0, 0])).unwrap();
        assert_eq!((p.dst_port, p.fragment), (25565, Some(Fragment { id: 7, offset: 0, more: true })));
        // Later fragments carry data, not ports.
        let p = parse_ip_packet(&ipv4(17, 1, true, &[0, 22, 0, 22, 0, 0, 0, 0])).unwrap();
        assert!(p.is_later_fragment());
        assert_eq!((p.proto, p.src_port, p.dst_port), (Udp, 0, 0));
        let p = parse_ip_packet(&ipv4(6, 3, false, &[0; 8])).unwrap();
        assert_eq!((p.proto, p.dst_port), (Tcp, 0));
        // RFC 1858: TCP at offset 1, or a first fragment cutting the header.
        assert!(parse_ip_packet(&ipv4(6, 1, false, &[0; 8])).is_none());
        assert!(parse_ip_packet(&ipv4(6, 0, true, &tcp_syn(22)[..8])).is_none());
        assert!(parse_ip_packet(&ipv4(17, 0, false, &[0x13, 0x88, 0x63, 0xdd])).is_none());
        // A whole packet (DF set) is not a fragment.
        let mut df = ipv4(6, 0, false, &tcp_syn(22));
        df[6] = 0x40;
        assert_eq!(parse_ip_packet(&df).unwrap().fragment, None);
        // IHL below the minimum header.
        let mut bad = ipv4(6, 0, false, &tcp_syn(22));
        bad[0] = 0x44;
        assert!(parse_ip_packet(&bad).is_none());
    }

    // ── Outbound routing (end-to-end over loopback UDP) ──────────────────

    async fn test_state() -> Arc<CoreState> {
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let state = Arc::new(CoreState::new(udp, std::env::temp_dir()));
        let id = crate::identity::Identity {
            user: crate::identity::UserInfo { id: "user-11111111".into(), handle: String::new(), display_name: String::new() },
            device: crate::identity::DeviceInfo {
                id: "device-11111111".into(), handle: String::new(), display_name: String::new(),
                hostname: String::new(), assigned_ipv4: None,
            },
            secret_key: [1u8; 32], public_key: [2u8; 32], auth: None,
        };
        state.apply_identity(&id).await;
        state
    }

    async fn add_peer(state: &Arc<CoreState>, relay: Option<&str>) {
        let mut net = state.net.write().await;
        net.peer_list.upsert(
            "device-a1b2c3d4", "172.22.178.196".parse().unwrap(), "fd22:2222:2222:2222::a1b2:c3d4".parse().unwrap(),
            None, None, None, None, None, None, false, 0,
        );
        if let Some(r) = relay {
            net.peer_list.update_relay("device-a1b2c3d4", r);
        }
        drop(net);
        let pk = crate::test_support::identity_with_key([7u8; 32]).public_key_base64();
        state.encryption.lock().await.add_peer("device-a1b2c3d4", &pk).unwrap();
    }

    /// IPv4/UDP 172.22.144.209:5000 → 172.22.178.196:25565.
    fn udp_packet() -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0,
                         172, 22, 144, 209, 172, 22, 178, 196];
        p.extend_from_slice(&[0x13, 0x88, 0x63, 0xdd, 0, 12, 0, 0]);
        p.extend_from_slice(b"ping");
        p
    }

    #[tokio::test]
    async fn outbound_goes_via_peer_relay_as_wireguard() {
        let state = test_state().await;
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        add_peer(&state, Some(&relay.local_addr().unwrap().to_string())).await;

        let pkt = udp_packet();
        let target = route_outbound_packet(&pkt, &state).await;
        assert_eq!(target, Some(relay.local_addr().unwrap()));

        let mut buf = [0u8; 2048];
        let (n, _) = relay.recv_from(&mut buf).await.unwrap();
        let frame = msst_packet::MsstPacket::decode(&buf[..n]).unwrap();
        assert_eq!(frame.packet_type, msst_packet::TYPE_WG);
        assert_eq!(msst_packet::decode_id(frame.src_id), "device-11111111");
        assert_eq!(msst_packet::decode_id(frame.dst_id), "device-a1b2c3d4");
        // No session yet: a handshake initiation; the packet waits for it.
        assert_eq!(frame.payload[0], 1);
        assert!(!frame.payload.windows(4).any(|w| w == b"ping"));

        // The flow was recorded: the reply counts as related traffic.
        let ct = state.conn_track.lock().unwrap();
        assert!(ct.is_related(
            "172.22.178.196".parse().unwrap(), 25565,
            "172.22.144.209".parse().unwrap(), 5000,
            17, current_unix(),
        ));
    }

    #[tokio::test]
    async fn outbound_falls_back_to_own_relay() {
        let state = test_state().await;
        let own = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        add_peer(&state, None).await;
        state.net.write().await.relay_addr = Some(own.local_addr().unwrap().to_string());
        assert_eq!(route_outbound_packet(&udp_packet(), &state).await, Some(own.local_addr().unwrap()));
    }

    #[tokio::test]
    async fn outbound_drops_unknown_peer_and_no_relay() {
        let state = test_state().await;
        // Unknown destination.
        assert_eq!(route_outbound_packet(&udp_packet(), &state).await, None);
        // Known peer, but no relay at all.
        add_peer(&state, None).await;
        assert_eq!(route_outbound_packet(&udp_packet(), &state).await, None);
        // Garbage.
        assert_eq!(route_outbound_packet(&[0x00, 0x01], &state).await, None);
        // Reachable, but no public key: nothing is sent unencrypted.
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        state.net.write().await.relay_addr = Some(relay.local_addr().unwrap().to_string());
        state.encryption.lock().await.remove_peer("device-a1b2c3d4");
        assert_eq!(route_outbound_packet(&udp_packet(), &state).await, None);
        let mut buf = [0u8; 64];
        assert!(tokio::time::timeout(std::time::Duration::from_millis(100), relay.recv_from(&mut buf)).await.is_err());
    }

    // ── Room expired on the coordinator ──────────────────────────────────

    /// Feed `events` to the coordinator event handler until they are used up.
    async fn handle_events(state: &Arc<CoreState>, events: Vec<CoordinatorEvent>) {
        let (ev_tx, _) = mpsc::channel(1);
        let client = Arc::new(CoordinatorClient::new(crate::coordinator::CoordinatorConfig { coord_url: "http://127.0.0.1:9".into() }, ev_tx));
        let (tx, mut rx) = mpsc::channel(events.len().max(1));
        for e in events {
            tx.send(e).await.unwrap();
        }
        drop(tx);
        coordinator_event_loop(client, &mut rx, state, None).await;
    }

    fn room_not_found() -> CoordinatorEvent {
        CoordinatorEvent::Error { message: "room not found".into(), code: None }
    }

    fn left_room_events(rx: &mut crate::state::EventReceiver) -> usize {
        let mut n = 0;
        while let Ok(e) = rx.try_recv() {
            if let msst_ipc_protocol::IpcEvent::RoomStateChanged { room_id, .. } = e {
                assert_eq!(room_id, None);
                n += 1;
            }
        }
        n
    }

    #[tokio::test]
    async fn a_room_the_coordinator_no_longer_has_is_left() {
        let (state, mut ipc) = crate::test_support::core_state("room-gone").await;
        {
            let mut net = state.net.write().await;
            net.joined_rooms.insert("space-1".into(), "Room".into());
            net.room_password_verifiers.insert("space-1".into(), "v".into());
            net.room_peers.insert("device-0000000b".into());
        }
        // A join waiting for its answer takes the error (it was about that
        // join); other errors don't touch the room.
        let (wtx, wrx) = tokio::sync::oneshot::channel();
        *state.room_waiter.lock().unwrap() = Some(wtx);
        handle_events(&state, vec![
            room_not_found(),
            CoordinatorEvent::Error { message: "密码错误".into(), code: Some("room_password_wrong".into()) },
        ]).await;
        assert!(wrx.await.unwrap().is_err());
        assert!(state.net.read().await.joined_rooms.contains_key("space-1"));
        assert_eq!(left_room_events(&mut ipc), 0);

        // Our keepalive or re-join was refused: the room expired.
        handle_events(&state, vec![room_not_found()]).await;
        {
            let net = state.net.read().await;
            assert!(net.joined_rooms.is_empty() && net.room_peers.is_empty() && net.room_password_verifiers.is_empty());
        }
        // The Controller is told, as after LeaveRoom.
        assert_eq!(left_room_events(&mut ipc), 1);
        // Not in a room any more: a late repeat changes nothing.
        handle_events(&state, vec![room_not_found()]).await;
        assert_eq!(left_room_events(&mut ipc), 0);
    }

    // ── Data-plane encryption: two Cores through a forwarding relay ──────

    type Forwarded = Arc<std::sync::Mutex<Vec<u8>>>;

    /// A relay that forwards MSST frames by `dst_id` to the registered
    /// sockets, recording each forwarded frame's type.
    async fn forwarding_relay(routes: Vec<([u8; 8], std::net::SocketAddr)>) -> (std::net::SocketAddr, Forwarded) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let seen: Forwarded = Default::default();
        let log = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = sock.recv_from(&mut buf).await {
                let Some(pkt) = msst_packet::MsstPacket::decode(&buf[..n]) else { continue };
                if let Some((_, to)) = routes.iter().find(|(id, _)| *id == pkt.dst_id) {
                    log.lock().unwrap().push(pkt.packet_type);
                    let _ = sock.send_to(&buf[..n], to).await;
                }
            }
        });
        (addr, seen)
    }

    struct WgCore {
        state: Arc<CoreState>,
        tun: mpsc::Receiver<Vec<u8>>,
        id: crate::identity::Identity,
    }

    async fn wg_core(name: &str, secret: u8) -> WgCore {
        let dir = std::env::temp_dir().join(format!("msst-test-wg-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let state = Arc::new(CoreState::new(udp.clone(), dir));
        let id = crate::test_support::identity_with_key([secret; 32]);
        state.apply_identity(&id).await;
        state.net.write().await.ping_enabled = true;
        let (tun_tx, tun) = mpsc::channel(64);
        tokio::spawn(inbound_loop(udp, state.clone(), tun_tx));
        WgCore { state, tun, id }
    }

    async fn know(core: &WgCore, other: &WgCore, relay: std::net::SocketAddr) {
        let (v4, v6) = other.id.virtual_ips();
        let pk = other.id.public_key_base64();
        crate::nodes::apply_peer(&core.state, crate::nodes::PeerData {
            device_id: &other.id.device.id, ipv4: &v4, ipv6: &v6, public_key: &pk, ..Default::default()
        })
        .await;
        let mut net = core.state.net.write().await;
        net.relay_addr = Some(relay.to_string());
        // Unauthenticated devices only accept room members (guest policy).
        net.room_peers.insert(other.id.device.id.clone());
    }

    /// IPv4 ICMP echo request.
    fn icmp_echo(src: &str, dst: &str) -> Vec<u8> {
        let (s, d): (std::net::Ipv4Addr, std::net::Ipv4Addr) = (src.parse().unwrap(), dst.parse().unwrap());
        let mut p = vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0];
        p.extend_from_slice(&s.octets());
        p.extend_from_slice(&d.octets());
        p.extend_from_slice(&[8, 0, 0, 0, 0, 1, 0, 1]);
        p
    }

    async fn enc_state(core: &WgCore, peer: &WgCore) -> Option<msst_core_state::encryption::EncState> {
        core.state.encryption.lock().await.state(&peer.id.device.id)
    }

    async fn recv_tun(core: &mut WgCore) -> Option<Vec<u8>> {
        tokio::time::timeout(std::time::Duration::from_millis(300), core.tun.recv()).await.ok().flatten()
    }

    async fn relay_pair(a: &WgCore, b: &WgCore) -> (std::net::SocketAddr, Forwarded) {
        forwarding_relay(vec![
            (msst_packet::encode_id(&a.id.device.id), a.state.udp_socket.local_addr().unwrap()),
            (msst_packet::encode_id(&b.id.device.id), b.state.udp_socket.local_addr().unwrap()),
        ])
        .await
    }

    #[tokio::test]
    async fn peers_talk_wireguard_through_a_relay() {
        use msst_core_state::encryption::EncState;
        let mut a = wg_core("a", 0x11).await;
        let mut b = wg_core("b", 0x22).await;
        let (relay, seen) = relay_pair(&a, &b).await;
        know(&a, &b, relay).await;
        know(&b, &a, relay).await;
        let mut events = a.state.subscribe_events();
        let (a4, b4) = (a.id.virtual_ips().0, b.id.virtual_ips().0);

        // First packet: waits for the handshake, then arrives encrypted.
        let ping = icmp_echo(&a4, &b4);
        assert_eq!(route_outbound_packet(&ping, &a.state).await, Some(relay));
        assert_eq!(recv_tun(&mut b).await, Some(ping.clone()));
        assert_eq!(enc_state(&a, &b).await, Some(EncState::Encrypted));
        assert!(crate::test_support::eventually(|| b.state.encryption.try_lock().is_ok_and(|e| e.state(&a.id.device.id) == Some(EncState::Encrypted))).await);
        let mut changes = Vec::new();
        while let Ok(e) = events.try_recv() {
            if let msst_ipc_protocol::IpcEvent::EncryptionChanged { new_state, .. } = e {
                changes.push(new_state);
            }
        }
        assert_eq!(changes, ["handshaking", "encrypted"]);
        // Only WireGuard ever crossed the relay.
        assert!(seen.lock().unwrap().iter().all(|t| *t == msst_packet::TYPE_WG));

        seen.lock().unwrap().clear();
        route_outbound_packet(&ping, &a.state).await;
        assert_eq!(recv_tun(&mut b).await, Some(ping.clone()));
        assert_eq!(*seen.lock().unwrap(), [msst_packet::TYPE_WG]);

        // Plaintext frames (the retired 0x04) and raw IP are ignored.
        let b_addr = b.state.udp_socket.local_addr().unwrap();
        let plain = msst_packet::MsstPacket {
            version: msst_packet::VERSION, packet_type: 0x04, flags: 0,
            src_id: msst_packet::encode_id(&a.id.device.id), dst_id: msst_packet::encode_id(&b.id.device.id),
            payload: ping.clone(),
        }
        .encode();
        a.state.udp_socket.send_to(&plain, b_addr).await.unwrap();
        a.state.udp_socket.send_to(&ping, b_addr).await.unwrap();
        assert_eq!(recv_tun(&mut b).await, None);

        // A decrypted packet must carry a's own address.
        route_outbound_packet(&icmp_echo("172.22.9.9", &b4), &a.state).await;
        assert_eq!(recv_tun(&mut b).await, None);

        // The other direction.
        let back = icmp_echo(&b4, &a4);
        seen.lock().unwrap().clear();
        route_outbound_packet(&back, &b.state).await;
        assert_eq!(recv_tun(&mut a).await, Some(back));
        assert_eq!(*seen.lock().unwrap(), [msst_packet::TYPE_WG]);
        assert_eq!(crate::diagnostics::path_view(&a.state).await["peers"][0]["encryption"], "encrypted");
    }

    #[tokio::test]
    async fn handshake_from_an_unknown_key_is_ignored() {
        use msst_core_state::encryption::EncState;
        let a = wg_core("unk-a", 0x33).await;
        let mut b = wg_core("unk-b", 0x44).await;
        let (relay, seen) = relay_pair(&a, &b).await;
        // a knows b, but b has no key for a.
        know(&a, &b, relay).await;
        let ping = icmp_echo(&a.id.virtual_ips().0, &b.id.virtual_ips().0);
        for _ in 0..3 {
            route_outbound_packet(&ping, &a.state).await;
        }
        assert_eq!(recv_tun(&mut b).await, None);
        // One initiation, the packets queued; nothing in plaintext.
        assert_eq!(*seen.lock().unwrap(), [msst_packet::TYPE_WG]);
        assert_eq!(enc_state(&a, &b).await, Some(EncState::Handshaking));
    }

    #[tokio::test]
    async fn diag_ping_through_the_relay_starts_the_session_and_measures() {
        let a = wg_core("diag-a", 0x77).await;
        let mut b = wg_core("diag-b", 0x78).await;
        let (relay, seen) = relay_pair(&a, &b).await;
        know(&a, &b, relay).await;
        know(&b, &a, relay).await;
        // No session yet, P2P never used: the ping goes through the relay.
        let job = crate::diagnostics::start_ping(&a.state, b.id.device.id.clone()).await.unwrap()["job_id"].as_str().unwrap().to_string();
        let mut done = serde_json::Value::Null;
        for _ in 0..60 {
            done = crate::diagnostics::ping_result(&a.state, &job).unwrap();
            if done["done"] == true {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(done["path"], "relay");
        let results = done["results"].as_array().unwrap();
        assert_eq!(results.len(), crate::diagnostics::DIAG_PING_COUNT);
        assert!(results.iter().all(|r| r.is_number()), "{:?}", results);
        assert!(seen.lock().unwrap().iter().all(|t| *t == msst_packet::TYPE_WG));
        // Probes are Core's own: never delivered to the peer's TUN.
        assert_eq!(recv_tun(&mut b).await, None);
        assert!(a.state.diag_probe_waiters.lock().unwrap().is_empty());
    }

    // ── Relay selection against a fake coordinator + fake relay ──────────

    #[tokio::test]
    async fn relay_path_rtt_is_measured_in_tunnel_across_two_relays() {
        use msst_core_state::encryption::EncState;
        let a = wg_core("rp-a", 0x55).await;
        let mut b = wg_core("rp-b", 0x66).await;
        // Each relay only forwards to the device registered with it.
        let (relay_a, seen_a) = forwarding_relay(vec![(msst_packet::encode_id(&a.id.device.id), a.state.udp_socket.local_addr().unwrap())]).await;
        let (relay_b, seen_b) = forwarding_relay(vec![(msst_packet::encode_id(&b.id.device.id), b.state.udp_socket.local_addr().unwrap())]).await;
        know(&a, &b, relay_a).await;
        know(&b, &a, relay_b).await;
        a.state.net.write().await.peer_list.update_relay(&b.id.device.id, &relay_b.to_string());
        b.state.net.write().await.peer_list.update_relay(&a.id.device.id, &relay_a.to_string());

        // Establish the session: A → R_B → B, B → R_A → A.
        let ping = icmp_echo(&a.id.virtual_ips().0, &b.id.virtual_ips().0);
        assert_eq!(route_outbound_packet(&ping, &a.state).await, Some(relay_b));
        assert_eq!(recv_tun(&mut b).await, Some(ping));
        assert_eq!(enc_state(&a, &b).await, Some(EncState::Encrypted));

        // A probes B (a dummy candidate keeps it in Probing): the relay-path
        // probe goes in-tunnel and the RTT comes back.
        let candidate: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let actions = {
            let mut sched = a.state.scheduler.lock().await;
            sched.handle_punch_request(&b.id.device.id, &[candidate], current_unix(), current_time_ms());
            let routed = std::collections::HashSet::from([b.id.device.id.clone()]);
            let eps = std::collections::HashMap::from([(b.id.device.id.clone(), vec![candidate])]);
            sched.tick(current_unix(), current_time_ms(), &eps, &routed)
        };
        assert!(actions.iter().any(|x| matches!(x, SchedulerAction::RelayPathProbe { .. })));
        seen_a.lock().unwrap().clear();
        seen_b.lock().unwrap().clear();
        for x in &actions {
            execute_scheduler_action(x, &a.state, &a.state.udp_socket).await;
        }
        let rtt = || async {
            let sched = a.state.scheduler.lock().await;
            sched.paths().find(|(id, _)| *id == &b.id.device.id).and_then(|(_, pp)| pp.relay_path_rtt_ms)
        };
        let mut measured = None;
        for _ in 0..50 {
            measured = rtt().await;
            if measured.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(measured.is_some(), "relay-path RTT measured");
        // Out via B's relay, back via ours, all as 0x0D; nothing for the TUN.
        assert_eq!(*seen_b.lock().unwrap(), [msst_packet::TYPE_WG]);
        assert_eq!(*seen_a.lock().unwrap(), [msst_packet::TYPE_WG]);
        assert!(a.state.relay_path_ok_at.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert_eq!(recv_tun(&mut b).await, None);
    }

    /// Datagrams a fake relay receives within `window`.
    async fn collect(relay: &tokio::net::UdpSocket, window: std::time::Duration) -> Vec<Vec<u8>> {
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        let end = tokio::time::Instant::now() + window;
        while let Ok(Ok((n, _))) = tokio::time::timeout_at(end, relay.recv_from(&mut buf)).await {
            got.push(buf[..n].to_vec());
        }
        got
    }

    #[tokio::test]
    async fn sreg_relay_gets_authenticated_registrations_only() {
        let state = test_state().await;
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_pk = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([2u8; 32])).as_bytes();
        {
            let mut net = state.net.write().await;
            net.relay_addr = Some(relay.local_addr().unwrap().to_string());
            net.relay_pub_key = Some(relay_pk);
            net.relay_sreg = true;
        }
        let keepalive = tokio::spawn(relay_keepalive_loop(state.clone()));
        register_with_relay(&state, &relay.local_addr().unwrap().to_string(), "device-11111111").await;
        // Immediately, then again about 1 s later (the relay may have
        // dropped the first while fetching our key).
        let got = collect(&relay, std::time::Duration::from_millis(1600)).await;
        keepalive.abort();
        assert_eq!(got.len(), 2, "{:?}", got);
        let id = crate::sdisc::wire_id("device-11111111");
        let key = crate::sreg::derive_key(&[1u8; 32], id, &relay_pk).unwrap();
        let mut last = 0;
        for p in &got {
            assert_eq!((p.len(), p[5]), (crate::sreg::PACKET_LEN, crate::sreg::TYPE_SREG));
            let counter = u64::from_be_bytes(p[23..31].try_into().unwrap());
            assert!(counter > last);
            last = counter;
            assert_eq!(*p, crate::sreg::build_packet(&key, id, counter), "tag verifies");
        }
        let diag = state.relay_reg.lock().unwrap().tx_sreg;
        assert_eq!(diag, 2);
    }

    #[tokio::test]
    async fn legacy_relay_still_gets_register() {
        let state = test_state().await;
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        state.net.write().await.relay_addr = Some(relay.local_addr().unwrap().to_string());
        register_with_relay(&state, &relay.local_addr().unwrap().to_string(), "device-11111111").await;
        let got = collect(&relay, std::time::Duration::from_millis(200)).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0][5], msst_packet::TYPE_REGISTER);
    }

    #[tokio::test]
    async fn relay_selection_picks_echoing_relay() {
        // Fake relay: echoes every datagram (like the real relay for TYPE_PING).
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, src)) = relay.recv_from(&mut buf).await {
                let _ = relay.send_to(&buf[..n], src).await;
            }
        });
        // Fake coordinator: one-shot HTTP response for GET /relays, listing a
        // dead relay and the live one.
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = http.local_addr().unwrap().port();
        let body = format!(r#"{{"relays":[{{"addr":"127.0.0.1:9"}},{{"addr":"{}"}}]}}"#, relay_addr);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = http.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let n = s.read(&mut req).await.unwrap();
            assert!(String::from_utf8_lossy(&req[..n]).starts_with("GET /relays "));
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(), body
            );
            s.write_all(resp.as_bytes()).await.unwrap();
        });

        let chosen = crate::relay::select_best_relay(
            &reqwest::Client::new(), &format!("http://127.0.0.1:{}", port), "device-11111111", None,
        ).await.unwrap();
        assert_eq!(chosen.addr, relay_addr.to_string());
        assert_eq!(chosen.pub_key, None);
    }

    /// The room relay: registered at once (sreg v1) and again by the
    /// keepalive loop; its health follows real `0x05` echoes; room traffic
    /// goes through it only while it works and the peer reports being on
    /// it too.
    #[tokio::test]
    async fn room_relay_registration_health_and_routing() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use crate::room_relay::HealthState;
        let state = test_state().await;
        let (tun_tx, _tun) = mpsc::channel(4);
        tokio::spawn(inbound_loop(state.udp_socket.clone(), state.clone(), tun_tx));

        // Our own relay stays silent; the room relay echoes RTT pings
        // while `echo` is set and reports everything it receives.
        let own = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let own_addr = own.local_addr().unwrap();
        let room = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let room_addr = room.local_addr().unwrap();
        let echo = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (seen_tx, mut seen) = mpsc::unbounded_channel::<Vec<u8>>();
        {
            let (room, echo) = (room.clone(), echo.clone());
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                while let Ok((n, src)) = room.recv_from(&mut buf).await {
                    if buf[5] == msst_packet::TYPE_RELAY_PING && echo.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = room.send_to(&buf[..n], src).await;
                    }
                    let _ = seen_tx.send(buf[..n].to_vec());
                }
            });
        }
        add_peer(&state, Some(&own_addr.to_string())).await;
        {
            let mut net = state.net.write().await;
            net.relay_addr = Some(own_addr.to_string());
            net.room_peers.insert("device-a1b2c3d4".into());
            net.joined_rooms.insert("space-1".into(), "Room".into());
        }
        let relay_pk = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([2u8; 32])).as_bytes();
        let room_state_relay = crate::coordinator::messages::RoomStateRelay {
            address: room_addr.to_string(),
            pub_key: STANDARD.encode(relay_pk),
            features: vec!["sdisc1".into(), "sreg1".into()],
            self_hosted: true,
        };
        let id = crate::sdisc::wire_id("device-11111111");
        let key = crate::sreg::derive_key(&[1u8; 32], id, &relay_pk).unwrap();

        // Registered at once, then ~1 s later by the keepalive loop.
        apply_room_relay(&state, "space-1", Some(&room_state_relay)).await;
        let keepalive = tokio::spawn(relay_keepalive_loop(state.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let mut regs = Vec::new();
        while let Ok(p) = seen.try_recv() {
            regs.push(p);
        }
        keepalive.abort();
        assert_eq!(regs.len(), 2, "{:?}", regs);
        for p in &regs {
            let counter = u64::from_be_bytes(p[23..31].try_into().unwrap());
            assert_eq!(*p, crate::sreg::build_packet(&key, id, counter), "a 0x0E for the room relay's key");
        }
        // A repeated room_state (e.g. after a reconnect) changes nothing.
        apply_room_relay(&state, "space-1", Some(&room_state_relay)).await;
        assert!(seen.try_recv().is_err());
        assert_eq!(state.net.read().await.room_relay.as_ref().unwrap().health.state(), HealthState::Probing);

        // Health: the first echoed ping makes it ok.
        let rtt = tokio::spawn(relay_rtt_loop(state.clone()));
        let mut ok = false;
        for _ in 0..100 {
            if state.net.read().await.room_relay.as_ref().unwrap().health.state() == HealthState::Ok {
                ok = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        rtt.abort();
        assert!(ok, "room relay never became ok");
        assert_eq!(crate::rooms::room_view(&state).await["room_relay"], serde_json::json!({ "address": room_addr.to_string(), "self_hosted": true, "state": "ok" }));

        // Routing: the room relay only once the peer reports it too.
        assert_eq!(relay_target(&state, "device-a1b2c3d4").await, Some(own_addr));
        state.net.write().await.set_peer_on_room_relay("device-a1b2c3d4", true);
        assert_eq!(relay_target(&state, "device-a1b2c3d4").await, Some(room_addr));
        // Not for a peer outside the room.
        state.net.write().await.room_peers.clear();
        assert_eq!(relay_target(&state, "device-a1b2c3d4").await, Some(own_addr));
        state.net.write().await.room_peers.insert("device-a1b2c3d4".into());

        // Three missed rounds: down, back to the preferred relays.
        echo.store(false, std::sync::atomic::Ordering::Relaxed);
        {
            let mut net = state.net.write().await;
            let h = &mut net.room_relay.as_mut().unwrap().health;
            for _ in 0..4 {
                h.tick();
            }
            assert_eq!(h.state(), HealthState::Down);
        }
        assert_eq!(relay_target(&state, "device-a1b2c3d4").await, Some(own_addr));
    }
}
