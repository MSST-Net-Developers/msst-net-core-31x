//! # msst-acl-engine
//!
//! Stateless ACL rule matching engine for MSST-Net Core.
//!
//! This crate is **pure logic** — no I/O, no async, no side effects.
//! It takes a set of firewall rules and a packet descriptor, and returns a
//! structured [`Decision`] explaining what happened.
//!
//! ## Priority (AGENTS.md §10)
//!
//! From highest to lowest:
//!
//! 1. Device-level DENY
//! 2. Device-level ALLOW
//! 3. User-level DENY
//! 4. User-level ALLOW
//! 5. Space-level DENY
//! 6. Space-level ALLOW
//! 7. Default: **DENY** (unmatched inbound traffic)
//!
//! Within each priority slot, the **first** rule that matches wins.
//!
//! ## Explainability (AGENTS.md §11)
//!
//! Every evaluation returns a [`Decision`] that answers:
//! - What source matched?
//! - What service matched?
//! - Which rule matched?
//! - What scope did the rule have?
//! - Why did the rule win?
//! - Was the final decision ALLOW or DENY?

mod decision;
mod match_context;
mod rules;

pub use decision::{Decision, DecisionReason, MatchedRule};
pub use match_context::{MatchContext, PrincipalRef};
pub use rules::{
    Action, Direction, FirewallRule, PermissionGroup, Protocol, ProtocolPort, Scope,
};

/// Evaluate the firewall rules for an inbound or outbound packet.
///
/// Returns a [`Decision`] that is always fully populated — even when no rule
/// matches (the default-deny case).
///
/// `resolve_user_devices` is a closure that, given a user ID, returns the set
/// of device IDs belonging to that user.  This keeps the engine free of any
/// specific peer-list implementation.
pub fn evaluate<F>(
    ctx: &MatchContext<'_>,
    rules: &[FirewallRule],
    resolve_user_devices: F,
) -> Decision
where
    F: Fn(&str) -> Vec<String>,
{
    // Track the first match for each priority slot.
    // Order: device_deny, device_allow, user_deny, user_allow, space_deny, space_allow.
    let mut device_deny:  Option<MatchedRule> = None;
    let mut device_allow: Option<MatchedRule> = None;
    let mut user_deny:    Option<MatchedRule> = None;
    let mut user_allow:   Option<MatchedRule> = None;
    let mut space_deny:   Option<MatchedRule> = None;
    let mut space_allow:  Option<MatchedRule> = None;

    for rule in rules {
        if !rule.is_active(ctx.now_unix) {
            continue;
        }
        if rule.direction != ctx.direction {
            continue;
        }
        if !rule.protocol_ports.iter().any(|pp| pp.matches(ctx.proto, ctx.dst_port)) {
            continue;
        }

        let matches_principal = match &rule.permission_group {
            PermissionGroup::Devices { ids } => ids.iter().any(|id| {
                if id == "*" { return true; }
                if id == ctx.src_device_id { return true; }
                // Resolve device mnemonics via the context.
                if !id.starts_with("device-") {
                    return ctx.resolve_device_mnemonic(id)
                        .map(|resolved| resolved == ctx.src_device_id)
                        .unwrap_or(false);
                }
                false
            }),
            PermissionGroup::Users { ids } => ids.iter().any(|uid| {
                if uid == "*" { return true; }
                resolve_user_devices(uid).iter().any(|d| d == ctx.src_device_id)
            }),
            PermissionGroup::Space => ctx.in_room_with_src,
        };

        if !matches_principal {
            continue;
        }

        let matched = MatchedRule {
            rule_id: rule.id.clone(),
            comment: rule.comment.clone(),
            action: rule.action.clone(),
            scope: match &rule.permission_group {
                PermissionGroup::Devices { .. } => rules::Scope::Device,
                PermissionGroup::Users { .. }   => rules::Scope::User,
                PermissionGroup::Space          => rules::Scope::Space,
            },
        };

        match (&rule.action, &rule.permission_group) {
            (Action::Deny,  PermissionGroup::Devices { .. }) => { if device_deny.is_none()  { device_deny  = Some(matched); } }
            (Action::Allow, PermissionGroup::Devices { .. }) => { if device_allow.is_none() { device_allow = Some(matched); } }
            (Action::Deny,  PermissionGroup::Users { .. })   => { if user_deny.is_none()    { user_deny    = Some(matched); } }
            (Action::Allow, PermissionGroup::Users { .. })   => { if user_allow.is_none()   { user_allow   = Some(matched); } }
            (Action::Deny,  PermissionGroup::Space)          => { if space_deny.is_none()   { space_deny   = Some(matched); } }
            (Action::Allow, PermissionGroup::Space)          => { if space_allow.is_none()  { space_allow  = Some(matched); } }
        }
    }

    // Apply priority order (highest first).
    if let Some(m) = device_deny  { return Decision::deny(m, DecisionReason::DeviceDenyPriority); }
    if let Some(m) = device_allow { return Decision::allow(m, DecisionReason::DeviceAllowPriority); }
    if let Some(m) = user_deny    { return Decision::deny(m, DecisionReason::UserDenyPriority); }
    if let Some(m) = user_allow   { return Decision::allow(m, DecisionReason::UserAllowPriority); }
    if let Some(m) = space_deny   { return Decision::deny(m, DecisionReason::SpaceDenyPriority); }
    if let Some(m) = space_allow  { return Decision::allow(m, DecisionReason::SpaceAllowPriority); }

    // No rule matched → default deny.
    Decision::default_deny()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rules::Scope;

    // ── Test helpers ────────────────────────────────────────────────────────

    const NOW: i64 = 1_700_000_000; // fixed "now" for deterministic tests
    const LOCAL_USER: &str = "usr-local";
    const DEVICE_A: &str = "device-aabbccdd";
    const DEVICE_B: &str = "device-11223344";
    const USER_X: &str = "usr-xxyyzz";
    const USER_Y: &str = "usr-1122aabb";

    /// Build an inbound TCP context from `DEVICE_A`.
    fn ctx_inbound_tcp(port: u16) -> MatchContext<'static> {
        MatchContext::new(DEVICE_A, Protocol::Tcp, port, Direction::Inbound, false, NOW, LOCAL_USER)
    }

    /// Build an inbound UDP context from `DEVICE_A`.
    fn ctx_inbound_udp(port: u16) -> MatchContext<'static> {
        MatchContext::new(DEVICE_A, Protocol::Udp, port, Direction::Inbound, false, NOW, LOCAL_USER)
    }

    /// Build an outbound TCP context from `DEVICE_A`.
    fn ctx_outbound_tcp(port: u16) -> MatchContext<'static> {
        MatchContext::new(DEVICE_A, Protocol::Tcp, port, Direction::Outbound, false, NOW, LOCAL_USER)
    }

    /// Build an inbound TCP context with `in_room_with_src = true`.
    fn ctx_inbound_tcp_in_room(port: u16) -> MatchContext<'static> {
        MatchContext::new(DEVICE_A, Protocol::Tcp, port, Direction::Inbound, true, NOW, LOCAL_USER)
    }

    /// A no-op user-device resolver (returns empty).
    fn no_user_devices(_: &str) -> Vec<String> { vec![] }

    /// A resolver that maps USER_X → [DEVICE_A], USER_Y → [DEVICE_B].
    fn test_user_devices(uid: &str) -> Vec<String> {
        match uid {
            USER_X => vec![DEVICE_A.into()],
            USER_Y => vec![DEVICE_B.into()],
            _ => vec![],
        }
    }

    /// A mnemonic resolver that maps "my-pc" → DEVICE_A.
    fn test_mnemonic_resolver(mnemonic: &str) -> Option<String> {
        match mnemonic {
            "my-pc" => Some(DEVICE_A.into()),
            "your-pc" => Some(DEVICE_B.into()),
            _ => None,
        }
    }

    /// Shorthand: device-level ALLOW rule for TCP `port`.
    fn device_allow(id: &str, device_id: &str, port: u16) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            permission_group: PermissionGroup::Devices { ids: vec![device_id.into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, port)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }
    }

    /// Shorthand: device-level DENY rule for TCP `port`.
    fn device_deny(id: &str, device_id: &str, port: u16) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            permission_group: PermissionGroup::Devices { ids: vec![device_id.into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, port)],
            action: Action::Deny,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }
    }

    /// Shorthand: user-level ALLOW rule for TCP `port`.
    fn user_allow(id: &str, user_id: &str, port: u16) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            permission_group: PermissionGroup::Users { ids: vec![user_id.into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, port)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }
    }

    /// Shorthand: user-level DENY rule for TCP `port`.
    fn user_deny(id: &str, user_id: &str, port: u16) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            permission_group: PermissionGroup::Users { ids: vec![user_id.into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, port)],
            action: Action::Deny,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }
    }

    /// Shorthand: space-level ALLOW rule for TCP `port`.
    fn space_allow(id: &str, port: u16) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            permission_group: PermissionGroup::Space,
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, port)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }
    }

    /// Shorthand: space-level DENY rule for TCP `port`.
    fn space_deny(id: &str, port: u16) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            permission_group: PermissionGroup::Space,
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, port)],
            action: Action::Deny,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }
    }

    // =======================================================================
    // 1. Default deny — no rules
    // =======================================================================

    #[test]
    fn no_rules_default_deny() {
        let d = evaluate(&ctx_inbound_tcp(25565), &[], no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
        assert!(d.matched_rule.is_none());
        assert!(!d.is_allow());
    }

    // =======================================================================
    // 2. Single-rule basic matches
    // =======================================================================

    #[test]
    fn single_device_allow_matches() {
        let rules = [device_allow("r1", DEVICE_A, 25565)];
        let d = evaluate(&ctx_inbound_tcp(25565), &rules, no_user_devices);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::DeviceAllowPriority);
        let m = d.matched_rule.as_ref().unwrap();
        assert_eq!(m.rule_id, "r1");
        assert_eq!(m.scope, Scope::Device);
    }

    #[test]
    fn single_device_deny_matches() {
        let rules = [device_deny("r1", DEVICE_A, 80)];
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DeviceDenyPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "r1");
    }

    #[test]
    fn single_user_allow_matches() {
        let rules = [user_allow("r1", USER_X, 443)];
        let d = evaluate(&ctx_inbound_tcp(443), &rules, test_user_devices);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::UserAllowPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().scope, Scope::User);
    }

    #[test]
    fn single_user_deny_matches() {
        let rules = [user_deny("r1", USER_X, 443)];
        let d = evaluate(&ctx_inbound_tcp(443), &rules, test_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::UserDenyPriority);
    }

    #[test]
    fn single_space_allow_matches_when_in_room() {
        let rules = [space_allow("r1", 25565)];
        let d = evaluate(&ctx_inbound_tcp_in_room(25565), &rules, no_user_devices);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::SpaceAllowPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().scope, Scope::Space);
    }

    #[test]
    fn single_space_deny_matches_when_in_room() {
        let rules = [space_deny("r1", 25565)];
        let d = evaluate(&ctx_inbound_tcp_in_room(25565), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::SpaceDenyPriority);
    }

    #[test]
    fn space_rule_no_match_when_not_in_room() {
        let rules = [space_allow("r1", 25565)];
        // ctx_inbound_tcp has in_room_with_src = false
        let d = evaluate(&ctx_inbound_tcp(25565), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    // =======================================================================
    // 3. Priority ordering
    // =======================================================================

    #[test]
    fn device_deny_beats_device_allow() {
        let rules = [
            device_allow("allow", DEVICE_A, 80),
            device_deny("deny", DEVICE_A, 80),
        ];
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DeviceDenyPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "deny");
    }

    #[test]
    fn device_allow_beats_user_deny() {
        let rules = [
            user_deny("user-deny", USER_X, 80),
            device_allow("dev-allow", DEVICE_A, 80),
        ];
        let d = evaluate(&ctx_inbound_tcp(80), &rules, test_user_devices);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::DeviceAllowPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "dev-allow");
    }

    #[test]
    fn user_deny_beats_user_allow() {
        let rules = [
            user_allow("user-allow", USER_X, 80),
            user_deny("user-deny", USER_X, 80),
        ];
        let d = evaluate(&ctx_inbound_tcp(80), &rules, test_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::UserDenyPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "user-deny");
    }

    #[test]
    fn user_allow_beats_space_deny() {
        let rules = [
            space_deny("space-deny", 80),
            user_allow("user-allow", USER_X, 80),
        ];
        let d = evaluate(
            &ctx_inbound_tcp_in_room(80),
            &rules,
            test_user_devices,
        );
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::UserAllowPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "user-allow");
    }

    #[test]
    fn space_deny_beats_space_allow() {
        let rules = [
            space_allow("space-allow", 80),
            space_deny("space-deny", 80),
        ];
        let d = evaluate(&ctx_inbound_tcp_in_room(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::SpaceDenyPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "space-deny");
    }

    /// Full chain: device_deny > device_allow > user_deny > user_allow >
    /// space_deny > space_allow.  Only the highest-priority match wins.
    #[test]
    fn full_priority_chain() {
        let rules = [
            space_allow("sa", 80),
            space_deny("sd", 80),
            user_allow("ua", USER_X, 80),
            user_deny("ud", USER_X, 80),
            device_allow("da", DEVICE_A, 80),
            device_deny("dd", DEVICE_A, 80),
        ];
        let d = evaluate(&ctx_inbound_tcp_in_room(80), &rules, test_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DeviceDenyPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "dd");
    }

    // =======================================================================
    // 4. Wildcard matching
    // =======================================================================

    #[test]
    fn wildcard_device_matches_any() {
        let rules = [FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices { ids: vec!["*".into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 80)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }];
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn wildcard_user_matches_any() {
        let rules = [FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Users { ids: vec!["*".into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 80)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }];
        // Even with an empty resolver, "*" matches.
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Allow);
    }

    // =======================================================================
    // 5. Mnemonic resolution
    // =======================================================================

    #[test]
    fn device_mnemonic_resolves_and_matches() {
        let rules = [FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices {
                ids: vec!["my-pc".into()],
            },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 22)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: Some("SSH from my laptop".into()),
        }];
        let resolver = test_mnemonic_resolver;
        let ctx = MatchContext::new(
            DEVICE_A, Protocol::Tcp, 22, Direction::Inbound, false, NOW, LOCAL_USER,
        )
        .with_mnemonic_resolver(&resolver);
        let d = evaluate(&ctx, &rules, no_user_devices);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(
            d.matched_rule.as_ref().unwrap().comment.as_deref(),
            Some("SSH from my laptop")
        );
    }

    #[test]
    fn device_mnemonic_no_match_returns_none() {
        let rules = [FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices {
                ids: vec!["unknown-mnemonic".into()],
            },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 22)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }];
        let resolver = test_mnemonic_resolver;
        let ctx = MatchContext::new(
            DEVICE_A, Protocol::Tcp, 22, Direction::Inbound, false, NOW, LOCAL_USER,
        )
        .with_mnemonic_resolver(&resolver);
        let d = evaluate(&ctx, &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn user_device_resolution() {
        // USER_X maps to DEVICE_A via the resolver.
        let rules = [user_allow("r1", USER_X, 443)];
        let d = evaluate(&ctx_inbound_tcp(443), &rules, test_user_devices);
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn user_device_resolution_wrong_user() {
        // USER_Y maps to DEVICE_B, but our context uses DEVICE_A.
        let rules = [user_allow("r1", USER_Y, 443)];
        let d = evaluate(&ctx_inbound_tcp(443), &rules, test_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    // =======================================================================
    // 6. Direction filtering
    // =======================================================================

    #[test]
    fn inbound_rule_does_not_match_outbound() {
        let rules = [device_allow("r1", DEVICE_A, 80)];
        let d = evaluate(&ctx_outbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn outbound_rule_matches_outbound() {
        let rules = [FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices { ids: vec![DEVICE_A.into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 80)],
            action: Action::Allow,
            direction: Direction::Outbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }];
        let d = evaluate(&ctx_outbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Allow);
    }

    // =======================================================================
    // 7. Rule lifecycle: disabled, expired, not-yet-expired
    // =======================================================================

    #[test]
    fn disabled_rule_is_skipped() {
        let rules = [FirewallRule {
            id: "r1".into(),
            ..device_allow("r1", DEVICE_A, 80)
        }];
        let mut r = rules[0].clone();
        r.enabled = false;
        let d = evaluate(&ctx_inbound_tcp(80), &[r], no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn expired_rule_is_skipped() {
        let mut r = device_allow("r1", DEVICE_A, 80);
        r.expires_at = Some(NOW - 1); // expired 1 second ago
        let d = evaluate(&ctx_inbound_tcp(80), &[r], no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn not_yet_expired_rule_matches() {
        let mut r = device_allow("r1", DEVICE_A, 80);
        r.expires_at = Some(NOW + 3600); // expires in 1 hour
        let d = evaluate(&ctx_inbound_tcp(80), &[r], no_user_devices);
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn no_expiry_means_never_expires() {
        let r = device_allow("r1", DEVICE_A, 80);
        assert!(r.is_active(NOW));
        assert!(r.is_active(i64::MAX));
    }

    // =======================================================================
    // 8. Protocol and port matching
    // =======================================================================

    #[test]
    fn tcp_rule_no_match_udp() {
        let rules = [device_allow("r1", DEVICE_A, 80)];
        let d = evaluate(&ctx_inbound_udp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn udp_rule_matches_udp() {
        let rules = [FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices { ids: vec![DEVICE_A.into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Udp, 53)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }];
        let d = evaluate(&ctx_inbound_udp(53), &rules, no_user_devices);
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn port_mismatch_no_match() {
        let rules = [device_allow("r1", DEVICE_A, 80)];
        let d = evaluate(&ctx_inbound_tcp(443), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn port_range_matches() {
        let r = FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices { ids: vec![DEVICE_A.into()] },
            protocol_ports: vec![ProtocolPort::range(Protocol::Tcp, 8000, 9000)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        };
        // 8080 is within range
        let d = evaluate(&ctx_inbound_tcp(8080), &[r.clone()], no_user_devices);
        assert_eq!(d.action, Action::Allow);
        // 7999 is below range
        let d = evaluate(&ctx_inbound_tcp(7999), &[r.clone()], no_user_devices);
        assert_eq!(d.action, Action::Deny);
        // 9001 is above range
        let d = evaluate(&ctx_inbound_tcp(9001), &[r], no_user_devices);
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn wildcard_port_matches_any() {
        let r = FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices { ids: vec![DEVICE_A.into()] },
            protocol_ports: vec![ProtocolPort::wildcard(Protocol::Tcp)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        };
        let d = evaluate(&ctx_inbound_tcp(1), &[r.clone()], no_user_devices);
        assert_eq!(d.action, Action::Allow);
        let d = evaluate(&ctx_inbound_tcp(65535), &[r.clone()], no_user_devices);
        assert_eq!(d.action, Action::Allow);
        let d = evaluate(&ctx_inbound_tcp(80), &[r], no_user_devices);
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn multiple_protocol_ports_in_one_rule() {
        // A rule that allows TCP:80 and UDP:53 from DEVICE_A.
        let r = FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices { ids: vec![DEVICE_A.into()] },
            protocol_ports: vec![
                ProtocolPort::single(Protocol::Tcp, 80),
                ProtocolPort::single(Protocol::Udp, 53),
            ],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        };
        let d = evaluate(&ctx_inbound_tcp(80), &[r.clone()], no_user_devices);
        assert_eq!(d.action, Action::Allow);
        let d = evaluate(&ctx_inbound_udp(53), &[r.clone()], no_user_devices);
        assert_eq!(d.action, Action::Allow);
        // TCP:53 should NOT match (only UDP:53 is in the rule).
        let d = evaluate(&ctx_inbound_tcp(53), &[r.clone()], no_user_devices);
        assert_eq!(d.action, Action::Deny);
    }

    // =======================================================================
    // 9. First match wins within a priority slot
    // =======================================================================

    #[test]
    fn first_device_allow_wins() {
        let rules = [
            device_allow("first", DEVICE_A, 80),
            FirewallRule {
                id: "second".into(),
                comment: Some("should not win".into()),
                ..device_allow("second", DEVICE_A, 80)
            },
        ];
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "first");
    }

    // =======================================================================
    // 10. Decision explainability — Display and serialization
    // =======================================================================

    #[test]
    fn decision_reason_display_is_readable() {
        let cases = [
            (DecisionReason::DeviceDenyPriority, "device-level deny rule matched (highest priority)"),
            (DecisionReason::DeviceAllowPriority, "device-level allow rule matched"),
            (DecisionReason::UserDenyPriority, "user-level deny rule matched"),
            (DecisionReason::UserAllowPriority, "user-level allow rule matched"),
            (DecisionReason::SpaceDenyPriority, "space-level deny rule matched"),
            (DecisionReason::SpaceAllowPriority, "space-level allow rule matched"),
            (DecisionReason::DefaultDeny, "no rule matched — default deny"),
        ];
        for (reason, expected) in cases {
            assert_eq!(reason.to_string(), expected);
        }
    }

    #[test]
    fn decision_round_trip_json() {
        let rules = [device_allow("r1", DEVICE_A, 80)];
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        let json = serde_json::to_string(&d).expect("serialize");
        let back: Decision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.action, d.action);
        assert_eq!(back.reason, d.reason);
        assert_eq!(
            back.matched_rule.as_ref().unwrap().rule_id,
            d.matched_rule.as_ref().unwrap().rule_id
        );
    }

    #[test]
    fn default_deny_json_has_no_matched_rule() {
        let d = evaluate(&ctx_inbound_tcp(80), &[], no_user_devices);
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["action"], "deny");
        assert_eq!(json["reason"], "default_deny");
        assert!(json["matched_rule"].is_null());
    }

    #[test]
    fn matched_rule_preserves_comment() {
        let r = FirewallRule {
            comment: Some("Minecraft server".into()),
            ..device_allow("r1", DEVICE_A, 25565)
        };
        let d = evaluate(&ctx_inbound_tcp(25565), &[r], no_user_devices);
        assert_eq!(
            d.matched_rule.as_ref().unwrap().comment.as_deref(),
            Some("Minecraft server")
        );
    }

    // =======================================================================
    // 11. Edge cases
    // =======================================================================

    #[test]
    fn device_not_in_rules_list_no_match() {
        let rules = [device_allow("r1", DEVICE_B, 80)]; // DEVICE_B, not DEVICE_A
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn empty_device_ids_list_never_matches() {
        let rules = [FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices { ids: vec![] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 80)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }];
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn device_deny_with_multiple_ids() {
        // A deny rule targeting both DEVICE_A and DEVICE_B.
        let r = FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Devices {
                ids: vec![DEVICE_B.into(), DEVICE_A.into()],
            },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 80)],
            action: Action::Deny,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        };
        let d = evaluate(&ctx_inbound_tcp(80), &[r], no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DeviceDenyPriority);
    }

    #[test]
    fn user_deny_with_multiple_user_ids() {
        // A deny rule targeting USER_Y (who owns DEVICE_B, not DEVICE_A).
        // Should not match DEVICE_A.
        let r = user_deny("r1", USER_Y, 80);
        let d = evaluate(&ctx_inbound_tcp(80), &[r], test_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn user_deny_matches_correct_user() {
        // USER_X owns DEVICE_A.
        let r = user_deny("r1", USER_X, 80);
        let d = evaluate(&ctx_inbound_tcp(80), &[r], test_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::UserDenyPriority);
    }

    /// Real-world scenario: device allow + user-level deny.
    /// Device-level ALLOW (for a specific friend) beats user-level DENY (for
    /// everyone else's users) because device scope is higher priority.
    #[test]
    fn minecraft_friends_scenario() {
        let rules = [
            // Allow trusted friend (DEVICE_B) to access Minecraft (device-level).
            device_allow("minecraft-friend", DEVICE_B, 25565),
            // Deny all unknown users on port 25565 (user-level, lower priority).
            FirewallRule {
                id: "minecraft-deny-others".into(),
                permission_group: PermissionGroup::Users { ids: vec!["*".into()] },
                protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 25565)],
                action: Action::Deny,
                direction: Direction::Inbound,
                expires_at: None,
                enabled: true,
                comment: Some("Block unknown Minecraft access".into()),
            },
        ];

        // DEVICE_B (friend) → device-allow matches (device > user priority)
        let ctx_friend = MatchContext::new(
            DEVICE_B, Protocol::Tcp, 25565, Direction::Inbound, false, NOW, LOCAL_USER,
        );
        let d = evaluate(&ctx_friend, &rules, no_user_devices);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "minecraft-friend");

        // DEVICE_A (not friend, not in any user-list) → user-wildcard deny
        let d = evaluate(&ctx_inbound_tcp(25565), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.matched_rule.as_ref().unwrap().rule_id, "minecraft-deny-others");

        // DEVICE_A on different port → default deny (no rule covers port 80)
        let d = evaluate(&ctx_inbound_tcp(80), &rules, no_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    /// Real-world scenario: user-level allow beats space-level deny.
    #[test]
    fn admin_user_overrides_space_block() {
        let rules = [
            // Space-level deny all on port 22.
            space_deny("block-ssh-space", 22),
            // But USER_X (admin) is allowed SSH.
            user_allow("admin-ssh", USER_X, 22),
        ];

        // DEVICE_A belongs to USER_X → user-allow wins over space-deny.
        let d = evaluate(
            &ctx_inbound_tcp_in_room(22),
            &rules,
            test_user_devices,
        );
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::UserAllowPriority);

        // DEVICE_B belongs to USER_Y (not admin) → space-deny applies.
        let ctx_b = MatchContext::new(
            DEVICE_B, Protocol::Tcp, 22, Direction::Inbound, true, NOW, LOCAL_USER,
        );
        let d = evaluate(&ctx_b, &rules, test_user_devices);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::SpaceDenyPriority);
    }

    // =======================================================================
    // 12. ProtocolPort unit tests
    // =======================================================================

    #[test]
    fn protocol_port_single_matches_exact() {
        let pp = ProtocolPort::single(Protocol::Tcp, 443);
        assert!(pp.matches(Protocol::Tcp, 443));
        assert!(!pp.matches(Protocol::Tcp, 80));
        assert!(!pp.matches(Protocol::Udp, 443));
    }

    #[test]
    fn protocol_port_range_boundaries() {
        let pp = ProtocolPort::range(Protocol::Udp, 5000, 5010);
        assert!(pp.matches(Protocol::Udp, 5000));
        assert!(pp.matches(Protocol::Udp, 5005));
        assert!(pp.matches(Protocol::Udp, 5010));
        assert!(!pp.matches(Protocol::Udp, 4999));
        assert!(!pp.matches(Protocol::Udp, 5011));
    }

    #[test]
    fn protocol_port_wildcard() {
        let pp = ProtocolPort::wildcard(Protocol::Tcp);
        assert!(pp.matches(Protocol::Tcp, 1));
        assert!(pp.matches(Protocol::Tcp, 80));
        assert!(pp.matches(Protocol::Tcp, 65535));
        assert!(!pp.matches(Protocol::Udp, 80));
    }
}