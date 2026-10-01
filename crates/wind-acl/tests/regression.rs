//! Zero-regression and optimizer tests for `wind-acl`.
//!
//! The core guarantee (<https://rust-proxy.github.io/wind/acl-ir/> §5) is that the degenerate embedding
//! routes identically to the legacy first-match-wins engine, and that the
//! optimizer (§7) preserves that. We assert it differentially: for a large grid
//! of `MatchContext`s, the legacy reference, the embedded ruleset, and the
//! optimized ruleset all agree.

use std::net::IpAddr;

use wind_acl::{MapField, Match, Ruleset, Side, Verdict, compile};
use wind_core::RouteAction;
use wind_rule::{MatchContext, NetworkType, Rule};

/// A representative config exercising typed leaves (domain/ip/port/proto),
/// Predicate fallbacks (geoip/process/wildcard/compound), Pass 1 same-verdict
/// runs, and a Pass 2 differing-verdict port run.
const CONFIG: &str = "
DOMAIN,exact.example.com,proxy
DOMAIN-SUFFIX,google.com,proxy
DOMAIN-SUFFIX,github.com,proxy
DOMAIN-KEYWORD,ads,reject
DOMAIN-WILDCARD,*.track.net,reject
IP-CIDR,10.0.0.0/8,direct
IP-CIDR,192.168.0.0/16,direct
IP-CIDR6,fc00::/7,direct
SRC-IP-CIDR,192.168.1.0/24,proxy
GEOIP,CN,direct
PROCESS-NAME,curl,direct
DST-PORT,80,proxy
DST-PORT,443,direct
DST-PORT,22,reject
NETWORK,udp,reject
AND,((NETWORK,tcp),(DST-PORT,8080)),proxy
MATCH,direct
";

const DEFAULT_OUTBOUND: &str = "direct";

/// Normalized routing decision — reject reason text is not a routing semantic.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
	Forward(String),
	Reject,
}

fn norm_action(a: &RouteAction) -> Decision {
	match a {
		RouteAction::Forward(o) => Decision::Forward(o.clone()),
		RouteAction::Reject(_) => Decision::Reject,
	}
}

fn norm_target(target: &str) -> Decision {
	match target.to_ascii_lowercase().as_str() {
		"reject" | "block" | "deny" => Decision::Reject,
		_ => Decision::Forward(target.to_string()),
	}
}

/// Legacy first-match-wins reference (mirrors `wind_acl::engine::do_route`
/// without guards).
fn reference(rules: &[Rule], ctx: &MatchContext) -> Decision {
	for r in rules {
		if r.matches(ctx) {
			return norm_target(&r.target);
		}
	}
	Decision::Forward(DEFAULT_OUTBOUND.to_string())
}

fn parse(config: &str) -> Vec<Rule> {
	Rule::parse_rules(config).into_iter().filter_map(Result::ok).collect()
}

#[test]
fn embedding_and_optimization_match_legacy_engine() {
	let reference_rules = parse(CONFIG);
	let embedded = Ruleset::from_rules(parse(CONFIG), DEFAULT_OUTBOUND);
	let optimized = compile(Ruleset::from_rules(parse(CONFIG), DEFAULT_OUTBOUND));

	let domains = [
		Some("exact.example.com"),
		Some("www.google.com"),
		Some("google.com"),
		Some("x.github.com"),
		Some("myads.example.com"),
		Some("foo.track.net"),
		Some("baidu.com"),
		None,
	];
	let dst_ips = [Some("1.1.1.1"), Some("10.1.2.3"), Some("192.168.5.5"), Some("fd00::1"), None];
	let dst_ports = [Some(80u16), Some(443), Some(22), Some(8080), None];
	let networks = [Some(NetworkType::Tcp), Some(NetworkType::Udp)];
	let src_ips = [Some("192.168.1.50"), None];
	let processes = [Some("curl"), None];

	let mut cases = 0u64;
	for domain in domains {
		for dst_ip in dst_ips {
			for dst_port in dst_ports {
				for network in networks {
					for src_ip in src_ips {
						for process in processes {
							let ctx = MatchContext {
								domain,
								dst_ip: dst_ip.map(|s| s.parse::<IpAddr>().unwrap()),
								dst_port,
								network,
								src_ip: src_ip.map(|s| s.parse::<IpAddr>().unwrap()),
								process_name: process,
								..Default::default()
							};

							let want = reference(&reference_rules, &ctx);
							let got_embed = norm_action(&embedded.route(&ctx));
							let got_opt = norm_action(&optimized.route(&ctx));

							assert_eq!(want, got_embed, "embedded mismatch for ctx={ctx:?}");
							assert_eq!(want, got_opt, "optimized mismatch for ctx={ctx:?}");
							cases += 1;
						}
					}
				}
			}
		}
	}
	assert!(cases > 1000, "expected a large grid, ran {cases}");
}

#[test]
fn optimizer_builds_sets_and_a_port_map() {
	let optimized = compile(Ruleset::from_rules(parse(CONFIG), DEFAULT_OUTBOUND));

	// Pass 1 produced at least the three same-verdict buckets:
	// {domains proxy}, {domains reject}, {dst ips direct}.
	assert!(
		optimized.sets.len() >= 3,
		"expected >=3 named sets, got {}",
		optimized.sets.len()
	);

	// Pass 2 produced exactly one port verdict map (ports 80/443/22, all
	// different verdicts, disjoint keys).
	assert_eq!(optimized.maps.len(), 1, "expected one port verdict map");
	let map = &optimized.maps[0];
	assert_eq!(map.field, MapField::Port);
	assert_eq!(map.side, Side::Dst);
	assert_eq!(map.entries.len(), 3);

	// The optimized chain is strictly shorter than the embedded one.
	let embedded = Ruleset::from_rules(parse(CONFIG), DEFAULT_OUTBOUND);
	assert!(optimized.chains[0].rules.len() < embedded.chains[0].rules.len());
}

#[test]
fn overlapping_port_run_is_not_compiled_to_a_map() {
	// Overlapping ranges with differing verdicts: first-match-wins must be
	// preserved, so Pass 2 MUST bail and keep the rules ordered.
	let config = "
DST-PORT,1000-2000,proxy
DST-PORT,1500,direct
MATCH,reject
";
	let optimized = compile(Ruleset::from_rules(parse(config), DEFAULT_OUTBOUND));
	assert!(optimized.maps.is_empty(), "overlapping ports must not become a vmap");

	// 1500 hits the first rule (proxy) under first-match-wins, not direct.
	let ctx = MatchContext {
		dst_port: Some(1500),
		..Default::default()
	};
	assert_eq!(norm_action(&optimized.route(&ctx)), Decision::Forward("proxy".into()));
}

#[test]
fn chain_jump_returns_to_caller() {
	// main: if tcp jump sub; else Always -> fallback
	// sub:  if dport 443 -> https; (else exhausted -> fallthrough -> back to
	// main)
	let rs = Ruleset {
		sets: vec![],
		maps: vec![],
		entry: 0,
		chains: vec![
			wind_acl::Chain {
				name: "main".into(),
				policy: Verdict::Forward("policy".into()),
				rules: vec![
					rule(Match::Proto(NetworkType::Tcp), Verdict::Jump("sub".into())),
					rule(Match::Always, Verdict::Forward("fallback".into())),
				],
			},
			wind_acl::Chain {
				name: "sub".into(),
				policy: Verdict::Forward("unused".into()),
				rules: vec![rule(
					Match::Port {
						side: Side::Dst,
						range: 443..=443,
					},
					Verdict::Forward("https".into()),
				)],
			},
		],
	};

	// tcp + 443 -> jump sub -> https
	assert_eq!(route_for(&rs, NetworkType::Tcp, 443), Decision::Forward("https".into()));
	// tcp + 80 -> jump sub -> no match -> return to main -> fallback
	assert_eq!(route_for(&rs, NetworkType::Tcp, 80), Decision::Forward("fallback".into()));
	// udp + 443 -> first rule misses -> fallback
	assert_eq!(route_for(&rs, NetworkType::Udp, 443), Decision::Forward("fallback".into()));
}

#[test]
fn chain_control_verdicts_are_distinguishable() {
	// One ruleset exercising all three control-flow verdicts (spec §5):
	//  - `Return` pops out of the chain it was evaluated in, so in the entry
	//    chain it reaches the entry policy instead of resuming the scan.
	//  - `Goto` is a tail call whose target's non-terminal result is a
	//    fallthrough at the call site, so the caller keeps scanning.
	//  - `Jump` returns to the caller at the rule after the jump.
	let rs = Ruleset {
		sets: vec![],
		maps: vec![],
		entry: 0,
		chains: vec![
			wind_acl::Chain {
				name: "main".into(),
				policy: Verdict::Forward("main-policy".into()),
				rules: vec![
					port_rule(80, Verdict::Return),
					// Reached only if rule 1 resumes the scan, so it must not run.
					port_rule(80, Verdict::Forward("after-return".into())),
					port_rule(81, Verdict::Goto("leaf".into())),
					port_rule(81, Verdict::Forward("after-goto".into())),
					port_rule(82, Verdict::Jump("leaf".into())),
					port_rule(82, Verdict::Forward("after-jump".into())),
					port_rule(83, Verdict::Forward("direct".into())),
				],
			},
			wind_acl::Chain {
				name: "leaf".into(),
				policy: Verdict::Forward("leaf-policy".into()),
				// No rule matches the ports above, so the leaf falls through.
				rules: vec![port_rule(999, Verdict::Forward("leaf-hit".into()))],
			},
		],
	};

	// Return -> entry policy, without running the later rule for the same key.
	assert_eq!(decision_norm(&rs, 80), "forward:main-policy");
	// Goto -> target falls through -> caller continues -> after-goto.
	assert_eq!(decision_norm(&rs, 81), "forward:after-goto");
	// Jump -> target falls through -> caller continues -> after-jump.
	assert_eq!(decision_norm(&rs, 82), "forward:after-jump");
	// A plain terminal verdict is unaffected.
	assert_eq!(decision_norm(&rs, 83), "forward:direct");
	// A port that matches nothing is a plain fallthrough to the policy.
	assert_eq!(decision_norm(&rs, 999), "forward:main-policy");
}

#[test]
fn chain_return_in_a_callee_runs_the_caller_rule_after_the_jump() {
	// main: Jump sub, then after-jump; sub: Return, then sub-later-rule.
	// The callee's remaining rules must not run and its policy must not apply.
	let rs = Ruleset {
		sets: vec![],
		maps: vec![],
		entry: 0,
		chains: vec![
			wind_acl::Chain {
				name: "main".into(),
				policy: Verdict::Forward("main-policy".into()),
				rules: vec![
					port_rule(80, Verdict::Jump("sub".into())),
					port_rule(80, Verdict::Forward("after-jump".into())),
				],
			},
			wind_acl::Chain {
				name: "sub".into(),
				policy: Verdict::Forward("sub-policy".into()),
				rules: vec![
					port_rule(80, Verdict::Return),
					port_rule(80, Verdict::Forward("sub-later-rule".into())),
				],
			},
		],
	};

	assert_eq!(decision_norm(&rs, 80), "forward:after-jump");
}

#[test]
fn chain_return_from_a_verdict_map_default_pops_the_chain() {
	// A `Return` reached through a map default must pop the rule's chain as
	// well, not resume scanning it.
	let rs = Ruleset {
		sets: vec![],
		maps: vec![wind_acl::VerdictMap {
			side: Side::Dst,
			field: MapField::Port,
			entries: vec![],
			default: Some(Verdict::Return),
		}],
		entry: 0,
		chains: vec![wind_acl::Chain {
			name: "main".into(),
			policy: Verdict::Forward("policy".into()),
			rules: vec![
				rule(Match::Always, Verdict::Map(0)),
				rule(Match::Always, Verdict::Forward("later-rule".into())),
			],
		}],
	};

	assert_eq!(decision_norm(&rs, 80), "forward:policy");
}

#[test]
fn exhausted_entry_chain_applies_the_entry_policy() {
	let rs = Ruleset {
		sets: vec![],
		maps: vec![],
		entry: 0,
		chains: vec![wind_acl::Chain {
			name: "main".into(),
			policy: Verdict::Reject("no match".into()),
			rules: vec![port_rule(443, Verdict::Forward("https".into()))],
		}],
	};

	assert_eq!(decision_norm(&rs, 443), "forward:https");
	assert_eq!(decision_norm(&rs, 80), "reject");
}

#[test]
fn max_chain_depth_bounds_a_goto_cycle() {
	// `MAX_CHAIN_DEPTH` must still cut a `Goto` cycle instead of recursing
	// without bound; the cut is reported as fallthrough, which the entry chain
	// turns into its policy.
	let rs = Ruleset {
		sets: vec![],
		maps: vec![],
		entry: 0,
		chains: vec![
			wind_acl::Chain {
				name: "a".into(),
				policy: Verdict::Forward("a-policy".into()),
				rules: vec![rule(Match::Always, Verdict::Goto("b".into()))],
			},
			wind_acl::Chain {
				name: "b".into(),
				policy: Verdict::Forward("b-policy".into()),
				rules: vec![rule(Match::Always, Verdict::Goto("a".into()))],
			},
		],
	};

	assert_eq!(decision_norm(&rs, 80), "forward:a-policy");
}

#[test]
fn verdict_map_dispatch() {
	let rs = Ruleset {
		sets: vec![],
		maps: vec![wind_acl::VerdictMap {
			side: Side::Dst,
			field: MapField::Port,
			entries: vec![
				(80..=80, Verdict::Forward("a".into())),
				(443..=443, Verdict::Forward("b".into())),
			],
			default: None,
		}],
		entry: 0,
		chains: vec![wind_acl::Chain {
			name: "main".into(),
			policy: Verdict::Forward("policy".into()),
			rules: vec![
				rule(Match::Always, Verdict::Map(0)),
				rule(Match::Always, Verdict::Forward("after-map".into())),
			],
		}],
	};

	// 80 -> a, 443 -> b (map hit)
	assert_eq!(route_port(&rs, 80), Decision::Forward("a".into()));
	assert_eq!(route_port(&rs, 443), Decision::Forward("b".into()));
	// 22 -> map miss (no default) -> fall through to next rule
	assert_eq!(route_port(&rs, 22), Decision::Forward("after-map".into()));
}

// -- small helpers for the hand-built chain tests --

fn rule(matches: Match, verdict: Verdict) -> wind_acl::IrRule {
	wind_acl::IrRule {
		matches,
		stmts: vec![],
		verdict,
	}
}

/// A destination-port rule; a single port is `p..=p`.
fn port_rule(port: u16, verdict: Verdict) -> wind_acl::IrRule {
	rule(
		Match::Port {
			side: Side::Dst,
			range: port..=port,
		},
		verdict,
	)
}

/// Route by destination port and render the decision as a string, so a failing
/// chain-control assertion shows which verdict was applied.
fn decision_norm(rs: &Ruleset, port: u16) -> String {
	let ctx = MatchContext {
		dst_port: Some(port),
		..Default::default()
	};
	match rs.route(&ctx) {
		RouteAction::Forward(o) => format!("forward:{o}"),
		RouteAction::Reject(_) => "reject".to_string(),
	}
}

fn route_for(rs: &Ruleset, net: NetworkType, port: u16) -> Decision {
	let ctx = MatchContext {
		network: Some(net),
		dst_port: Some(port),
		..Default::default()
	};
	norm_action(&rs.route(&ctx))
}

fn route_port(rs: &Ruleset, port: u16) -> Decision {
	let ctx = MatchContext {
		dst_port: Some(port),
		..Default::default()
	};
	norm_action(&rs.route(&ctx))
}
