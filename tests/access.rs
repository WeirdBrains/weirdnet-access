use weirdnet_access::catalog::core;
use weirdnet_access::enforce::{Step, decide_with_step};
use weirdnet_access::*;

fn catalog() -> Catalog {
    let mut c = Catalog::core();
    c.add("files.write", "upload and change files", false).unwrap();
    c.add("files.read", "download files", false).unwrap();
    c.add("files.delete", "delete files", true).unwrap();
    c.imply("files.write", &["files.read"]).unwrap();
    c.imply("files.delete", &["files.write"]).unwrap();
    c.imply(core::MEMBERS_KICK, &[core::MEMBERS_LIST]).unwrap();
    c
}

fn s(v: Visibility, a: Access) -> Settings {
    Settings { visibility: v, access: a }
}

fn stranger() -> Facts {
    Facts { user: Some("stranger".into()), ..Default::default() }
}
fn trusted() -> Facts {
    Facts { user: Some("friend".into()), trusted: true, ..Default::default() }
}
fn member(role: &str) -> Facts {
    Facts { user: Some("mem".into()), membership_role: Some(role.into()), ..Default::default() }
}
fn revoked_member() -> Facts {
    Facts { node_revoked: true, ..member("user") }
}
fn owner() -> Facts {
    Facts { user: Some("me".into()), is_owner: true, ..Default::default() }
}

#[test]
fn enforcement_order() {
    let c = catalog();
    let r = presets::ranked(&c, &["files.write"], &["files.read"]).unwrap();
    use Access::*;
    use Visibility::*;
    let d = |st, f: &Facts, p| decide_with_step(&c, &r, st, f, p);

    // Stranger.
    assert_eq!(d(s(Private, Open), &stranger(), "read"), (Decision::NotFound, Step::Visibility));
    assert_eq!(d(s(Private, Gated), &stranger(), "read"), (Decision::NotFound, Step::Visibility));
    assert_eq!(d(s(Public, Gated), &stranger(), "read"), (Decision::JoinFirst, Step::Membership));
    assert_eq!(d(s(Public, Open), &stranger(), "read").0, Decision::Allow { actor: Actor::Guest, transport: Transport::Plain });
    // A peer whose card didn't resolve counts as a stranger even if "trusted" was set.
    let unresolved = Facts { user: None, trusted: true, ..Default::default() };
    assert_eq!(d(s(Private, Open), &unresolved, "read").0, Decision::NotFound);

    // Trusted non-member.
    assert!(matches!(d(s(Private, Open), &trusted(), "read").0, Decision::Allow { actor: Actor::Guest, transport: Transport::Sealed }));
    assert_eq!(d(s(Private, Gated), &trusted(), "read"), (Decision::NotFound, Step::Membership));
    assert_eq!(d(s(Public, Gated), &trusted(), "read").0, Decision::JoinFirst);

    // Member.
    for st in [s(Private, Gated), s(Public, Gated)] {
        let (dec, _) = d(st, &member("user"), "files.read");
        assert!(matches!(dec, Decision::Allow { actor: Actor::Member { .. }, transport: Transport::Sealed }), "{dec:?}");
    }
    // A valid membership makes a Private resource visible without a trust-list entry.
    assert!(matches!(d(s(Private, Open), &member("user"), "read").0, Decision::Allow { actor: Actor::Member { .. }, .. }));
    // But a membership naming a role that is gone doesn't.
    assert_eq!(d(s(Private, Gated), &member("gone"), "read"), (Decision::NotFound, Step::Visibility));
    let tm = Facts { trusted: true, ..member("user") };
    assert!(matches!(d(s(Private, Gated), &tm, "files.read").0, Decision::Allow { .. }));
    assert_eq!(d(s(Private, Gated), &tm, "files.delete"), (Decision::Denied("the role does not allow this"), Step::Role));
    // A viewer gets reads only.
    let v = Facts { trusted: true, ..member("viewer") };
    assert!(matches!(d(s(Public, Gated), &v, "files.read").0, Decision::Allow { .. }));
    assert!(matches!(d(s(Public, Gated), &v, "files.write").0, Decision::Denied(_)));
    // A membership naming a removed role or the owner role isn't honored.
    assert_eq!(d(s(Public, Gated), &member("gone"), "read").0, Decision::JoinFirst);
    assert_eq!(d(s(Public, Gated), &member("owner"), "read").0, Decision::JoinFirst);

    // Revoked member.
    assert_eq!(d(s(Private, Gated), &revoked_member(), "read"), (Decision::NotFound, Step::Identity));
    assert_eq!(d(s(Public, Gated), &revoked_member(), "read"), (Decision::Denied("revoked node"), Step::Identity));
    assert_eq!(d(s(Public, Open), &revoked_member(), "read").0, Decision::Denied("revoked node"));

    // Owner.
    assert!(matches!(d(s(Private, Gated), &owner(), "files.delete").0, Decision::Allow { actor: Actor::Owner, transport: Transport::Sealed }));
}

#[test]
fn guests_open_vs_gated() {
    let c = catalog();
    let mut r = presets::ranked(&c, &["files.write"], &["files.read"]).unwrap();
    use Access::*;
    use Visibility::*;
    // Open: guests act as `user`, but never with managing perms.
    assert!(matches!(decide(&c, &r, s(Public, Open), &stranger(), "files.write"), Decision::Allow { actor: Actor::Guest, .. }));
    assert!(matches!(decide(&c, &r, s(Public, Open), &stranger(), "members.invite"), Decision::Denied(_)));
    r.set_defaults(&c, &Actor::Owner, None, None, Some(Some("admin"))).unwrap();
    assert!(matches!(decide(&c, &r, s(Public, Open), &stranger(), "files.delete"), Decision::Denied(_)), "managing never goes to guests");
    assert!(matches!(decide(&c, &r, s(Public, Open), &stranger(), "files.write"), Decision::Allow { .. }));
    // Gated: guests don't exist.
    assert_eq!(decide(&c, &r, s(Public, Gated), &stranger(), "read"), Decision::JoinFirst);
    // No guest role: guests can do nothing.
    r.set_defaults(&c, &Actor::Owner, None, None, Some(None)).unwrap();
    assert!(matches!(decide(&c, &r, s(Public, Open), &stranger(), "read"), Decision::Denied(_)));
    // owner_member has no guest role by default.
    let om = presets::owner_member(&c, &[]).unwrap();
    assert!(matches!(decide(&c, &om, s(Public, Open), &stranger(), "read"), Decision::Denied(_)));
    assert!(matches!(decide(&c, &om, s(Public, Gated), &member("member"), "members.list"), Decision::Allow { .. }));
}

#[test]
fn implications_are_transitive() {
    let c = catalog();
    assert!(c.implies_perm("files.delete", "files.read"));
    assert!(c.implies_perm("*", "anything"));
    assert!(!c.implies_perm("files.read", "files.write"));
    let mut c2 = catalog();
    assert!(c2.imply("files.read", &["files.delete"]).is_err(), "cycles refused");
    assert!(c2.imply("files.read", &["nope"]).is_err());
    assert!(c2.add("read", "again", false).is_err());
    assert!(c2.add("Bad Name", "", false).is_err());
    assert!(c.is_managing("members.kick") && !c.is_managing("read") && !c.is_managing("members.list"));
}

fn admin(r: &RoleSet) -> Actor {
    r.actor("ada", "admin").unwrap()
}
fn user(r: &RoleSet) -> Actor {
    r.actor("ulf", "user").unwrap()
}

#[test]
fn rank_rules() {
    let c = catalog();
    let mut r = presets::ranked(&c, &[], &[]).unwrap();
    let (a, u) = (admin(&r), user(&r));

    // Granting.
    assert!(r.check_grant(&Actor::Owner, r.owner()).is_ok());
    assert!(r.check_grant(&a, r.owner()).is_err());
    assert!(r.check_grant(&a, r.get("admin").unwrap()).is_err(), "not your own rank");
    assert!(r.check_grant(&a, r.get("user").unwrap()).is_ok());

    // Acting on members.
    assert!(r.check_kick(&c, &a, Some("user")).is_ok());
    assert!(r.check_kick(&c, &a, Some("admin")).is_err());
    assert!(r.check_kick(&c, &Actor::Owner, Some("owner")).is_err());
    assert!(r.check_kick(&c, &u, Some("viewer")).is_err(), "user lacks members.kick");
    assert!(r.check_set_role(&c, &a, Some("viewer"), "user").is_ok());
    assert!(r.check_set_role(&c, &a, Some("viewer"), "admin").is_err());
    assert!(r.check_set_role(&c, &a, Some("admin"), "viewer").is_err());

    // Creating and editing roles.
    assert!(r.create(&c, &a, "mod", 80, &["read"]).is_err(), "must rank below your own");
    assert!(r.create(&c, &a, "everything", 60, &["*"]).is_err());
    assert!(r.create(&c, &u, "x", 1, &["read"]).is_err(), "needs roles.manage");
    let m = r.create(&c, &a, "Mod", 60, &["read", "members.kick"]).unwrap().id.clone();
    assert_eq!(m, "mod");
    assert!(r.create(&c, &a, "mod", 1, &[]).is_err(), "names are unique");
    assert!(r.create(&c, &a, "typo", 1, &["raed"]).is_err());
    assert!(r.edit(&c, &a, &m, None, Some(90), None).is_err());
    assert!(r.edit(&c, &a, "owner", Some("boss"), None, None).is_err());
    assert!(r.edit(&c, &Actor::Owner, "owner", None, None, Some(&["read"])).is_err(), "the owner role holds everything");
    assert!(r.edit(&c, &a, "admin", None, Some(10), None).is_err());
    r.edit(&c, &a, &m, Some("moderator"), Some(70), Some(&["read", "members.kick", "members.list"])).unwrap();
    assert_eq!(r.by_name("moderator").unwrap().rank, 70);
    let order: Vec<_> = r.roles().iter().map(|x| x.id.clone()).collect();
    assert_eq!(order, ["owner", "admin", "mod", "user", "viewer"]);

    // Removing roles.
    assert!(r.remove(&c, &a, "owner").is_err());
    assert!(r.remove(&c, &a, "user").is_err(), "user is a default");
    assert_eq!(r.remove(&c, &a, &m).unwrap().id, "viewer");
    assert!(r.remove(&c, &a, "admin").is_err());
    r.set_defaults(&c, &a, Some("viewer"), Some("viewer"), Some(Some("viewer"))).unwrap();
    assert!(r.set_defaults(&c, &a, Some("admin"), None, None).is_err());
    assert!(r.set_defaults(&c, &u, Some("viewer"), None, None).is_err());
    assert_eq!(r.remove(&c, &a, "user").unwrap().id, "viewer");
    assert!(r.remove(&c, &Actor::Owner, "viewer").is_err(), "a default");
    // A role edit applies to members at once: their actor is looked up by id.
    r.edit(&c, &Actor::Owner, "viewer", None, None, Some(&[])).unwrap();
    let v = r.actor("val", "viewer").unwrap();
    assert!(!r.can(&c, &v, "read"));
}

#[test]
fn role_sets_check_and_round_trip() {
    let c = catalog();
    let r = presets::owner_member(&c, &["files.read"]).unwrap();
    let j = serde_json::to_string(&r).unwrap();
    let back: RoleSet = serde_json::from_str(&j).unwrap();
    assert_eq!(back, r);
    let bad = vec![Role { id: "a".into(), name: "a".into(), rank: 1, perms: vec![], builtin: false }];
    assert!(RoleSet::new(&c, bad).is_err(), "needs an owner");
    let typo = vec![
        Role { id: "owner".into(), name: "owner".into(), rank: 100, perms: vec!["*".into()], builtin: true },
        Role { id: "m".into(), name: "m".into(), rank: 1, perms: vec!["nope".into()], builtin: false },
    ];
    assert!(RoleSet::new(&c, typo).is_err());
    assert_eq!(Settings::default().transport(), Transport::Sealed);
    assert_eq!(s(Visibility::Public, Access::Open).transport(), Transport::Plain);
}
