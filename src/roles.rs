//! Roles, actors and the rank rules (Muninn's, the default model).
//!
//! - A role is a name, a rank, permissions and a builtin flag.
//! - The owner can do everything. Others may only grant, edit or remove roles ranked below
//!   their own, and only act on members ranked below them; only the owner grants the
//!   builtin `owner` role, which always holds everything and can't be removed.
//! - Guests act under the resource's guest role only on Open resources, and never get
//!   managing permissions.

use crate::catalog::{ALL, Catalog, core};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// The builtin owner role's name.
pub const OWNER: &str = "owner";

/// A role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// A stable id (what memberships carry).
    pub id: String,
    /// Its name.
    pub name: String,
    /// Higher outranks lower.
    pub rank: i64,
    /// Its permissions (`*` for everything).
    pub perms: Vec<String>,
    /// Shipped by the app rather than made by a user.
    #[serde(default)]
    pub builtin: bool,
}

impl Role {
    /// True for the builtin owner role.
    pub fn is_owner(&self) -> bool {
        self.builtin && self.name == OWNER
    }

    /// True if this role gives `perm` (implications included).
    pub fn has(&self, catalog: &Catalog, perm: &str) -> bool {
        self.perms.iter().any(|p| catalog.implies_perm(p, perm))
    }
}

/// Who is acting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    /// The resource's owner.
    Owner,
    /// A member, under a role.
    Member {
        /// The member's user id.
        user_id: String,
        /// The role they act under.
        role: Role,
    },
    /// Not a member (only meaningful on Open resources).
    Guest,
}

impl Actor {
    /// Its rank for the rank rules.
    pub fn rank(&self) -> i64 {
        match self {
            Actor::Owner => i64::MAX,
            Actor::Member { role, .. } => role.rank,
            Actor::Guest => i64::MIN,
        }
    }

    /// Who, for logs.
    pub fn who(&self) -> String {
        match self {
            Actor::Owner => "owner".into(),
            Actor::Member { user_id, role } => format!("{user_id} ({})", role.name),
            Actor::Guest => "guest".into(),
        }
    }
}

/// May `a` give `role` to someone? Only the owner gives the builtin owner role; others give
/// only roles ranked below their own. (The rank rule without a [`RoleSet`], for apps that
/// keep their roles elsewhere.)
pub fn check_grant(a: &Actor, role: &Role) -> Result<()> {
    if role.is_owner() && a != &Actor::Owner {
        return Err(Error::Denied("only the owner gives the owner role".into()));
    }
    if a != &Actor::Owner && role.rank >= a.rank() {
        return Err(Error::Denied(format!("{} ranks as high as or above {}", role.name, a.who())));
    }
    Ok(())
}

/// May `a` act on (kick, change the role of) a member holding `theirs` (`None` if they have
/// no role)? Nobody acts on the owner; others act only on members ranked below them.
pub fn check_over(a: &Actor, theirs: Option<&Role>) -> Result<()> {
    if theirs.is_some_and(Role::is_owner) {
        return Err(Error::Denied("that is the owner".into()));
    }
    if a == &Actor::Owner {
        return Ok(());
    }
    let rank = theirs.map(|r| r.rank).unwrap_or(i64::MIN);
    if rank >= a.rank() {
        return Err(Error::Denied(format!("they rank as high as or above {}", a.who())));
    }
    Ok(())
}

/// A resource's roles and its defaults for new members and guests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSet {
    roles: Vec<Role>,
    /// What approved join requests get.
    pub apply_role: Option<String>,
    /// What invitees get.
    pub invite_role: Option<String>,
    /// What guests act under on Open resources.
    pub guest_role: Option<String>,
}

fn new_id(roles: &[Role], name: &str) -> String {
    let base: String = name.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let mut id = base.clone();
    let mut n = 2;
    while roles.iter().any(|r| r.id == id) {
        id = format!("{base}-{n}");
        n += 1;
    }
    id
}

fn check_role_name(n: &str) -> Result<()> {
    if n.trim().is_empty() || n.len() > 64 || n.chars().any(char::is_control) {
        return Err(Error::invalid("role", format!("bad name {n:?}")));
    }
    Ok(())
}

impl RoleSet {
    /// A set from roles (ids unique, exactly one builtin owner).
    pub fn new(catalog: &Catalog, roles: Vec<Role>) -> Result<Self> {
        let owners = roles.iter().filter(|r| r.is_owner()).count();
        if owners != 1 {
            return Err(Error::invalid("roles", "exactly one builtin owner role"));
        }
        for (i, r) in roles.iter().enumerate() {
            check_role_name(&r.name)?;
            if roles[..i].iter().any(|o| o.id == r.id) {
                return Err(Error::invalid("roles", format!("{} appears twice", r.id)));
            }
            for p in &r.perms {
                catalog.check(p)?;
            }
        }
        Ok(Self { roles, apply_role: None, invite_role: None, guest_role: None })
    }

    /// The roles, highest rank first.
    pub fn roles(&self) -> Vec<&Role> {
        let mut v: Vec<&Role> = self.roles.iter().collect();
        v.sort_by(|a, b| b.rank.cmp(&a.rank).then(a.name.cmp(&b.name)));
        v
    }

    /// A role by id.
    pub fn get(&self, id: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.id == id)
    }

    /// A role by name (case-insensitive).
    pub fn by_name(&self, name: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.name.eq_ignore_ascii_case(name))
    }

    /// The owner role.
    pub fn owner(&self) -> &Role {
        self.roles.iter().find(|r| r.is_owner()).expect("an owner role")
    }

    /// The actor for a member holding role `role_id` (from their membership). `None` if
    /// the role is gone.
    pub fn actor(&self, user_id: &str, role_id: &str) -> Option<Actor> {
        let role = self.get(role_id)?;
        if role.is_owner() {
            // Only the resource owner is the owner; a membership can't make someone it.
            return None;
        }
        Some(Actor::Member { user_id: user_id.into(), role: role.clone() })
    }

    /// The guest role, if guests may act.
    pub fn guest(&self) -> Option<&Role> {
        self.guest_role.as_deref().and_then(|id| self.get(id))
    }

    /// What `actor` may do (guests only through [`crate::enforce`], which checks Open).
    pub fn can(&self, catalog: &Catalog, actor: &Actor, perm: &str) -> bool {
        match actor {
            Actor::Owner => true,
            Actor::Member { role, .. } => self.get(&role.id).is_some_and(|r| r.has(catalog, perm)),
            Actor::Guest => !catalog.is_managing(perm) && self.guest().is_some_and(|r| r.has(catalog, perm)),
        }
    }

    fn require(&self, catalog: &Catalog, a: &Actor, perm: &str) -> Result<()> {
        if self.can(catalog, a, perm) { Ok(()) } else { Err(Error::Denied(format!("{} may not {perm}", a.who()))) }
    }

    /// May `a` give `role` to someone?
    pub fn check_grant(&self, a: &Actor, role: &Role) -> Result<()> {
        check_grant(a, role)
    }

    /// May `a` act on a member holding `their_role` (kick, change role)?
    pub fn check_over(&self, a: &Actor, their_role: Option<&str>) -> Result<()> {
        check_over(a, their_role.and_then(|r| self.get(r)))
    }

    /// Creates a role ranked below `a`'s own (needs `roles.manage`).
    pub fn create(&mut self, catalog: &Catalog, a: &Actor, name: &str, rank: i64, perms: &[&str]) -> Result<&Role> {
        self.require(catalog, a, core::ROLES_MANAGE)?;
        check_role_name(name)?;
        if self.by_name(name).is_some() {
            return Err(Error::invalid("role", format!("{name} exists")));
        }
        let perms = perms.iter().map(|p| catalog.check(p)).collect::<Result<Vec<_>>>()?;
        if a != &Actor::Owner && rank >= a.rank() {
            return Err(Error::Denied("a new role must rank below your own".into()));
        }
        if a != &Actor::Owner && perms.iter().any(|p| p == ALL) {
            return Err(Error::Denied("only the owner makes a role with every permission".into()));
        }
        let id = new_id(&self.roles, name);
        self.roles.push(Role { id: id.clone(), name: name.into(), rank, perms, builtin: false });
        Ok(self.get(&id).unwrap())
    }

    /// Edits a role ranked below `a`'s own. The owner role can't be changed.
    pub fn edit(&mut self, catalog: &Catalog, a: &Actor, id: &str, name: Option<&str>, rank: Option<i64>, perms: Option<&[&str]>) -> Result<&Role> {
        self.require(catalog, a, core::ROLES_MANAGE)?;
        let role = self.get(id).ok_or_else(|| Error::invalid("role", format!("no role {id}")))?.clone();
        self.check_grant(a, &role)?;
        if role.is_owner() {
            return Err(Error::Denied("the owner role always holds everything".into()));
        }
        if let Some(k) = rank
            && a != &Actor::Owner
            && k >= a.rank()
        {
            return Err(Error::Denied("a role must rank below your own".into()));
        }
        let perms = perms.map(|v| v.iter().map(|p| catalog.check(p)).collect::<Result<Vec<_>>>()).transpose()?;
        if a != &Actor::Owner && perms.as_ref().is_some_and(|v| v.iter().any(|p| p == ALL)) {
            return Err(Error::Denied("only the owner gives a role every permission".into()));
        }
        if let Some(n) = name {
            check_role_name(n)?;
            if self.by_name(n).is_some_and(|r| r.id != id) {
                return Err(Error::invalid("role", format!("{n} exists")));
            }
        }
        let r = self.roles.iter_mut().find(|r| r.id == id).unwrap();
        if let Some(n) = name {
            r.name = n.into();
        }
        if let Some(k) = rank {
            r.rank = k;
        }
        if let Some(p) = perms {
            r.perms = p;
        }
        Ok(self.get(id).unwrap())
    }

    /// Removes a role ranked below `a`'s own; returns the role its members move to (the
    /// lowest remaining). The owner role and the current defaults can't be removed.
    pub fn remove(&mut self, catalog: &Catalog, a: &Actor, id: &str) -> Result<Role> {
        self.require(catalog, a, core::ROLES_MANAGE)?;
        let role = self.get(id).ok_or_else(|| Error::invalid("role", format!("no role {id}")))?.clone();
        self.check_grant(a, &role)?;
        if role.is_owner() {
            return Err(Error::Denied("the owner role stays".into()));
        }
        if [&self.apply_role, &self.invite_role, &self.guest_role].iter().any(|d| d.as_deref() == Some(id)) {
            return Err(Error::Denied(format!("{} is a default for new members or guests; choose another first", role.name)));
        }
        self.roles.retain(|r| r.id != id);
        let fallback = self.roles.iter().filter(|r| !r.is_owner()).min_by_key(|r| r.rank).cloned();
        fallback.ok_or_else(|| Error::invalid("roles", "a resource needs a role besides the owner's"))
    }

    /// Sets the defaults (needs `members.defaults`; each role must be one `a` may grant).
    pub fn set_defaults(
        &mut self,
        catalog: &Catalog,
        a: &Actor,
        apply: Option<&str>,
        invite: Option<&str>,
        guest: Option<Option<&str>>,
    ) -> Result<()> {
        self.require(catalog, a, core::MEMBERS_DEFAULTS)?;
        for id in [apply, invite, guest.flatten()].into_iter().flatten() {
            let r = self.get(id).ok_or_else(|| Error::invalid("role", format!("no role {id}")))?;
            self.check_grant(a, r)?;
        }
        if let Some(x) = apply {
            self.apply_role = Some(x.into());
        }
        if let Some(x) = invite {
            self.invite_role = Some(x.into());
        }
        if let Some(g) = guest {
            self.guest_role = g.map(Into::into);
        }
        Ok(())
    }

    /// Checks a change of a member's role (needs `members.role`, rank over them, and the
    /// right to grant the new role).
    pub fn check_set_role(&self, catalog: &Catalog, a: &Actor, their_role: Option<&str>, new_role: &str) -> Result<()> {
        self.require(catalog, a, core::MEMBERS_ROLE)?;
        self.check_over(a, their_role)?;
        let r = self.get(new_role).ok_or_else(|| Error::invalid("role", format!("no role {new_role}")))?;
        self.check_grant(a, r)
    }

    /// Checks removing a member (needs `members.kick` and rank over them).
    pub fn check_kick(&self, catalog: &Catalog, a: &Actor, their_role: Option<&str>) -> Result<()> {
        self.require(catalog, a, core::MEMBERS_KICK)?;
        self.check_over(a, their_role)
    }
}

/// Ready-made role sets.
pub mod presets {
    use super::*;

    fn owned(v: &[&str]) -> Vec<String> {
        v.iter().map(|p| p.to_string()).collect()
    }

    /// `owner` (100, everything) and `member` (50, `read`, `members.list` and `extra`);
    /// members are the default for invites and join requests. Morph's default set.
    pub fn owner_member(catalog: &Catalog, extra: &[&str]) -> Result<RoleSet> {
        let mut m = owned(&[core::READ, core::MEMBERS_LIST]);
        m.extend(owned(extra));
        let mut s = RoleSet::new(
            catalog,
            vec![
                Role { id: "owner".into(), name: OWNER.into(), rank: 100, perms: vec![ALL.into()], builtin: true },
                Role { id: "member".into(), name: "member".into(), rank: 50, perms: m, builtin: true },
            ],
        )?;
        s.apply_role = Some("member".into());
        s.invite_role = Some("member".into());
        Ok(s)
    }

    /// Muninn's ranks: `owner` (100, everything), `admin` (80, every catalog permission),
    /// `user` (50) and `viewer` (10), each with `read`, `members.list` and the app's extras;
    /// `user` is the default for invites and join requests, and guests act as it on Open
    /// resources (Muninn's open orgs).
    pub fn ranked(catalog: &Catalog, user: &[&str], viewer: &[&str]) -> Result<RoleSet> {
        let base = [core::MEMBERS_LIST, core::READ];
        let with = |extra: &[&str]| {
            let mut v = owned(&base);
            for e in extra {
                if !v.iter().any(|x| x == e) {
                    v.push(e.to_string());
                }
            }
            v
        };
        let mut s = RoleSet::new(
            catalog,
            vec![
                Role { id: "owner".into(), name: OWNER.into(), rank: 100, perms: vec![ALL.into()], builtin: true },
                Role { id: "admin".into(), name: "admin".into(), rank: 80, perms: catalog.all_names(), builtin: true },
                Role { id: "user".into(), name: "user".into(), rank: 50, perms: with(user), builtin: true },
                Role { id: "viewer".into(), name: "viewer".into(), rank: 10, perms: with(viewer), builtin: true },
            ],
        )?;
        s.apply_role = Some("user".into());
        s.invite_role = Some("user".into());
        s.guest_role = Some("user".into());
        Ok(s)
    }
}
