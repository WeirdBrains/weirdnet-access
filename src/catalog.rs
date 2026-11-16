//! Permissions: the shared core and the app's extensions, with implications.

use crate::error::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};

/// Everything (only the owner role holds it by default).
pub const ALL: &str = "*";

/// The shared core every app has.
pub mod core {
    /// See and fetch the resource.
    pub const READ: &str = "read";
    /// See who the members are.
    pub const MEMBERS_LIST: &str = "members.list";
    /// Approve or deny join requests.
    pub const MEMBERS_APPROVE: &str = "members.approve";
    /// Invite people.
    pub const MEMBERS_INVITE: &str = "members.invite";
    /// Remove members ranked below you.
    pub const MEMBERS_KICK: &str = "members.kick";
    /// Change the roles of members ranked below you.
    pub const MEMBERS_ROLE: &str = "members.role";
    /// Choose the roles new members get.
    pub const MEMBERS_DEFAULTS: &str = "members.defaults";
    /// Create, edit and remove roles ranked below your own.
    pub const ROLES_MANAGE: &str = "roles.manage";
}

/// One permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    /// Its name (`a-z0-9._-`).
    pub name: String,
    /// What it allows, for people.
    pub description: String,
    /// Managing permissions are never given to guests.
    pub managing: bool,
}

/// The permission catalog: the core plus what the app adds.
#[derive(Debug, Clone)]
pub struct Catalog {
    perms: BTreeMap<String, Permission>,
    implies: BTreeMap<String, BTreeSet<String>>,
}

fn check_name(n: &str) -> Result<()> {
    let ok = (1..=64).contains(&n.len())
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
        && !n.starts_with('.');
    if ok { Ok(()) } else { Err(Error::invalid("permission", format!("{n:?}"))) }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::core()
    }
}

impl Catalog {
    /// The shared core: `read`, `members.*` and `roles.manage`.
    pub fn core() -> Self {
        let mut c = Catalog { perms: BTreeMap::new(), implies: BTreeMap::new() };
        for (n, d, m) in [
            (core::READ, "see and fetch the resource", false),
            (core::MEMBERS_LIST, "see who the members are", false),
            (core::MEMBERS_APPROVE, "approve or deny join requests", true),
            (core::MEMBERS_INVITE, "invite people to join", true),
            (core::MEMBERS_KICK, "remove members ranked below you", true),
            (core::MEMBERS_ROLE, "change the roles of members ranked below you", true),
            (core::MEMBERS_DEFAULTS, "choose the roles new members get", true),
            (core::ROLES_MANAGE, "create, edit and remove roles ranked below your own", true),
        ] {
            c.perms.insert(n.into(), Permission { name: n.into(), description: d.into(), managing: m });
        }
        c
    }

    /// Adds an app permission. Core names can't be redefined.
    pub fn add(&mut self, name: &str, description: &str, managing: bool) -> Result<&mut Self> {
        check_name(name)?;
        if self.perms.contains_key(name) {
            return Err(Error::invalid("permission", format!("{name} already exists")));
        }
        self.perms.insert(name.into(), Permission { name: name.into(), description: description.into(), managing });
        Ok(self)
    }

    /// Says `stronger` includes `weaker` (both must exist; cycles are refused).
    pub fn imply(&mut self, stronger: &str, weaker: &[&str]) -> Result<&mut Self> {
        for p in std::iter::once(&stronger).chain(weaker) {
            if !self.perms.contains_key(*p) {
                return Err(Error::invalid("permission", format!("{p} is not in the catalog")));
            }
        }
        for w in weaker {
            if *w == stronger || self.implies_perm(w, stronger) {
                return Err(Error::invalid("implication", format!("{w} already includes {stronger}")));
            }
            self.implies.entry(stronger.into()).or_default().insert(w.to_string());
        }
        Ok(self)
    }

    /// Every permission.
    pub fn permissions(&self) -> impl Iterator<Item = &Permission> {
        self.perms.values()
    }

    /// One permission.
    pub fn get(&self, name: &str) -> Option<&Permission> {
        self.perms.get(name)
    }

    /// Normalizes and checks a permission name (`*` is everything).
    pub fn check(&self, p: &str) -> Result<String> {
        let p = p.trim().to_ascii_lowercase();
        if p == ALL || self.perms.contains_key(&p) {
            Ok(p)
        } else {
            Err(Error::invalid("permission", format!("`{p}`: one of {}", self.perms.keys().cloned().collect::<Vec<_>>().join(", "))))
        }
    }

    /// True if `p` is a managing permission (or unknown, to be safe).
    pub fn is_managing(&self, p: &str) -> bool {
        p == ALL || self.perms.get(p).is_none_or(|x| x.managing)
    }

    /// True if holding `held` gives `wanted` (itself, `*`, or through implications, followed
    /// transitively).
    pub fn implies_perm(&self, held: &str, wanted: &str) -> bool {
        if held == ALL || held == wanted {
            return true;
        }
        let mut seen = BTreeSet::new();
        let mut todo = vec![held];
        while let Some(h) = todo.pop() {
            if let Some(ws) = self.implies.get(h) {
                for w in ws {
                    if w == wanted {
                        return true;
                    }
                    if seen.insert(w.as_str()) {
                        todo.push(w);
                    }
                }
            }
        }
        false
    }

    /// Every non-`*` permission name.
    pub fn all_names(&self) -> Vec<String> {
        self.perms.keys().cloned().collect()
    }
}
