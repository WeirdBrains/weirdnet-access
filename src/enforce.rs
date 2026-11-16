//! Host-side enforcement, per request, in a fixed order:
//!
//! 1. **Identity.** Noise has authenticated the peer id; the app resolves it to a user
//!    through the node cert in the peer's card. Revoked nodes are refused.
//! 2. **Visibility.** Private: a user who isn't the owner and isn't on the trust list gets
//!    "not found", which leaks nothing; a membership alone doesn't make a Private resource
//!    visible. Public: continue.
//! 3. **Membership.** Gated: a valid, unrevoked membership for this resource is needed
//!    (Public + Gated non-members may see the listing and request to join). Open: continue.
//! 4. **Role.** The actor's role must allow the action (implications and rank rules
//!    included). Guests never get managing permissions.
//! 5. **Transport.** Private or Gated content goes over sealed streams; Public + Open goes
//!    plain, its integrity coming from the signed manifest.

use crate::axes::{Access, Visibility};
use crate::catalog::Catalog;
use crate::roles::{Actor, RoleSet};

/// A resource's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settings {
    /// Who can see it.
    pub visibility: Visibility,
    /// Whether membership is needed.
    pub access: Access,
}

impl Settings {
    /// How content must travel.
    pub fn transport(&self) -> Transport {
        if self.visibility == Visibility::Public && self.access == Access::Open { Transport::Plain } else { Transport::Sealed }
    }
}

/// What the host knows about the requester, from checks done before (weirdnet-net: the
/// node cert, the trust list, `check_presented` for the membership).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// The user the peer resolves to, if its card checked out.
    pub user: Option<String>,
    /// The peer's node cert is revoked.
    pub node_revoked: bool,
    /// The user is the resource's owner.
    pub is_owner: bool,
    /// The user is on the host's trust list.
    pub trusted: bool,
    /// The role id from a valid, unexpired, unrevoked membership of this resource.
    pub membership_role: Option<String>,
}

/// How content goes out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Sealed streams bound to the exchange and both peers.
    Sealed,
    /// Plain (Public + Open; the signed manifest gives integrity).
    Plain,
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Go ahead, as this actor, over this transport.
    Allow {
        /// Who.
        actor: Actor,
        /// How.
        transport: Transport,
    },
    /// Answer "not found" (Private, not trusted; or a revoked node on a Private resource).
    NotFound,
    /// Public + Gated, not a member: show the title, owner and description and offer a join
    /// request; no content.
    JoinFirst,
    /// Known, but not allowed.
    Denied(&'static str),
}

/// The step that decided (for tests and logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// 1.
    Identity,
    /// 2.
    Visibility,
    /// 3.
    Membership,
    /// 4.
    Role,
}

/// Decides one request for `perm` on a resource.
pub fn decide(catalog: &Catalog, roles: &RoleSet, settings: Settings, facts: &Facts, perm: &str) -> Decision {
    decide_with_step(catalog, roles, settings, facts, perm).0
}

/// [`decide`], also saying which step decided.
pub fn decide_with_step(catalog: &Catalog, roles: &RoleSet, settings: Settings, facts: &Facts, perm: &str) -> (Decision, Step) {
    let private = settings.visibility == Visibility::Private;
    // 1. Identity.
    if facts.node_revoked {
        return (if private { Decision::NotFound } else { Decision::Denied("revoked node") }, Step::Identity);
    }
    let owner = facts.is_owner && facts.user.is_some();
    let member = facts.user.as_deref().zip(facts.membership_role.as_deref()).and_then(|(u, r)| roles.actor(u, r));
    // 2. Visibility. Members of a Private resource must be on the trust list too.
    if private && !owner && !(facts.trusted && facts.user.is_some()) {
        return (Decision::NotFound, Step::Visibility);
    }
    // 3. Membership.
    let actor = if owner {
        Actor::Owner
    } else {
        match (member, settings.access) {
            (Some(a), _) => a,
            (None, Access::Open) => Actor::Guest,
            (None, Access::Gated) => return (if private { Decision::NotFound } else { Decision::JoinFirst }, Step::Membership),
        }
    };
    // 4. Role.
    if !roles.can(catalog, &actor, perm) {
        return (Decision::Denied("the role does not allow this"), Step::Role);
    }
    // 5. Transport.
    (Decision::Allow { actor, transport: settings.transport() }, Step::Role)
}
