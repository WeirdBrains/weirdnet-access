# weirdnet-access

Access policy for Weirdnet apps. It answers "may this peer do this to this resource?" the
same way in every app.

- **Two independent settings.** Visibility is `private` (only the owner and trusted peers
  know it exists; members must be trusted too) or `public`. Access is `open` (no membership needed) or `gated`
  (a valid membership is needed). On the wire it is always `gated`; CLIs may also accept
  `members`, `member` and `closed`. New resources default to Private + Open.
- **A shared permission core that apps extend.** The core is `read`, `members.list`,
  `members.approve`, `members.invite`, `members.kick`, `members.role`, `members.defaults`
  and `roles.manage`. Apps add their own, with implications (`files.delete` includes
  `files.write`, which includes `files.read`), followed transitively. Cycles are refused.
- **Ranked roles that users can change.** Each role has a name, a rank and permissions.
  The rank rules are Muninn's. Presets: `owner_member` (Morph) and `ranked`
  (owner/admin/user/viewer, Muninn).
- **Owner, member and guest actors.** Guests act under the resource's guest role only on
  Open resources, and never with managing permissions.
- **Enforcement in a fixed order.** Identity, visibility, membership, role, then
  transport. Private or Gated content goes sealed; Public + Open goes plain.

```rust
use weirdnet_access::*;

let mut catalog = Catalog::core();
catalog.add("files.read", "download files", false)?;
catalog.add("files.write", "upload and change files", false)?;
catalog.imply("files.write", &["files.read"])?;
let roles = presets::ranked(&catalog, &["files.write"], &["files.read"])?;

let settings = Settings { visibility: Visibility::Public, access: Access::Gated };
// From weirdnet-net: the node cert, the trust list, and `check_presented` on the membership.
let facts = Facts { user: Some("ulf".into()), membership_role: Some("user".into()), ..Default::default() };
assert!(matches!(
    decide(&catalog, &roles, settings, &facts, "files.write"),
    Decision::Allow { transport: Transport::Sealed, .. }
));
let stranger = Facts { user: Some("someone".into()), ..Default::default() };
assert_eq!(decide(&catalog, &roles, settings, &stranger, "files.read"), Decision::JoinFirst);
# Ok::<(), Error>(())
```

## The steps

| Step | Private | Public |
| --- | --- | --- |
| 1. Identity | revoked node: not found | revoked node: denied |
| 2. Visibility | not the owner and not trusted: not found (members must be trusted too) | continue |
| 3. Membership (Gated) | no membership: not found | no membership: join first |
| 4. Role | the role must allow it | the role must allow it |
| 5. Transport | sealed | sealed if Gated, plain if Open |

## Rank rules

- The owner can do everything, and only the owner grants the builtin `owner` role. That
  role always holds `*` and can't be edited or removed.
- Everyone else may grant, create, edit and remove only roles ranked below their own, and
  may kick or re-role only members ranked below them. Only the owner makes a role with `*`.
- Removing a role moves its members to the lowest remaining role. A role that is the
  default for join requests, invites or guests can't be removed until the default changes.

The crate doesn't depend on weirdnet-net. Apps pass in facts they have already checked.
See [SECURITY.md](SECURITY.md).

License: BSD-3-Clause.
