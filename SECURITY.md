# Security

Report problems privately to m3talsmith@gmail.com.

## What the policy guarantees

- Requests go through the steps in a fixed order: identity, visibility, membership, role.
  A revoked node never gets past the first step.
- A Private resource answers "not found" to anyone who isn't the owner or on the trust
  list, so its existence isn't revealed. A membership alone doesn't make it visible: its
  members must be trusted too.
- A Gated resource gives content only to valid members; on a Public resource, non-members
  see the listing and can ask to join.
- Guests act only on Open resources, only under the guest role, and never get managing
  permissions, whatever that role says.
- A membership can't make someone the owner, and a membership naming a removed role gives
  nothing.
- Only the owner grants the owner role. Everyone else may grant, edit, create or remove
  only roles ranked below their own, and act only on members ranked below them.
- Private or Gated content must travel over sealed streams.

## Limits

- The crate decides; it doesn't check certificates or memberships. The app passes
  [`Facts`] from weirdnet-net (node certs, the trust list, `check_presented`); wrong facts
  give wrong answers.
- Roles are looked up by id at each request, so an edit or removal applies at once to
  hosts holding the new role set. Members' devices learn of it only when they sync.
