# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `roles::check_grant` and `roles::check_over`: the rank rules without a `RoleSet`, for apps that keep their roles elsewhere.

## [0.1.0] - 2026-11-16

### Added

- Visibility (private/public) and access (open/gated) as independent settings.
- The shared permission core, app permissions and transitive implications.
- Ranked roles with Muninn's rank rules, and the `owner_member` and `ranked` presets.
- Owner, member and guest actors; guests never get managing permissions.
- A private resource is visible only to its owner and trusted users: members must be on the trust list too.
- `decide`: identity, visibility, membership, role, then sealed or plain transport.

[Unreleased]: https://github.com/WeirdBrains/weirdnet-access/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/WeirdBrains/weirdnet-access/compare/6cf2e0f5a71feadb3f28fa2613ac0a79925b8b25...v0.1.0
