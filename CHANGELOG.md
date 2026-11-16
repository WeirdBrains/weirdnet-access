# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Visibility (private/public) and access (open/gated) as independent settings.
- The shared permission core, app permissions and transitive implications.
- Ranked roles with Muninn's rank rules, and the `owner_member` and `ranked` presets.
- Owner, member and guest actors; guests never get managing permissions.
- `decide`: identity, visibility, membership, role, then sealed or plain transport.
