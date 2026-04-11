# OpenMesh

OpenMesh is an open-source censorship-circumvention network: a lightweight peer-to-peer relay and exit system designed to help people reach the open internet without centralized infrastructure. Security-focused.

## What OpenMesh Does

- Routes traffic through a decentralized peer-to-peer mesh of relay and exit nodes
- Supports flexible 1-hop, 2-hop, and 3-hop routing profiles
- Uses transport and handshake layers designed to blend with common web traffic patterns
- Pairs a Go networking core with mobile, desktop, and operator tooling

## Mission

Help people access the open internet without central servers, accounts, subscriptions, or easily blockable infrastructure.

## Principles

- Zero config for everyday users
- Lightweight clients with minimal idle overhead
- No central choke points
- Transports that resemble normal web traffic
- Open source and community-driven stewardship

## Repository Structure

- `core/`: Go daemon and networking logic
- `mobile/`: mobile client code
- `desktop/`: desktop client code
- `scripts/`: installer and operator tooling
- `docs/`: operator, launch, and project documentation
- `bootstrap/`: seed peer manifest published with GitHub Releases

## Distribution

OpenMesh is now set up to publish release artifacts through GitHub Releases.

- Linux servers: use the rendered release installer from the latest release asset
- macOS desktop: download the packaged DMG from the release page
- Windows desktop: download the ZIP from the release page
- Android: download the APK from the release page

The Linux installer expects GitHub release assets, not a custom domain.

## Bootstrap Peers

Fresh clients need at least one bootstrap peer manifest to discover the mesh.
The release workflow publishes `bootstrap-peers.json` from `bootstrap/peers.json`
as a release asset, and the installer plus packaged apps point at that asset by default.

Recommended operator flow:

1. Start one or more public relay or exit nodes.
2. Run `openmeshd self-record` on each seed node.
3. Merge those records into `bootstrap/peers.json`.
4. Cut a GitHub release so `bootstrap-peers.json` is updated for clients.

## Contributing

OpenMesh is maintained in the open. Contributions are especially welcome in:

- protocol review and threat-model feedback
- transport and handshake design review
- documentation and contributor experience
- mobile and desktop UX planning
- test planning and CI design

Start with [CONTRIBUTING.md](CONTRIBUTING.md), then open a discussion or issue before large changes.

## Funding

This project aims to stay community-driven. Donations are optional, do not buy influence, and will never gate access to the software.

See [docs/DONATIONS.md](docs/DONATIONS.md) for the donation page template and operational recommendations.

## Safety

If you find a vulnerability, do not open a public issue. Follow [SECURITY.md](SECURITY.md).
