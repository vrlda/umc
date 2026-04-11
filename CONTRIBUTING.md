# Contributing to OpenMesh

Thanks for contributing to OpenMesh.

The best contributions improve safety, reliability, usability, and maintainability.

## Before you start

1. Read the README and the relevant documentation in this repository.
2. Check for an existing issue or discussion.
3. For any large design, protocol, privacy, or security change, start a discussion before opening a pull request.

## Good contributions

- improve documentation
- add tests for existing behavior
- fix scoped bugs with a clear reproduction
- propose contributor tooling or CI improvements
- review privacy, censorship-resistance, or operator-safety assumptions

## What to include in a pull request

- a short explanation of the problem
- the proposed change and why it helps
- tests or a clear explanation of why tests are not yet practical
- docs updates when behavior, workflow, or expectations change
- security notes if the change affects transport, identity, routing, or logging

## Design expectations

- Keep changes focused. Small pull requests are easier to review and safer to merge.
- Prefer explicitness over cleverness.
- Do not add telemetry, tracking, or opaque network behavior.
- Avoid introducing central points of control without a public design discussion.
- If a change impacts privacy or operator risk, call that out directly in the pull request.

## Security issues

Do not report vulnerabilities in public issues, discussions, or pull requests.

Follow `SECURITY.md` for private reporting instructions.

## Community process

- Issues are for actionable work.
- Discussions are for questions, design ideas, and broader project direction.
- Maintainers may close or redirect contributions that are too broad or need prior design agreement.

## Licensing

By contributing, you agree that your contributions will be licensed under the MIT License in this repository.
