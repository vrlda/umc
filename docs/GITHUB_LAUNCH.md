# GitHub Launch Guide

This guide is for publishing and maintaining OpenMesh as a public repository.

## Repository description

OpenMesh is an open-source censorship-circumvention network: a lightweight peer-to-peer relay and exit system designed to help people reach the open internet without centralized infrastructure. Security-focused.

## Suggested homepage and About section

- Homepage: your project website or docs site
- Description: use the text above
- Website button: set only after the public site is live
- Social preview: upload a custom image before launch

## Suggested topics

- `p2p`
- `decentralized`
- `privacy`
- `networking`
- `censorship-circumvention`
- `anti-censorship`
- `quic`
- `websocket`
- `noise-protocol`
- `dht`
- `onion-routing`
- `go`
- `flutter`
- `open-source`
- `community-driven`

## General settings

- Visibility: `Public`
- Features:
  - `Issues`: on
  - `Pull Requests`: on
  - `Discussions`: on
  - `Projects`: on
  - `Wiki`: off
  - `Sponsor button`: set up only after funding links are real

## Pull request settings

Recommended defaults:

- Allow squash merging: on
- Allow merge commits: off
- Allow rebase merging: off
- Allow auto-merge: on after CI exists
- Automatically delete head branches: on

Rationale: security-focused infrastructure projects usually benefit from a
cleaner `main` history and fewer merge-style debates.

## Branch and ruleset settings for `main`

Create a branch ruleset targeting `main` with:

- Require a pull request before merging
- Require at least 1 approval
- Dismiss stale approvals when new commits are pushed
- Require conversation resolution before merge
- Block force pushes
- Block branch deletion
- Require linear history

Enable later, after the repo has real owners and CI:

- Require status checks to pass
- Require approval from Code Owners
- Require signed commits, if maintainers are ready to enforce it

Do not enable required Code Owner review until `CODEOWNERS` has real teams or usernames.

## Security and analysis settings

Turn on everything GitHub recommends for public repositories:

- Dependency graph
- Dependabot alerts
- Dependabot security updates
- Secret scanning
- Push protection
- Code scanning
- Private vulnerability reporting

Also:

- Watch the repository with `All Activity` for maintainers who handle security
- Review alert routing before launch

## Discussions setup

Create these categories:

- Announcements
- Q&A
- Ideas
- Show and Tell
- Operators
- Governance

Pin one welcome discussion that links to the README, contribution guide,
security policy, support resources, and donation page.

## Labels to create early

- `good first issue`
- `help wanted`
- `needs triage`
- `bug`
- `feature`
- `docs`
- `architecture`
- `security`
- `transport`
- `routing`
- `dht`
- `mobile`
- `desktop`
- `operator`
- `legal`

## Funding setup

1. Publish a donation page or equivalent public funding page.
2. Update `.github/FUNDING.yml` with real links.
3. Enable the sponsor button in repository settings.
4. Make sure the donation page clearly lists supported chains and addresses.
5. State that donations do not grant governance or merge rights.

## Before making the repo public

- remove any secrets, credentials, or private infrastructure details
- review git history, not just current files
- verify no private test endpoints or personal addresses are documented
- add the real website, social preview image, and donation links
- populate `CODEOWNERS` with real maintainers or teams
- make sure at least one maintainer is ready to review issues and discussions
- create 5 to 10 starter issues and label at least 3 with `good first issue`

## Optional organization-level setup

If you expect multiple repositories, create a public `.github` repository for
shared community-health files across the organization.
