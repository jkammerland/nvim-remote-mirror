# Security policy

## Supported versions

Security fixes are applied to the latest published release and the current
default branch. Older releases and historical commits are not supported;
upgrade to the latest release before reporting a problem that may already have
been fixed.

This project is pre-1.0. Security fixes may require incompatible configuration,
protocol, or deployment changes when preserving compatibility would leave
users exposed.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Prefer GitHub's
private vulnerability reporting flow under **Security > Advisories > Report a
vulnerability**. If that flow is unavailable, email
`jkammerland@gmail.com` with a subject beginning `nvim-remote-mirror security`.

Include the affected version or commit, operating systems involved, a concise
impact assessment, reproducible steps or a minimal proof of concept, and any
suggested remediation. Remove credentials, private repository contents, and
other unrelated personal data from the report.

Please allow time to investigate and coordinate a fix before public disclosure.
Do not publish exploit details, notify third parties, or test against systems
you do not own or have explicit permission to assess. A disclosure date and
credit can be coordinated through the private report. If active exploitation
or imminent user harm is suspected, say so clearly in the initial report.

## Scope

Security reports may cover the Lua plugin, sidecar, remote agent, signed build
registry and release tooling, SSH command construction, protocol parsing,
mirror and transactional-write integrity, path handling, cache trust, or a
project workflow that could expose protected signing material.

General defects, feature requests, unsupported configurations, social
engineering, denial of service requiring untrusted local code execution, and
vulnerabilities solely in third-party services or dependencies should use the
normal issue tracker unless they create a project-specific exploit path. For a
third-party dependency issue, identify how it is reachable through this
project and which supported version is affected.
