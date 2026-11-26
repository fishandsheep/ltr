# Security policy

## Scope and threat model

LTR forwards arbitrary TCP bytes. TLS is the default on both ends, but `--no-tls` (for relays without TLS, set explicitly on both ends) sends tunnel payloads in plaintext, so anyone able to observe the network can read or alter them unless tunnel TLS or an external secure network is used. HMAC authentication proves knowledge of the shared Secret during the control handshake; it does not encrypt payloads.

The Web console is a separate administrative surface. Local Web mode binds to loopback by default. Remote Web mode uses HTTPS before traffic enters the tunnel and requires a separate bearer token for every `/api/*` request.

## Secure deployment

- Set a strong secret on both server and clients via `LTR_SECRET` or `ltr conf set secret` (secrets are not accepted as command-line flags, since argv is visible to other local users).
- Bind control and tunnel listeners only to intended interfaces.
- Use tunnel TLS with an explicit CA or pinned certificate fingerprint when payload confidentiality is required.
- In remote Web mode, keep the bearer token private and prefer an explicit PEM certificate/key for production.
- Do not expose unauthenticated local Web mode on a public interface.
- Never paste secrets or tokens into issue reports or logs.

LTR does not collect telemetry, analytics, or crash reports.

## Reporting a vulnerability

Please do not open a public issue for an undisclosed vulnerability. Use the repository's GitHub Security Advisories contact path at:

https://github.com/fishandsheep/ltr/security/advisories/new

Include a concise impact statement, affected version/commit, reproduction steps, and any proposed mitigation. We will acknowledge valid reports and coordinate disclosure after a fix is available.
