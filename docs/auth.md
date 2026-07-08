# Authentication — airlock.ing

## This site (airlock.ing)

The website is public and requires no authentication. Everyone is welcome,
humans and agents alike.

## The Airlock hosted registry (api.airlock.ing)

The hosted registry API is in **private beta**. It speaks:

- **OAuth 2.1** with `private_key_jwt` client authentication (RFC 7523)
- **Ed25519 signatures** over W3C `did:key` identifiers
- **RFC 8693 Token Exchange** for scoped delegation with cascade revocation

When the public API opens, standard discovery metadata will be served at:

- `https://api.airlock.ing/.well-known/oauth-authorization-server`
- `https://api.airlock.ing/.well-known/openid-configuration`

## Registering an agent

Early-access registration is human-in-the-loop today:

1. Request access at <https://airlock.ing/access/> (the form is also exposed
   as a WebMCP tool named `request_airlock_early_access`, so an agent may
   submit it on its user's behalf), or
2. Email <contact@airlock.ing>.

Self-serve agent registration (`POST /register` with a signed AgentProfile)
opens with the public API. The protocol itself is open source:
<https://github.com/airlock-protocol/airlock>.
