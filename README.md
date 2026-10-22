# Caddy Session to JWT
Een Caddy v2-module die op gematchte paden een sessie omzet in een JWT en die als
`Authorization: Bearer <jwt>` naar upstream (Hasura) stuurt. De JWT wordt opgehaald bij
een token-endpoint (proxy-jwt) en in-memory gecachet.

Er zijn twee paden:

- **Cookie-pad (browser):** de better-auth sessie-cookie wordt ingeruild voor een JWT.
  Fail-open: lukt dat niet, dan gaat de request zonder JWT door (Hasura valt terug op de
  unauthorized-role).
- **Bearer-pad (native apps, "phantom token"):** de app stuurt
  `Authorization: Bearer <app-token>`. Het app-token wordt ingeruild voor een JWT (met
  de thuisorganisatie van de gebruiker; er is geen organisatiekeuze per verzoek).
  Fail-closed: zonder verse JWT gaat er niets naar upstream, en
  het app-token bereikt upstream nooit.

## Installation

`xcaddy build --with github.com/GetThePointGit/caddy-session-to-jwt`

## Configuration

```text
{
  order session_to_jwt before reverse_proxy
  order session_to_jwt_evict before reverse_proxy
}

:80 {
  # Intern endpoint (niet via de publieke ingress exposen!)
  handle /internal/auth-evict {
    session_to_jwt_evict {
      shared_secret "geheim"
      cookie_name better-auth.session_token   # optioneel (default)
    }
  }

  handle /v1/* {
    session_to_jwt {
      jwt_url http://web:3000/api/auth/proxy-jwt
      shared_secret "geheim"                  # gaat als x-proxy-secret naar jwt_url
      cookie_name better-auth.session_token   # optioneel (default)
      cache_ttl_seconds 300                   # optioneel (default 300)
    }
    reverse_proxy hasura:8080
  }
}
```

De cache-TTL is `min(cache_ttl_seconds, tijd tot exp)` en geldt voor beide paden.

## Gedrag per request

| Request                                         | Resultaat |
|-------------------------------------------------|-----------|
| Websocket-upgrade                               | Geen JWT-injectie (waterworks#287); een meegestuurde `Authorization` wordt gestript. |
| Sessie-cookie **én** `Authorization`            | `400 {"error":"ambiguous_credentials"}`, niet geproxied. |
| Alleen sessie-cookie                            | Cookie-pad (ongewijzigd, fail-open). |
| Alleen `Authorization: Bearer <x>`              | Bearer-pad (zie hieronder). |
| Alleen `Authorization` met ander scheme (Basic, leeg, meerdere headers) | `401 {"error":"invalid_session"}`. |
| Geen cookie en geen `Authorization`             | Doorlaten zonder JWT (ongewijzigd). |

Een door de client meegestuurde `Authorization` gaat dus nooit ongewijzigd naar upstream:
hij wordt omgezet in een JWT of de request wordt geweigerd.

### Bearer-pad

1. Cache-key `bearer:<x>`, los van de cookie-keys. Een meegestuurde `X-Wit-Org` wordt
   genegeerd en niet doorgestuurd.
2. Bij een cache-miss: `POST jwt_url` met `x-proxy-secret` en `Authorization: Bearer <x>`.
   Géén cookie. Time-out 10s.
3. Response van het token-endpoint:

| Token-endpoint                                   | Antwoord van de proxy |
|--------------------------------------------------|-----------------------|
| `200 {"token","exp"}`                            | cachen, `Authorization: Bearer <jwt>` zetten (overschrijft het app-token), door naar upstream |
| `401`                                            | `401 {"error":"invalid_session"}` |
| al het andere (overige 4xx, ook 403 door een fout secret, 5xx, time-out, netwerkfout, ongeldige JSON) | `503 {"error":"auth_unavailable"}` |

Foutantwoorden hebben `Content-Type: application/json`. Negatieve resultaten worden niet
gecachet. Tokens, `Authorization` en cookies worden nooit gelogd.

## Evict (uitloggen)

`session_to_jwt_evict` verwijdert gecachte JWT's; vereist de header `x-proxy-secret`
(anders `403`). Antwoordt altijd `204` (idempotent).

- Met de sessie-cookie: verwijdert de JWT van die cookie (ongewijzigd).
- Met `Authorization: Bearer <x>`: verwijdert de entry `bearer:<x>`.

## compile with custom caddy plugin locally for development

1. installeer go
2. installeer `xcaddy`, zie binaries op https://github.com/caddyserver/xcaddy/releases
3. build with command `./xcaddy build --with github.com/GetThePointGit/caddy-session-to-jwt=./`

4. run caddy with `./caddy run`

Tests: `go vet ./... && go test ./...`

## Changelog

### v1.4.0
- Bearer-pad ("phantom token") voor de native apps: `Authorization: Bearer <app-token>`
  wordt bij het token-endpoint ingeruild voor een JWT. Fail-closed met JSON-foutbodies
  (`invalid_session`, `auth_unavailable`).
- Cookie én `Authorization` tegelijk: `400 {"error":"ambiguous_credentials"}`.
- **Gedragswijziging:** een door de client meegestuurde `Authorization` werd voorheen zonder
  sessie-cookie (en bij een mislukte cookie-inruil, en op websocket-upgrades) ongewijzigd naar
  upstream doorgestuurd. Nu wordt die omgezet in een JWT of geweigerd, en op
  websocket-upgrades gestript.
- Evict accepteert `Authorization: Bearer <x>` en verwijdert de JWT van dat token.
- Cookie-pad verder ongewijzigd.
