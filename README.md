# Caddy Session to JWT
A Caddy v2 module that converts sessionID form a cookie to a JWT token. This JWT token can be used to authenticate the user in the backend.
The JWT token is fetched from a Redis store and/or from a http request to a backend server (and then stored in Redis).



Redis code based on: https://github.com/pberkel/caddy-storage-redis



## Installation

`xcaddy build --with github.com/GetThePointGit/caddy-session-to-jwt`

## Configuration

todo:

```text

<site> {
    sessiontojwt {
        ...
    }
    ...
}

```

## compile with custom caddy plugin locally for development

1. installeer go
2. installeer `xcaddy`, zie binaries op https://github.com/caddyserver/xcaddy/releases
3. build with command `./xcaddy build --with github.com/GetThePointGit/caddy-session_to_jwt=./`

4. run caddy with `./caddy run`


