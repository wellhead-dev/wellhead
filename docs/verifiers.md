# Verifiers

A check runs before `wellhead seed` writes anything, and on present values with
`wellhead missing --verify`. It concludes **accepted**, **rejected**, or **unknown** (rate limited,
5xx, network error, or a kind this release does not implement). Rejected writes nothing. Unknown asks
the person whether to write anyway, and writes nothing when no one can answer. A check never prints a
value, and only calls `https://` URLs.

Parameters are annotations named `wellhead.dev/verify.<kind>.<param>`.

| Kind | What it proves | Fields | Parameters |
| --- | --- | --- | --- |
| `none` | Nothing: a reviewed exception | | |
| `http` | A URL answers the expected status with credentials from the fields | named in `auth` | `url` (required), `method` (GET), `auth`: `bearer:<field>`, `basic:<user-field>:<password-field>` or `header:<Name>:<field>`, `status`: accepted codes (200) |
| `format` | Each named field matches a regular expression, anchored | the parameter names | `<field>`: an RE2 expression |
| `github-app` | The private key signs a JWT GitHub accepts for the app, the installation is that app's and not suspended, holds the permissions and covers the repositories | `app_id`, `installation_id`, `private_key` | `api`, `permissions` (`contents:write issues:read`), `repositories` (`owner/name ...`), `app-id-field`, `installation-id-field`, `private-key-field` |
| `github-token` | `GET /user` accepts the token; reads its expiry header | `token` | `api`, `field`, `scopes` (classic tokens) |
| `gitlab-token` | The token is active and has the scopes; reads its expiry | `token` | `api` (https://gitlab.com), `field`, `scopes` |
| `slack-bot-token` | `auth.test` accepts the token and `x-oauth-scopes` holds the scopes | `token` | `api`, `field`, `scopes` |
| `cloudflare-token` | `tokens/verify` says active; reads its expiry | `token` | `api`, `field` |

`github-app` with `repositories` on an installation limited to selected repositories mints an
installation token to list them and revokes it straight after.

When a check reports an expiry, `seed` stores it as the `expires` custom metadata of the vault path and
warns when it is less than 14 days away. Without one, `wellhead.dev/expires` or `wellhead.dev/lifetime`
sets it.

## Example: a GitHub App

```yaml
metadata:
  annotations:
    wellhead.dev/origin: provided
    wellhead.dev/how: >-
      GitHub organisation settings, Developer settings, GitHub Apps, the app: copy the App ID,
      generate a private key, and copy the installation id from the installation's URL.
    wellhead.dev/fields: app_id installation_id private_key
    wellhead.dev/plain: app_id installation_id
    wellhead.dev/verify: github-app
    wellhead.dev/verify.github-app.permissions: contents:read pull_requests:write
    wellhead.dev/verify.github-app.repositories: example/app
```

```sh
wellhead seed apps/github-app private_key=@./app.private-key.pem
```
