# Browser Manager plugin

Standalone MeshCentral plugin for authorized browser-extension enrollment, public heartbeat, version inventory and policy management.

## Install

Copy the whole `browsermanager` directory to:

```text
meshcentral-data/plugins/browsermanager/
```

Restart MeshCentral. The plugin starts a local HTTP listener on `127.0.0.1:8787` by default.

## MeshCentral config

Optional settings inside `settings.plugins.browsermanager`:

```json
{
  "publicEndpointEnabled": true,
  "listenHost": "127.0.0.1",
  "listenPort": 8787,
  "heartbeatPath": "/heartbeat",
  "healthPath": "/health"
}
```

Environment alternatives:

```text
BROWSERMANAGER_HOST=127.0.0.1
BROWSERMANAGER_PORT=8787
```

## Reverse proxy for appgologin.duckdns.org

Add these locations to the HTTPS Nginx server block for `appgologin.duckdns.org`:

```nginx
location = /browsermanager/health {
    proxy_pass http://127.0.0.1:8787/health;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location = /browsermanager/heartbeat {
    proxy_pass http://127.0.0.1:8787/heartbeat;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-BrowserManager-Token $http_x_browsermanager_token;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 64k;
}
```

Reload Nginx:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Do not send heartbeat requests to `pluginadmin.ashx`; that endpoint requires a logged-in MeshCentral session and returns `Unauthorized` otherwise.

## Test public endpoint

Health check:

```bash
curl -i https://appgologin.duckdns.org/browsermanager/health
```

Expected response:

```json
{"ok":true,"service":"browsermanager"}
```

Heartbeat using the dedicated header, which is recommended behind reverse proxies:

```bash
curl -i -X POST https://appgologin.duckdns.org/browsermanager/heartbeat \
  -H "Content-Type: application/json" \
  -H "X-BrowserManager-Token: YOUR_ENROLLMENT_TOKEN" \
  --data '{
    "extensionId":"abcdefghijklmnopabcdefghijklmnop",
    "installationId":"random-id-at-least-16-characters",
    "extensionVersion":"1.0.0",
    "browserVersion":"Chrome/150.0.0.0",
    "platform":"Windows 11"
  }'
```

Bearer authentication is also accepted:

```text
Authorization: Bearer YOUR_ENROLLMENT_TOKEN
```

A missing token returns `Missing token`. A token that is unknown, revoked or expired returns `Invalid, revoked or expired enrollment token`.

## Admin endpoints

These require a logged-in MeshCentral `siteadmin` session:

```text
GET  pluginadmin.ashx?api=bootstrap
GET  pluginadmin.ashx?api=devices
POST pluginadmin.ashx?api=create-enrollment
POST pluginadmin.ashx?api=revoke-enrollment
POST pluginadmin.ashx?api=set-policy
```

## Storage

Runtime state is stored in `browsermanager/data/browsermanager.json`. Enrollment tokens are stored only as SHA-256 hashes. The plaintext token is returned once when an administrator creates an enrollment.

The plugin does not expose cookie, credential, clipboard, browsing-history, DOM, localStorage, screenshot or arbitrary-script collection.
