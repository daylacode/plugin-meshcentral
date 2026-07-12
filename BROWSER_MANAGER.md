# Browser Extension Manager

This repository now includes `browsermanager.js`, a separate MeshCentral plugin backend for authorized browser-extension fleet management.

## Supported capabilities

- Short-lived enrollment tokens (1-168 hours)
- Extension installation registration
- Heartbeat and online/offline state
- Extension/browser/platform version inventory
- Per-device update channel and reporting policy
- Administrative audit log

The backend intentionally does not implement cookie, credential, clipboard, browsing-history, DOM, localStorage, screenshot or arbitrary-script collection.

## Installation

Copy these two files into a MeshCentral plugin directory named `browsermanager`:

```text
meshcentral-data/plugins/browsermanager/browsermanager.js
meshcentral-data/plugins/browsermanager/config.json
```

Use `browsermanager.config.json` from this repository as the destination `config.json`.

Restart MeshCentral after installing or updating the plugin.

## Storage

Runtime state is stored at:

```text
plugins/browsermanager/data/browsermanager.json
```

The file is written atomically and created with owner-only permissions where supported. Enrollment bearer tokens are never stored directly; only SHA-256 hashes are persisted.

## Admin API

The plugin uses the standard MeshCentral admin plugin request handlers.

### Read status

```text
GET pluginadmin.ashx?api=bootstrap
GET pluginadmin.ashx?api=devices
```

Only users with `siteadmin` access are accepted.

### Create an enrollment token

```http
POST pluginadmin.ashx?api=create-enrollment
Content-Type: application/json

{
  "domainId": "",
  "label": "Chrome production",
  "ttlHours": 24
}
```

The returned plaintext token is shown once. Store it in the managed extension configuration and rotate/revoke it after enrollment.

### Revoke an enrollment token

```http
POST pluginadmin.ashx?api=revoke-enrollment
Content-Type: application/json

{
  "enrollmentId": "..."
}
```

### Set device policy

```http
POST pluginadmin.ashx?api=set-policy
Content-Type: application/json

{
  "deviceId": "...",
  "updateChannel": "stable",
  "reportingEnabled": true
}
```

## Extension heartbeat payload

Bind the MeshCentral plugin web-request callback according to the installed MeshCentral version, then send:

```http
POST <browsermanager extension endpoint>
Authorization: Bearer <enrollment-token>
Content-Type: application/json

{
  "extensionId": "abcdefghijklmnopabcdefghijklmnop",
  "installationId": "locally-generated-random-id",
  "extensionVersion": "1.0.0",
  "browserVersion": "Chrome/150.0.0.0",
  "platform": "Windows 11"
}
```

Response:

```json
{
  "deviceId": "...",
  "serverTime": "2026-07-13T00:00:00.000Z",
  "policy": {
    "updateChannel": "stable",
    "reportingEnabled": true,
    "updatedAt": "2026-07-13T00:00:00.000Z"
  }
}
```

Generate `installationId` once with `crypto.randomUUID()` and persist it in `chrome.storage.local`. Do not use a machine fingerprint or collect unrelated browser data.
