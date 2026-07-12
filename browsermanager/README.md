# Browser Manager plugin

Standalone MeshCentral plugin for authorized browser-extension enrollment, heartbeat, version inventory and policy management.

## Install

Copy the whole `browsermanager` directory to:

```text
meshcentral-data/plugins/browsermanager/
```

Result:

```text
meshcentral-data/plugins/browsermanager/config.json
meshcentral-data/plugins/browsermanager/browsermanager.js
```

Restart MeshCentral after copying the files.

## Admin endpoints

```text
GET  pluginadmin.ashx?api=bootstrap
GET  pluginadmin.ashx?api=devices
POST pluginadmin.ashx?api=create-enrollment
POST pluginadmin.ashx?api=revoke-enrollment
POST pluginadmin.ashx?api=set-policy
```

Only `siteadmin` users can call the admin endpoints.

## Heartbeat payload

The extension request handler accepts only POST requests with a short-lived enrollment bearer token and this metadata:

```json
{
  "extensionId": "abcdefghijklmnopabcdefghijklmnop",
  "installationId": "random-id-created-once-and-stored-locally",
  "extensionVersion": "1.0.0",
  "browserVersion": "Chrome/150.0.0.0",
  "platform": "Windows 11"
}
```

The plugin does not expose cookie, credential, clipboard, browsing-history, DOM, localStorage, screenshot or arbitrary-script collection.

## Storage

Runtime state is stored in `browsermanager/data/browsermanager.json`. Enrollment tokens are stored only as SHA-256 hashes. The plaintext token is returned once when an administrator creates an enrollment.
