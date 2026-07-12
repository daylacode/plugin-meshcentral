# Browser Extension Manager

The standalone plugin is located in [`browsermanager/`](browsermanager/).

Install by copying the complete directory to:

```text
meshcentral-data/plugins/browsermanager/
```

Required files:

```text
meshcentral-data/plugins/browsermanager/config.json
meshcentral-data/plugins/browsermanager/browsermanager.js
```

Restart MeshCentral after installation. Detailed API, storage and heartbeat documentation is in [`browsermanager/README.md`](browsermanager/README.md).

The plugin supports authorized enrollment, heartbeat, version inventory, online/offline status, policy updates and audit logging. It does not provide cookie, credential, clipboard, browsing-history, DOM, localStorage, screenshot or arbitrary-script collection.
