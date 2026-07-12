"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

module.exports.browsermanager = function (parent) {
  const obj = {};
  obj.parent = parent;
  obj.meshServer = parent.parent;
  obj.debug = obj.meshServer.debug;

  const stateDir = path.join(__dirname, "data");
  const statePath = path.join(stateDir, "browsermanager.json");
  const ONLINE_WINDOW_MS = 2 * 60 * 1000;

  function nowIso() {
    return new Date().toISOString();
  }

  function randomToken(bytes) {
    return crypto.randomBytes(bytes || 32).toString("base64url");
  }

  function tokenHash(token) {
    return crypto.createHash("sha256").update(String(token || ""), "utf8").digest("hex");
  }

  function emptyState() {
    return { version: 1, enrollments: [], devices: [], audit: [] };
  }

  function loadState() {
    try {
      if (!fs.existsSync(statePath)) return emptyState();
      const parsed = JSON.parse(fs.readFileSync(statePath, "utf8"));
      return Object.assign(emptyState(), parsed || {});
    } catch (error) {
      obj.debug("plugin:browsermanager", "state load failed", error);
      return emptyState();
    }
  }

  function saveState(state) {
    fs.mkdirSync(stateDir, { recursive: true });
    const tempPath = statePath + ".tmp";
    fs.writeFileSync(tempPath, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
    fs.renameSync(tempPath, statePath);
  }

  function appendAudit(state, event, actor, details) {
    state.audit.unshift({ id: randomToken(12), at: nowIso(), event, actor, details: details || {} });
    state.audit = state.audit.slice(0, 1000);
  }

  function sendJson(res, status, payload) {
    res.status(status);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.send(JSON.stringify(payload));
  }

  function readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
        if (raw.length > 1024 * 1024) reject(new Error("Request body too large"));
      });
      req.on("end", () => {
        if (!raw) return resolve({});
        try { resolve(JSON.parse(raw)); } catch (_) { reject(new Error("Invalid JSON body")); }
      });
      req.on("error", reject);
    });
  }

  function requireAdmin(user, res) {
    if (!user || !user.siteadmin) {
      sendJson(res, 403, { error: "Forbidden" });
      return false;
    }
    return true;
  }

  function bearerToken(req) {
    const header = String((req.headers && req.headers.authorization) || "");
    return header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  }

  function findActiveEnrollment(state, token) {
    const hash = tokenHash(token);
    return state.enrollments.find((item) => item.tokenHash === hash && !item.revokedAt && (!item.expiresAt || Date.parse(item.expiresAt) > Date.now()));
  }

  function publicDevice(device) {
    const lastSeenMs = Date.parse(device.lastSeenAt || 0);
    return Object.assign({}, device, { online: Number.isFinite(lastSeenMs) && Date.now() - lastSeenMs <= ONLINE_WINDOW_MS });
  }

  obj.server_startup = function () {
    fs.mkdirSync(stateDir, { recursive: true });
    obj.debug("plugin:browsermanager", "plugin started");
  };

  obj.handleAdminReq = async function (req, res, user) {
    if (!requireAdmin(user, res)) return;
    const state = loadState();
    const api = req.query && req.query.api;

    if (api === "bootstrap" || api === "devices") {
      sendJson(res, 200, {
        devices: state.devices.map(publicDevice),
        enrollments: state.enrollments.map((item) => ({
          id: item.id,
          domainId: item.domainId,
          label: item.label,
          createdAt: item.createdAt,
          expiresAt: item.expiresAt,
          revokedAt: item.revokedAt || null
        })),
        audit: state.audit.slice(0, 200)
      });
      return;
    }

    sendJson(res, 200, {
      name: "Browser Extension Manager",
      description: "Authorized extension enrollment, heartbeat and policy status. Sensitive browser data collection is intentionally unsupported."
    });
  };

  obj.handleAdminPostReq = async function (req, res, user) {
    if (!requireAdmin(user, res)) return;

    try {
      const body = await readJsonBody(req);
      const state = loadState();
      const api = req.query && req.query.api;
      const actor = user.name || user._id || "siteadmin";

      if (api === "create-enrollment") {
        const token = randomToken(32);
        const ttlHours = Math.max(1, Math.min(Number(body.ttlHours) || 24, 168));
        const enrollment = {
          id: randomToken(12),
          tokenHash: tokenHash(token),
          domainId: String(body.domainId || user.domain || ""),
          label: String(body.label || "Extension enrollment").slice(0, 120),
          createdAt: nowIso(),
          expiresAt: new Date(Date.now() + ttlHours * 3600000).toISOString(),
          revokedAt: null
        };
        state.enrollments.push(enrollment);
        appendAudit(state, "enrollment.created", actor, { enrollmentId: enrollment.id, domainId: enrollment.domainId });
        saveState(state);
        sendJson(res, 201, { enrollmentId: enrollment.id, token, expiresAt: enrollment.expiresAt });
        return;
      }

      if (api === "revoke-enrollment") {
        const enrollment = state.enrollments.find((item) => item.id === String(body.enrollmentId || ""));
        if (!enrollment) return sendJson(res, 404, { error: "Enrollment not found" });
        enrollment.revokedAt = nowIso();
        appendAudit(state, "enrollment.revoked", actor, { enrollmentId: enrollment.id });
        saveState(state);
        sendJson(res, 200, { ok: true });
        return;
      }

      if (api === "set-policy") {
        const device = state.devices.find((item) => item.id === String(body.deviceId || ""));
        if (!device) return sendJson(res, 404, { error: "Device not found" });
        device.policy = {
          updateChannel: ["stable", "beta"].includes(body.updateChannel) ? body.updateChannel : "stable",
          reportingEnabled: body.reportingEnabled !== false,
          updatedAt: nowIso()
        };
        appendAudit(state, "device.policy.updated", actor, { deviceId: device.id, policy: device.policy });
        saveState(state);
        sendJson(res, 200, { ok: true, policy: device.policy });
        return;
      }

      sendJson(res, 404, { error: "Unknown API" });
    } catch (error) {
      sendJson(res, 400, { error: error.message || "Bad request" });
    }
  };

  async function handleExtensionRequest(req, res) {
    try {
      const body = await readJsonBody(req);
      const token = bearerToken(req);
      const state = loadState();
      const enrollment = findActiveEnrollment(state, token);
      if (!enrollment) return sendJson(res, 401, { error: "Invalid or expired enrollment token" });

      const extensionId = String(body.extensionId || "").trim();
      const installationId = String(body.installationId || "").trim();
      if (!extensionId || !installationId) return sendJson(res, 400, { error: "extensionId and installationId are required" });

      const id = tokenHash(enrollment.domainId + ":" + extensionId + ":" + installationId).slice(0, 32);
      let device = state.devices.find((item) => item.id === id);
      if (!device) {
        device = {
          id,
          domainId: enrollment.domainId,
          extensionId,
          installationId,
          enrolledAt: nowIso(),
          policy: { updateChannel: "stable", reportingEnabled: true, updatedAt: nowIso() }
        };
        state.devices.push(device);
        appendAudit(state, "device.enrolled", "extension", { deviceId: id, domainId: enrollment.domainId });
      }

      device.lastSeenAt = nowIso();
      device.extensionVersion = String(body.extensionVersion || "").slice(0, 40);
      device.browserVersion = String(body.browserVersion || "").slice(0, 80);
      device.platform = String(body.platform || "").slice(0, 80);
      saveState(state);
      sendJson(res, 200, { deviceId: id, serverTime: nowIso(), policy: device.policy });
    } catch (error) {
      sendJson(res, 400, { error: error.message || "Bad request" });
    }
  }

  // Exposed under both names for compatibility with MeshCentral plugin hosts.
  obj.handleRequest = handleExtensionRequest;
  obj.handleWebRequest = handleExtensionRequest;

  return obj;
};
