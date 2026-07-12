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
  const onlineWindowMs = 2 * 60 * 1000;
  const maxBodyBytes = 64 * 1024;
  let writeQueue = Promise.resolve();

  const nowIso = () => new Date().toISOString();
  const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
  const tokenHash = (token) => crypto.createHash("sha256").update(String(token || ""), "utf8").digest("hex");
  const emptyState = () => ({ version: 1, enrollments: [], devices: [], audit: [] });

  function normalizeState(value) {
    const state = Object.assign(emptyState(), value && typeof value === "object" ? value : {});
    state.enrollments = Array.isArray(state.enrollments) ? state.enrollments : [];
    state.devices = Array.isArray(state.devices) ? state.devices : [];
    state.audit = Array.isArray(state.audit) ? state.audit : [];
    return state;
  }

  function loadState() {
    try {
      if (!fs.existsSync(statePath)) return emptyState();
      return normalizeState(JSON.parse(fs.readFileSync(statePath, "utf8")));
    } catch (error) {
      obj.debug("plugin:browsermanager", "state load failed", error);
      return emptyState();
    }
  }

  function saveState(state) {
    writeQueue = writeQueue.then(() => {
      fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
      const tempPath = `${statePath}.${process.pid}.tmp`;
      fs.writeFileSync(tempPath, JSON.stringify(normalizeState(state), null, 2) + "\n", { mode: 0o600 });
      fs.renameSync(tempPath, statePath);
    });
    return writeQueue;
  }

  function appendAudit(state, event, actor, details) {
    state.audit.unshift({ id: randomToken(12), at: nowIso(), event, actor, details: details || {} });
    state.audit = state.audit.slice(0, 1000);
  }

  function sendJson(res, status, payload) {
    res.status(status);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.send(JSON.stringify(payload));
  }

  function readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let raw = "";
      let done = false;

      const fail = (error) => {
        if (done) return;
        done = true;
        reject(error);
      };

      req.on("data", (chunk) => {
        if (done) return;
        raw += chunk;
        if (Buffer.byteLength(raw, "utf8") > maxBodyBytes) {
          fail(new Error("Request body too large"));
          if (typeof req.destroy === "function") req.destroy();
        }
      });

      req.on("end", () => {
        if (done) return;
        done = true;
        if (!raw) return resolve({});
        try {
          const parsed = JSON.parse(raw);
          resolve(parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {});
        } catch (_) {
          reject(new Error("Invalid JSON body"));
        }
      });
      req.on("error", fail);
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
    const match = /^Bearer\s+(.+)$/i.exec(header);
    return match ? match[1].trim() : "";
  }

  function safeText(value, maxLength) {
    return String(value || "").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, maxLength);
  }

  function validExtensionId(value) {
    return /^[a-p]{32}$/.test(value);
  }

  function findActiveEnrollment(state, token) {
    if (!token) return null;
    const hash = tokenHash(token);
    return state.enrollments.find((item) => {
      if (!item || item.revokedAt || item.tokenHash !== hash) return false;
      const expires = Date.parse(item.expiresAt || "");
      return Number.isFinite(expires) && expires > Date.now();
    }) || null;
  }

  function publicDevice(device) {
    const lastSeen = Date.parse(device.lastSeenAt || "");
    return Object.assign({}, device, {
      installationId: undefined,
      online: Number.isFinite(lastSeen) && Date.now() - lastSeen <= onlineWindowMs
    });
  }

  obj.server_startup = function () {
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    obj.debug("plugin:browsermanager", "plugin started");
  };

  obj.handleAdminReq = async function (req, res, user) {
    if (!requireAdmin(user, res)) return;
    const api = req.query && req.query.api;
    if (api !== "bootstrap" && api !== "devices") {
      sendJson(res, 404, { error: "Unknown API" });
      return;
    }

    const state = loadState();
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
  };

  obj.handleAdminPostReq = async function (req, res, user) {
    if (!requireAdmin(user, res)) return;

    try {
      const body = await readJsonBody(req);
      const state = loadState();
      const api = req.query && req.query.api;
      const actor = safeText(user.name || user._id || "siteadmin", 120);

      if (api === "create-enrollment") {
        const ttlHours = Math.max(1, Math.min(Math.trunc(Number(body.ttlHours) || 24), 168));
        const token = randomToken(32);
        const enrollment = {
          id: randomToken(12),
          tokenHash: tokenHash(token),
          domainId: safeText(body.domainId || user.domain || "", 128),
          label: safeText(body.label || "Extension enrollment", 120),
          createdAt: nowIso(),
          expiresAt: new Date(Date.now() + ttlHours * 3600000).toISOString(),
          revokedAt: null
        };
        state.enrollments.push(enrollment);
        appendAudit(state, "enrollment.created", actor, { enrollmentId: enrollment.id, domainId: enrollment.domainId });
        await saveState(state);
        sendJson(res, 201, { enrollmentId: enrollment.id, token, expiresAt: enrollment.expiresAt });
        return;
      }

      if (api === "revoke-enrollment") {
        const id = safeText(body.enrollmentId, 64);
        const enrollment = state.enrollments.find((item) => item.id === id);
        if (!enrollment) return sendJson(res, 404, { error: "Enrollment not found" });
        if (!enrollment.revokedAt) enrollment.revokedAt = nowIso();
        appendAudit(state, "enrollment.revoked", actor, { enrollmentId: enrollment.id });
        await saveState(state);
        sendJson(res, 200, { ok: true });
        return;
      }

      if (api === "set-policy") {
        const id = safeText(body.deviceId, 64);
        const device = state.devices.find((item) => item.id === id);
        if (!device) return sendJson(res, 404, { error: "Device not found" });
        device.policy = {
          updateChannel: ["stable", "beta"].includes(body.updateChannel) ? body.updateChannel : "stable",
          reportingEnabled: body.reportingEnabled !== false,
          updatedAt: nowIso()
        };
        appendAudit(state, "device.policy.updated", actor, { deviceId: device.id, policy: device.policy });
        await saveState(state);
        sendJson(res, 200, { ok: true, policy: device.policy });
        return;
      }

      sendJson(res, 404, { error: "Unknown API" });
    } catch (error) {
      sendJson(res, error.message === "Request body too large" ? 413 : 400, { error: error.message || "Bad request" });
    }
  };

  async function handleExtensionRequest(req, res) {
    try {
      if (String(req.method || "POST").toUpperCase() !== "POST") {
        return sendJson(res, 405, { error: "Method not allowed" });
      }

      const body = await readJsonBody(req);
      const state = loadState();
      const enrollment = findActiveEnrollment(state, bearerToken(req));
      if (!enrollment) return sendJson(res, 401, { error: "Invalid or expired enrollment token" });

      const extensionId = safeText(body.extensionId, 32);
      const installationId = safeText(body.installationId, 128);
      if (!validExtensionId(extensionId) || installationId.length < 16) {
        return sendJson(res, 400, { error: "Invalid extensionId or installationId" });
      }

      const id = tokenHash(`${enrollment.domainId}:${extensionId}:${installationId}`).slice(0, 32);
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
      device.extensionVersion = safeText(body.extensionVersion, 40);
      device.browserVersion = safeText(body.browserVersion, 80);
      device.platform = safeText(body.platform, 80);
      await saveState(state);
      sendJson(res, 200, { deviceId: id, serverTime: nowIso(), policy: device.policy });
    } catch (error) {
      sendJson(res, error.message === "Request body too large" ? 413 : 400, { error: error.message || "Bad request" });
    }
  }

  obj.handleRequest = handleExtensionRequest;
  obj.handleWebRequest = handleExtensionRequest;
  return obj;
};
