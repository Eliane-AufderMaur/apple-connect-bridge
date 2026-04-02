// netlify/functions/apple.js
// Vollständige, funktionierende Version mit Debug & korrektem Parser

const crypto = require("crypto");
const zlib = require("zlib");

const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";
const MIN_DATE = "2025-06-20";

// ---------------------------
// Utility: JSON response
// ---------------------------
function json(statusCode, obj) {
  return {
    statusCode,
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(obj),
  };
}

function getEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable: ${name}`);
  return v;
}

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// ---------------------------
// JWT for Apple API
// ---------------------------
function makeJwt() {
  const ISSUER = getEnv("ASC_ISSUER_ID");
  const KEY_ID = getEnv("ASC_KEY_ID");

  let s = String(getEnv("ASC_PRIVATE_KEY")).trim();
  s = s.replace(/^"(.*)"$/s, "$1").replace(/^'(.*)'$/s, "$1");
  s = s.replace(/\\n/g, "\n");

  s = s
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");

  let keyObj;
  try {
    const der = Buffer.from(s, "base64");
    keyObj = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } catch (e) {
    throw new Error(
      `ASC_PRIVATE_KEY cannot be parsed. Must be Apple .p8 PKCS#8. Details: ${e.message}`
    );
  }

  const header = { alg: "ES256", kid: KEY_ID, typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISSUER,
    iat: now,
    exp: now + 10 * 60,
    aud: "appstoreconnect-v1",
  };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(
    JSON.stringify(payload)
  )}`;

  const sig = crypto.sign("sha256", Buffer.from(unsigned), {
    key: keyObj,
    dsaEncoding: "ieee-p1363",
  });

  return `${unsigned}.${base64url(sig)}`;
}

// ---------------------------
// GZIP decompress
// ---------------------------
function gunzipAsync(buffer) {
  return new Promise((resolve, reject) => {
    zlib.gunzip(buffer, (err, out) => (err ? reject(err) : resolve(out)));
  });
}

// ---------------------------
// Parser: INSTALLS / DELETES
// ---------------------------
function parseTxtGzToTotals(txt, options = {}) {
  const { excludeUpdates = false } = options;

  const lines = txt.split("\n").filter(Boolean);
  if (lines.length < 2)
    return { installs: 0, uninstalls: 0, downloadTypeStats: {} };

  const header = lines[0].split("\t").map((s) => s.trim());
  const headerLc = header.map((s) => s.toLowerCase());
  const idx = (name) => headerLc.indexOf(String(name).toLowerCase());

  const eventCol = idx("event");
  const countsCol = headerLc.includes("counts") ? idx("counts") : idx("count");
  const downloadTypeCol = idx("download type");

  if (eventCol < 0 || countsCol < 0) {
    return {
      installs: 0,
      uninstalls: 0,
      downloadTypeStats: { _error: "missing event/counts column" },
    };
  }

  let installs = 0,
    uninstalls = 0;
  const downloadTypeStats = {};

  for (let i = 1; i < lines.length; i++) {
    const parts = lines[i].split("\t");

    const ev = (parts[eventCol] || "").toLowerCase();
    const c = Number(parts[countsCol] || 0);

    const dt =
      downloadTypeCol >= 0 ? String(parts[downloadTypeCol] || "").trim() : "";
    if (dt) downloadTypeStats[dt] = (downloadTypeStats[dt] || 0) + c;

    // Updates rausfiltern falls gewünscht
    if (excludeUpdates && dt.toLowerCase().includes("update")) continue;

    if (ev.includes("install")) installs += c;
    if (ev.includes("delete")) uninstalls += c;
  }

  return { installs, uninstalls, downloadTypeStats };
}

// ---------------------------
// Fetch JSON + Debug
// ---------------------------
async function ascFetchJson(url, jwt, debugCalls, options = {}) {
  const res = await fetch(url, {
    method: options.method || "GET",
    headers: {
      Authorization: `Bearer ${jwt}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const text = await res.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (debugCalls) {
    debugCalls.push({
      url,
      status: res.status,
      ok: res.ok,
      bodyPreview: String(text).slice(0, 800),
    });
  }

  if (!res.ok) {
    throw new Error(
      `ASC HTTP ${res.status} for ${url}: ${String(text).slice(0, 800)}`
    );
  }

  if (data?.errors?.length) {
    throw new Error(
      `ASC errors for ${url}: ${JSON.stringify(data.errors).slice(0, 800)}`
    );
  }

  return data;
}

// ---------------------------
// Report Picker
// ---------------------------
function pickInstDelReportId(reportsJson) {
  const data = reportsJson?.data || [];
  const nameLc = (s) => (s || "").toLowerCase();
  const candidates = data.filter((r) =>
    nameLc(r.attributes?.name).includes("installation and deletion")
  );
  return candidates[0]?.id || null;
}

// ---------------------------
// MAIN HANDLER
// ---------------------------
exports.handler = async (event) => {
  const qs = event.queryStringParameters || {};
  const date = qs.date;
  const appId = qs.appId;
  const debug = qs.debug === "1";
  const excludeUpdates = qs.excludeUpdates === "1";
  const debugCalls = debug ? [] : null;

  if (!date || !appId) {
    return json(400, { error: "Missing query params: date, appId" });
  }

  if (date < MIN_DATE) {
    return json(200, {
      date,
      installs: 0,
      uninstalls: 0,
      note: "before MIN_DATE",
    });
  }

  try {
    const jwt = makeJwt();

    // ---------------------------------------------------------
    // 1) ONGOING REQUEST
    // ---------------------------------------------------------
    const ongoingList = await ascFetchJson(
      `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONGOING`,
      jwt,
      debugCalls
    );

    let ongoingRequestId = ongoingList?.data?.[0]?.id;

    if (!ongoingRequestId) {
      const created = await ascFetchJson(
        `${ASC_BASE}/analyticsReportRequests`,
        jwt,
        debugCalls,
        {
          method: "POST",
          body: {
            data: {
              type: "analyticsReportRequests",
              attributes: { accessType: "ONGOING" },
              relationships: { app: { data: { type: "apps", id: appId } } },
            },
          },
        }
      );
      ongoingRequestId = created?.data?.id;
    }

    // Reports für ONGOING
    let ongoingReportId = null;
    if (ongoingRequestId) {
      const ongoingReports = await ascFetchJson(
        `${ASC_BASE}/analyticsReportRequests/${ongoingRequestId}/reports?filter[category]=APP_USAGE`,
        jwt,
        debugCalls
      );
      ongoingReportId = pickInstDelReportId(ongoingReports);
    }

    // ---------------------------------------------------------
    // 2) Versuche ONGOING INSTANCE
    // ---------------------------------------------------------
    if (ongoingReportId) {
      const instances = await ascFetchJson(
        `${ASC_BASE}/analyticsReports/${ongoingReportId}/instances?filter[processingDate]=${date}&filter[granularity]=DAILY`,
        jwt,
        debugCalls
      );

      const instance = instances?.data?.[0];

      if (instance) {
        const segments = await ascFetchJson(
          `${ASC_BASE}/analyticsReportInstances/${instance.id}/segments`,
          jwt,
          debugCalls
        );

        let installs = 0,
          uninstalls = 0;

        for (const seg of segments.data || []) {
          const ab = await fetch(seg.attributes.url).then((r) => r.arrayBuffer());
          const gzBuf = Buffer.from(ab);
          const txtBuf = await gunzipAsync(gzBuf);
          const txt = txtBuf.toString("utf-8");

          const totals = parseTxtGzToTotals(txt, { excludeUpdates });

          installs += totals.installs;
          uninstalls += totals.uninstalls;

          // Sample output
          if (debug && !globalThis.__sampleShown) {
            globalThis.__sampleShown = true;
            debugCalls.push({
              sampleLines: txt.split("\n").slice(0, 5),
            });
          }
        }

        return json(200, {
          date,
          installs,
          uninstalls,
          source: "ongoing",
          ...(debug ? { debugCalls } : {}),
        });
      }
    }

    // ---------------------------------------------------------
    // 3) SNAPSHOT FALLBACK
    // ---------------------------------------------------------
    const snapshotList = await ascFetchJson(
      `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONE_TIME_SNAPSHOT`,
      jwt,
      debugCalls
    );

    let snapshotRequestId = snapshotList?.data?.[0]?.id;

    if (!snapshotRequestId) {
      const created = await ascFetchJson(
        `${ASC_BASE}/analyticsReportRequests`,
        jwt,
        debugCalls,
        {
          method: "POST",
          body: {
            data: {
              type: "analyticsReportRequests",
              attributes: { accessType: "ONE_TIME_SNAPSHOT" },
              relationships: { app: { data: { type: "apps", id: appId } } },
            },
          },
        }
      );
      snapshotRequestId = created?.data?.id;
    }

    const snapReports = await ascFetchJson(
      `${ASC_BASE}/analyticsReportRequests/${snapshotRequestId}/reports?filter[category]=APP_USAGE`,
      jwt,
      debugCalls
    );

    const snapReportId = pickInstDelReportId(snapReports);

    const snapInstances = await ascFetchJson(
      `${ASC_BASE}/analyticsReports/${snapReportId}/instances?filter[processingDate]=${date}&filter[granularity]=DAILY`,
      jwt,
      debugCalls
    );

    const snapInstance = snapInstances?.data?.[0];

    if (!snapInstance) {
      return json(200, {
        date,
        installs: 0,
        uninstalls: 0,
        note: "snapshot-no-instance",
        ...(debug ? { debugCalls } : {}),
      });
    }

    const snapSegments = await ascFetchJson(
      `${ASC_BASE}/analyticsReportInstances/${snapInstance.id}/segments`,
      jwt,
      debugCalls
    );

    let installs = 0,
      uninstalls = 0;

    for (const seg of snapSegments.data || []) {
      const ab = await fetch(seg.attributes.url).then((r) => r.arrayBuffer());
      const gzBuf = Buffer.from(ab);
      const txtBuf = await gunzipAsync(gzBuf);
      const txt = txtBuf.toString("utf-8");

      const totals = parseTxtGzToTotals(txt, { excludeUpdates });

      installs += totals.installs;
      uninstalls += totals.uninstalls;

      if (debug && !globalThis.__sampleShown) {
        globalThis.__sampleShown = true;
        debugCalls.push({
          sampleLines: txt.split("\n").slice(0, 5),
        });
      }
    }

    return json(200, {
      date,
      installs,
      uninstalls,
      source: "snapshot",
      ...(debug ? { debugCalls } : {}),
    });
  } catch (err) {
    return json(500, { error: err.message, ...(debug ? { debugCalls } : {}) });
  }
};
