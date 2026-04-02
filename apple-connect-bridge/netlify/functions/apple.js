// netlify/functions/apple.js
// CommonJS Netlify Function (exports.handler) + Debug/Error Handling

const crypto = require("crypto");
const zlib = require("zlib");

const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";
const MIN_DATE = "2025-06-20";

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

// ES256 JWT for Apple API (sign as ieee-p1363 => JOSE-compatible raw signature)
function makeJwt() {
  const ISSUER = getEnv("ASC_ISSUER_ID");
  const KEY_ID = getEnv("ASC_KEY_ID");

  // Netlify env vars often store newlines as \n
  const PRIVATE_KEY = getEnv("ASC_PRIVATE_KEY").replace(/\\n/g, "\n");

  const header = { alg: "ES256", kid: KEY_ID, typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISSUER,
    iat: now,
    exp: now + 10 * 60,
    aud: "appstoreconnect-v1",
  };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;

  const sig = crypto.sign("sha256", Buffer.from(unsigned), {
    key: PRIVATE_KEY,
    dsaEncoding: "ieee-p1363",
  });

  return `${unsigned}.${base64url(sig)}`;
}

function gunzipAsync(buffer) {
  return new Promise((resolve, reject) => {
    zlib.gunzip(buffer, (err, out) => (err ? reject(err) : resolve(out)));
  });
}

// Extract installs + deletions
function parseTxtGzToTotals(txt) {
  const lines = txt.split("\n").filter(Boolean);
  if (lines.length < 2) return { installs: 0, uninstalls: 0 };

  const header = lines[0].split("\t").map((s) => s.toLowerCase());
  const eventCol = header.indexOf("event");
  const countCol = header.indexOf("count");

  let installs = 0,
    uninstalls = 0;

  for (let i = 1; i < lines.length; i++) {
    const parts = lines[i].split("\t");
    const ev = (parts[eventCol] || "").toLowerCase();
    const c = Number(parts[countCol] || 0);

    if (ev.includes("install")) installs += c;
    if (ev.includes("delete")) uninstalls += c;
  }

  return { installs, uninstalls };
}

// Pick correct Installation/Deletion report
function pickInstDelReportId(reportsJson, preferDetailed = false) {
  const data = reportsJson?.data || [];
  const nameLc = (str) => (str || "").toLowerCase();

  const candidates = data.filter((r) =>
    nameLc(r.attributes?.name).includes("app store installation and deletion")
  );

  if (!candidates.length) return null;

  const typeToFind = preferDetailed ? "detailed" : "standard";
  const preferred = candidates.find((r) => nameLc(r.attributes?.name).includes(typeToFind));

  return (preferred || candidates[0]).id;
}

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
    throw new Error(`ASC HTTP ${res.status} for ${url}: ${String(text).slice(0, 800)}`);
  }
  if (data?.errors?.length) {
    throw new Error(`ASC errors for ${url}: ${JSON.stringify(data.errors).slice(0, 800)}`);
  }

  return data;
}

exports.handler = async (event) => {
  const qs = event.queryStringParameters || {};
  const date = qs.date;
  const appId = qs.appId;
  const debug = qs.debug === "1";
  const debugCalls = debug ? [] : null;

  if (!date || !appId) {
    return json(400, { error: "Missing query params: date, appId" });
  }

  // Historische Schranke
  if (date < MIN_DATE) {
    return json(200, { date, installs: 0, uninstalls: 0, note: "before MIN_DATE", ...(debug ? { debugCalls } : {}) });
  }

  try {
    const jwt = makeJwt();

    // 1) ONGOING report request
    const ongoingList = await ascFetchJson(
      `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONGOING`,
      jwt,
      debugCalls
    );

    let ongoingRequestId = ongoingList?.data?.[0]?.id;

    // If none exists → create one
    if (!ongoingRequestId) {
      const created = await ascFetchJson(`${ASC_BASE}/analyticsReportRequests`, jwt, debugCalls, {
        method: "POST",
        body: {
          data: {
            type: "analyticsReportRequests",
            attributes: { accessType: "ONGOING" },
            relationships: { app: { data: { type: "apps", id: appId } } },
          },
        },
      });

      ongoingRequestId = created?.data?.id;
    }

    // 2) ONGOING Reports → Pick Installation/Deletion
    let ongoingReportId = null;
    if (ongoingRequestId) {
      const ongoingReports = await ascFetchJson(
        `${ASC_BASE}/analyticsReportRequests/${ongoingRequestId}/reports?filter[category]=APP_USAGE`,
        jwt,
        debugCalls
      );
      ongoingReportId = pickInstDelReportId(ongoingReports, false);
    }

    // 3) Try to fetch ONGOING instance
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
          const totals = parseTxtGzToTotals(txtBuf.toString("utf-8"));
          installs += totals.installs;
          uninstalls += totals.uninstalls;
        }

        return json(200, { date, installs, uninstalls, source: "ongoing", ...(debug ? { debugCalls } : {}) });
      }
    }

    // 4) FALLBACK: SNAPSHOT
    const snapshotList = await ascFetchJson(
      `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONE_TIME_SNAPSHOT`,
      jwt,
      debugCalls
    );

    let snapshotRequestId = snapshotList?.data?.[0]?.id;

    if (!snapshotRequestId) {
      const created = await ascFetchJson(`${ASC_BASE}/analyticsReportRequests`, jwt, debugCalls, {
        method: "POST",
        body: {
          data: {
            type: "analyticsReportRequests",
            attributes: { accessType: "ONE_TIME_SNAPSHOT" },
            relationships: { app: { data: { type: "apps", id: appId } } },
          },
        },
      });

      snapshotRequestId = created?.data?.id;
    }

    const snapReports = await ascFetchJson(
      `${ASC_BASE}/analyticsReportRequests/${snapshotRequestId}/reports?filter[category]=APP_USAGE`,
      jwt,
      debugCalls
    );

    const snapReportId = pickInstDelReportId(snapReports, false);

    if (!snapReportId) {
      return json(500, { error: "No installs/deletions snapshot report found", ...(debug ? { debugCalls } : {}) });
    }

    const snapInstances = await ascFetchJson(
      `${ASC_BASE}/analyticsReports/${snapReportId}/instances?filter[processingDate]=${date}&filter[granularity]=DAILY`,
      jwt,
      debugCalls
    );

    const snapInstance = snapInstances?.data?.[0];

    if (!snapInstance) {
      return json(200, { date, installs: 0, uninstalls: 0, note: "snapshot-no-instance", ...(debug ? { debugCalls } : {}) });
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
      const totals = parseTxtGzToTotals(txtBuf.toString("utf-8"));
      installs += totals.installs;
      uninstalls += totals.uninstalls;
    }

    return json(200, { date, installs, uninstalls, source: "snapshot", ...(debug ? { debugCalls } : {}) });
  } catch (err) {
    return json(500, { error: err?.message || String(err), ...(debug ? { debugCalls } : {}) });
  }
};
