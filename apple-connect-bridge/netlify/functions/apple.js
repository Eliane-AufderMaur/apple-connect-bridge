// netlify/functions/apple.js

const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";

// Minimum date for historical import (Option B: ab 20.06.2025)
const MIN_DATE = "2025-06-20";

async function ascFetchJson(url, jwt, debugCalls) {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${jwt}` } });
  const text = await res.text();

  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }

  if (debugCalls) {
    debugCalls.push({
      url,
      status: res.status,
      ok: res.ok,
      bodyPreview: text.slice(0, 500)
    });
  }

  if (!res.ok) throw new Error(`ASC HTTP ${res.status} for ${url}: ${text.slice(0, 500)}`);
  if (json?.errors?.length) throw new Error(`ASC errors for ${url}: ${JSON.stringify(json.errors).slice(0, 500)}`);

  return json;
}


function getEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable: ${name}`);
  return v;
}

// Create ES256 JWT for Apple API
async function makeJwt() {
  const ISSUER = getEnv("ASC_ISSUER_ID");
  const KEY_ID = getEnv("ASC_KEY_ID");
  const PRIVATE_KEY = getEnv("ASC_PRIVATE_KEY");

  const pem = PRIVATE_KEY.replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\n/g, "");

  const raw = Uint8Array.from(atob(pem), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    "pkcs8",
    raw,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const header = { alg: "ES256", kid: KEY_ID, typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    iss: ISSUER,
    iat: now,
    exp: now + 10 * 60,
    aud: "appstoreconnect-v1"
  };

  const encode = obj =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

  const h = encode(header);
  const p = encode(payload);
  const unsigned = `${h}.${p}`;

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(unsigned)
  );

  const sig = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return `${unsigned}.${sig}`;
}

// GZIP decompress
async function decompressGzip(buffer) {
  const ds = new DecompressionStream("gzip");
  const stream = new Response(new Blob([buffer]).stream().pipeThrough(ds)).body;
  return await new Response(stream).arrayBuffer();
}

// Extract installs + deletions
function parseTxtGzToTotals(txt) {
  const lines = txt.split("\n").filter(Boolean);
  if (lines.length < 2) return { installs: 0, uninstalls: 0 };

  const header = lines[0].split("\t").map(s => s.toLowerCase());
  const eventCol = header.indexOf("event");
  const countCol = header.indexOf("count");

  let installs = 0, uninstalls = 0;

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
  const nameLc = str => (str || "").toLowerCase();

  const candidates = data.filter(r =>
    nameLc(r.attributes?.name).includes("app store installation and deletion")
  );

  if (!candidates.length) return null;

  const typeToFind = preferDetailed ? "detailed" : "standard";

  const preferred = candidates.find(r =>
    nameLc(r.attributes?.name).includes(typeToFind)
  );

  return (preferred || candidates[0]).id;
}

// ===========================================================
// MAIN FUNCTION
// ===========================================================
export default async (req, context) => {
  const url = new URL(req.url);
  const date = url.searchParams.get("date");
  const appId = url.searchParams.get("appId");
  const debug = url.searchParams.get("debug") === "1";
  const debugCalls = debug ? [] : null;


  if (!date || !appId) {
    return new Response(
      JSON.stringify({ error: "Missing query params: date, appId" }),
      { status: 400 }
    );
  }

  // Historische Schranke
  if (date < MIN_DATE) {
    return new Response(
      JSON.stringify({ date, installs: 0, uninstalls: 0, note: "before MIN_DATE" }),
      { status: 200 }
    );
  }

  try {
    const jwt = await makeJwt();

    // --------------------------------------------------------
    // 1) ONGOING report request
    // --------------------------------------------------------
    const ongoingList = await ascFetchJson(
  `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONGOING`,
  jwt,
  debugCalls
);


    let ongoingRequestId = ongoingList?.data?.[0]?.id;

    // If none exists → create one
    if (!ongoingRequestId) {
      const created = await fetch(`${ASC_BASE}/analyticsReportRequests`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${jwt}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          data: {
            type: "analyticsReportRequests",
            attributes: { accessType: "ONGOING" },
            relationships: { app: { data: { type: "apps", id: appId } } }
          }
        })
      }).then(r => r.json());

      ongoingRequestId = created.data.id;
    }

    // --------------------------------------------------------
    // 2) ONGOING Reports → Pick Installation/Deletion
    // --------------------------------------------------------
    const ongoingReports = await fetch(
      `${ASC_BASE}/analyticsReportRequests/${ongoingRequestId}/reports?filter[category]=APP_USAGE`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    const ongoingReportId = pickInstDelReportId(ongoingReports, false);

    // --------------------------------------------------------
    // 3) Try to fetch ONGOING instance
    // --------------------------------------------------------
    if (ongoingReportId) {
      const instances = await fetch(
        `${ASC_BASE}/analyticsReports/${ongoingReportId}/instances?filter[processingDate]=${date}&filter[granularity]=DAILY`,
        { headers: { Authorization: `Bearer ${jwt}` } }
      ).then(r => r.json());

      const instance = instances?.data?.[0];

      if (instance) {
        const segments = await fetch(
          `${ASC_BASE}/analyticsReportInstances/${instance.id}/segments`,
          { headers: { Authorization: `Bearer ${jwt}` } }
        ).then(r => r.json());

        let installs = 0, uninstalls = 0;

        for (const seg of segments.data) {
          const gz = await fetch(seg.attributes.url).then(r => r.arrayBuffer());
          const txt = new TextDecoder("utf-8").decode(await decompressGzip(gz));
          const totals = parseTxtGzToTotals(txt);
          installs += totals.installs;
          uninstalls += totals.uninstalls;
        }

        return new Response(
          JSON.stringify({ date, installs, uninstalls, source: "ongoing" }),
          { status: 200 }
        );
      }
    }

    // --------------------------------------------------------
    // 4) FALLBACK: SNAPSHOT
    // --------------------------------------------------------
    const snapshotList = await fetch(
      `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONE_TIME_SNAPSHOT`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    let snapshotRequestId = snapshotList?.data?.[0]?.id;

    if (!snapshotRequestId) {
      const created = await fetch(`${ASC_BASE}/analyticsReportRequests`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${jwt}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          data: {
            type: "analyticsReportRequests",
            attributes: { accessType: "ONE_TIME_SNAPSHOT" },
            relationships: { app: { data: { type: "apps", id: appId } } }
          }
        })
      }).then(r => r.json());

      snapshotRequestId = created.data.id;
    }

    const snapReports = await fetch(
      `${ASC_BASE}/analyticsReportRequests/${snapshotRequestId}/reports?filter[category]=APP_USAGE`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    const snapReportId = pickInstDelReportId(snapReports, false);

    if (!snapReportId) {
      return new Response(
        JSON.stringify({ error: "No installs/deletions snapshot report found" }),
        { status: 500 }
      );
    }

    // Fetch specific snapshot instance
    const snapInstances = await fetch(
      `${ASC_BASE}/analyticsReports/${snapReportId}/instances?filter[processingDate]=${date}&filter[granularity]=DAILY`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    const snapInstance = snapInstances?.data?.[0];

    if (!snapInstance) {
      return new Response(
        JSON.stringify({ date, installs: 0, uninstalls: 0, note: "snapshot-no-instance" }),
        { status: 200 }
      );
    }

    // Segments for snapshot
    const snapSegments = await fetch(
      `${ASC_BASE}/analyticsReportInstances/${snapInstance.id}/segments`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    let installs = 0, uninstalls = 0;

    for (const seg of snapSegments.data) {
      const gz = await fetch(seg.attributes.url).then(r => r.arrayBuffer());
      const txt = new TextDecoder("utf-8").decode(await decompressGzip(gz));
      const totals = parseTxtGzToTotals(txt);
      installs += totals.installs;
      uninstalls += totals.uninstalls;
    }

    return new Response(
      JSON.stringify({ date, installs, uninstalls, source: "snapshot" }),
      { status: 200 }
    );

  return new Response(
  JSON.stringify({ error: err.message, debugCalls }),
  { status: 500 }
);

