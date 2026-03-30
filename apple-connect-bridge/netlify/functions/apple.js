// netlify/functions/apple.js

const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";

// Minimum date for historical import (Option B)
const MIN_DATE = "2025-06-20";

function getEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable: ${name}`);
  return v;
}

// Create JWT for ASC API
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

// GZIP decoding for Apple segments
async function decompressGzip(buffer) {
  const ds = new DecompressionStream("gzip");
  const stream = new Response(new Blob([buffer]).stream().pipeThrough(ds)).body;
  return await new Response(stream).arrayBuffer();
}

// Parse .txt.gz for installs and deletions
function parseTxtGzToTotals(txt) {
  const lines = txt.split("\n").filter(Boolean);
  if (lines.length < 2) return { installs: 0, uninstalls: 0 };

  const header = lines[0].split("\t").map(h => h.toLowerCase());
  const eventCol = header.indexOf("event");
  const countCol = header.indexOf("count");

  let installs = 0;
  let uninstalls = 0;

  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split("\t");
    const ev = (cols[eventCol] || "").toLowerCase();
    const c = Number(cols[countCol] || 0);

    if (ev.includes("install")) installs += c;
    if (ev.includes("delete") || ev.includes("delet")) uninstalls += c;
  }

  return { installs, uninstalls };
}

// ===============================================
// MAIN HANDLER
// ===============================================
export default async (req, context) => {
  const url = new URL(req.url);
  const date = url.searchParams.get("date");
  const appId = url.searchParams.get("appId");

  if (!date || !appId) {
    return new Response(
      JSON.stringify({ error: "Missing query params: date, appId" }),
      { status: 400 }
    );
  }

  if (date < MIN_DATE) {
    // Out of allowed historical range
    return new Response(
      JSON.stringify({ date, installs: 0, uninstalls: 0, note: "before MIN_DATE" }),
      { status: 200 }
    );
  }

  try {
    const jwt = await makeJwt();

    // -------------------------------------------
    // 1) Find ONGOING report request or create one
    // -------------------------------------------
    const ongoingList = await fetch(
      `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONGOING`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    let requestId = ongoingList?.data?.[0]?.id;

    if (!requestId) {
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

      requestId = created.data.id;
    }

    // -------------------------------------------
    // 2) Get ONGOING report for Installations/Deletions
    // -------------------------------------------
    const reports = await fetch(
      `${ASC_BASE}/analyticsReportRequests/${requestId}/reports?filter[category]=APP_USAGE`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    const report = reports.data.find(r => {
      const n = (r.attributes?.name || "").toLowerCase();
      return n.includes("installations") && n.includes("delet");
    });


    if (!report) {
      return new Response(
        JSON.stringify({ error: "No installs/deletions report found" }),
        { status: 500 }
      );
    }

    const reportId = report.id;

    // -------------------------------------------
    // 3) Try ONGOING instance for this date
    // -------------------------------------------
    const instances = await fetch(
      `${ASC_BASE}/analyticsReports/${reportId}/instances?filter[processingDate]=${date}&filter[granularity]=DAILY`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    const ongoingInstance = instances?.data?.[0];

    if (ongoingInstance) {
      // Get segment URLs
      const segments = await fetch(
        `${ASC_BASE}/analyticsReportInstances/${ongoingInstance.id}/segments`,
        { headers: { Authorization: `Bearer ${jwt}` } }
      ).then(r => r.json());

      let installs = 0, uninstalls = 0;

      for (const seg of segments.data) {
        const gz = await fetch(seg.attributes.url).then(r => r.arrayBuffer());
        const txt = new TextDecoder("utf-8").decode(await decompressGzip(gz));
        const t = parseTxtGzToTotals(txt);
        installs += t.installs;
        uninstalls += t.uninstalls;
      }

      return new Response(
        JSON.stringify({ date, installs, uninstalls, source: "ongoing" }),
        { status: 200 }
      );
    }

    // -------------------------------------------
    // 4) ONGOING has no instance → Use ONE_TIME_SNAPSHOT
    // -------------------------------------------
    const snapshotList = await fetch(
      `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONE_TIME_SNAPSHOT`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    let snapshotRequestId = snapshotList?.data?.[0]?.id;

    if (!snapshotRequestId) {
      const createdSnap = await fetch(`${ASC_BASE}/analyticsReportRequests`, {
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

      snapshotRequestId = createdSnap.data.id;
    }

    // get reports for snapshot
    const snapReports = await fetch(
      `${ASC_BASE}/analyticsReportRequests/${snapshotRequestId}/reports?filter[category]=APP_USAGE`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    const snapReport = snapReports.data.find(r =>
      r.attributes.name.toLowerCase().includes("install")
    );

    if (!snapReport) {
      return new Response(
        JSON.stringify({ error: "No snapshot installs report found" }),
        { status: 500 }
      );
    }

    const snapReportId = snapReport.id;

    // snapshot instances: no daily filtering → fetch all, then we filter manually
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

    // get its segments
    const snapSegments = await fetch(
      `${ASC_BASE}/analyticsReportInstances/${snapInstance.id}/segments`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    let installs = 0, uninstalls = 0;

    for (const seg of snapSegments.data) {
      const gz = await fetch(seg.attributes.url).then(r => r.arrayBuffer());
      const txt = new TextDecoder("utf-8").decode(await decompressGzip(gz));
      const t = parseTxtGzToTotals(txt);
      installs += t.installs;
      uninstalls += t.uninstalls;
    }

    return new Response(
      JSON.stringify({ date, installs, uninstalls, source: "snapshot" }),
      { status: 200 }
    );

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
};
