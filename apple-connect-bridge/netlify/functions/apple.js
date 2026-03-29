// netlify/functions/apple.js

const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";

function getEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable: ${name}`);
  return v;
}

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

export default async (req, context) => {
  try {
    const jwt = await makeJwt();

    const { searchParams } = new URL(req.url);
    const date = searchParams.get("date");
    const appId = searchParams.get("appId");

const mode = searchParams.get("mode");

// Admin-only: list apps (to find appId) when explicitly requested
if (mode === "listApps") {
  const adminKey = searchParams.get("adminKey");
  if (!adminKey || adminKey !== process.env.ASC_ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 });
  }

  const appsRes = await fetch(`${ASC_BASE}/apps?limit=200`, {
    headers: { Authorization: `Bearer ${jwt}` }
  });
  const apps = await appsRes.json();
  return new Response(JSON.stringify(apps, null, 2), { status: 200 });
}

if (!date || !appId) {
  return new Response(
    JSON.stringify({ error: "Missing query params: date, appId" }),
    { status: 400 }
  );
}



    const requests = await fetch(
      `${ASC_BASE}/apps/${appId}/analyticsReportRequests?filter[accessType]=ONGOING`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    let requestId = requests?.data?.[0]?.id;

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

    const reports = await fetch(
      `${ASC_BASE}/analyticsReportRequests/${requestId}/reports?filter[category]=APP_USAGE`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    const report = reports.data.find(r =>
      r.attributes.name.toLowerCase().includes("install")
    );

    if (!report) {
      return new Response(
        JSON.stringify({ error: "Installations report not found" }),
        { status: 500 }
      );
    }

    const reportId = report.id;

    const instances = await fetch(
      `${ASC_BASE}/analyticsReports/${reportId}/instances?filter[processingDate]=${date}&filter[granularity]=DAILY`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    const instance = instances?.data?.[0];

    if (!instance) {
      return new Response(
        JSON.stringify({ date, installs: 0, uninstalls: 0, note: "no instance" }),
        { status: 200 }
      );
    }

    const segments = await fetch(
      `${ASC_BASE}/analyticsReportInstances/${instance.id}/segments`,
      { headers: { Authorization: `Bearer ${jwt}` } }
    ).then(r => r.json());

    let installs = 0;
    let uninstalls = 0;

    for (const seg of segments.data) {
      const url = seg.attributes.url;
      const gz = await fetch(url).then(r => r.arrayBuffer());

      const txt = new TextDecoder("utf-8").decode(await decompressGzip(gz));
      const lines = txt.split("\n").map(l => l.trim()).filter(Boolean);

      if (lines.length < 2) continue;

      const header = lines[0].split("\t").map(s => s.toLowerCase());
      const eventCol = header.indexOf("event");
      const countCol = header.indexOf("count");

      for (let i = 1; i < lines.length; i++) {
        const cols = lines[i].split("\t");
        const event = cols[eventCol]?.toLowerCase() || "";
        const count = Number(cols[countCol] || 0);
        if (event.includes("install")) installs += count;
        if (event.includes("delete")) uninstalls += count;
      }
    }

    return new Response(
      JSON.stringify({ date, installs, uninstalls }),
      { status: 200 }
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500
    });
  }
};

async function decompressGzip(buffer) {
  const ds = new DecompressionStream("gzip");
  const stream = new Response(new Blob([buffer]).stream().pipeThrough(ds)).body;
  return await new Response(stream).arrayBuffer();
}
