// apple-connect-bridge/netlify/functions/apple.js
// UI Installations & UI Deletions via SalesReports (Units / Returns)
// Robust: ES256 JWT + gzip (TSV) parsing + debug

const crypto = require("crypto");
const zlib = require("zlib");

const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";

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

// ES256 JWT for App Store Connect API
function makeJwt() {
  const ISSUER = getEnv("ASC_ISSUER_ID");
  const KEY_ID = getEnv("ASC_KEY_ID");

  let s = String(getEnv("ASC_PRIVATE_KEY")).trim();
  s = s.replace(/^"(.*)"$/s, "$1").replace(/^'(.*)'$/s, "$1");
  s = s.replace(/\\n/g, "\n");

  // Accept PEM or base64 body
  const stripped = s
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");

  const keyObj = crypto.createPrivateKey({
    key: Buffer.from(stripped, "base64"),
    format: "der",
    type: "pkcs8",
  });

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
    key: keyObj,
    dsaEncoding: "ieee-p1363",
  });

  return `${unsigned}.${base64url(sig)}`;
}

function findColIndex(cols, names) {
  const lc = cols.map((c) => String(c || "").trim().toLowerCase());
  for (const n of names) {
    const i = lc.indexOf(String(n).toLowerCase());
    if (i >= 0) return i;
  }
  return -1;
}

exports.handler = async (event) => {
  const qs = event.queryStringParameters || {};
  const date = qs.date; // YYYY-MM-DD
  const debug = qs.debug === "1";

  const vendorNumber = process.env.APPLE_VENDOR_NUMBER;
  const appId = qs.appId || process.env.APPLE_APP_ID;

  if (!date) return json(400, { error: "Missing query param: date (YYYY-MM-DD)" });
  if (!vendorNumber) return json(500, { error: "Missing env var: APPLE_VENDOR_NUMBER" });

  try {
    const jwt = makeJwt();

    const url =
      `${ASC_BASE}/salesReports` +
      `?filter[frequency]=DAILY` +
      `&filter[reportType]=SALES` +
      `&filter[reportSubType]=SUMMARY` +
      `&filter[reportDate]=${encodeURIComponent(date)}` +
      `&filter[vendorNumber]=${encodeURIComponent(vendorNumber)}` +
      `&filter[version]=1_0`;

    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/a-gzip",
      },
    });

    if (!res.ok) {
      const text = await res.text();
      return json(res.status, { date, error: text.slice(0, 1200), source: "salesReports" });
    }

    const ab = await res.arrayBuffer();
    const raw = Buffer.from(ab);

    // SalesReports is gzipped
    let txt;
    try {
      txt = zlib.gunzipSync(raw).toString("utf-8");
    } catch {
      txt = raw.toString("utf-8");
    }

    const lines = txt.split("\n").filter(Boolean);
    if (lines.length < 2) {
      return json(200, { date, installs: 0, uninstalls: 0, note: "no-data", source: "salesReports" });
    }

    const headerLine = lines[0];
    const delim = headerLine.includes("\t") ? "\t" : ","; // usually TSV
    const cols = headerLine.split(delim).map((s) => s.trim());

    const idxUnits = findColIndex(cols, ["Units"]);
    const idxReturns = findColIndex(cols, ["Returns"]);
    const idxAppleId = findColIndex(cols, ["Apple Identifier", "App Apple Identifier"]);

    if (idxUnits < 0 || idxReturns < 0) {
      return json(500, {
        date,
        error: "Could not find Units/Returns columns in SalesReport",
        header: cols,
        source: "salesReports",
      });
    }

    let installs = 0;
    let uninstalls = 0;
    let matchedRows = 0;

    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(delim);

      if (idxAppleId >= 0 && appId) {
        const rowAppleId = String(parts[idxAppleId] || "").trim();
        if (rowAppleId && rowAppleId !== String(appId)) continue;
      }

      installs += Number(parts[idxUnits] || 0);
      uninstalls += Number(parts[idxReturns] || 0);
      matchedRows++;
    }

    return json(200, {
      date,
      appId: appId || null,
      installs,
      uninstalls,
      source: "salesReports",
      ...(debug
        ? {
            debug: {
              url,
              delimiter: delim === "\t" ? "\\t" : ",",
              header: cols,
              matchedRows,
              sampleLines: lines.slice(0, 5),
            },
          }
        : {}),
    });
  } catch (e) {
    return json(500, { date, error: e.message, source: "salesReports" });
  }
};
