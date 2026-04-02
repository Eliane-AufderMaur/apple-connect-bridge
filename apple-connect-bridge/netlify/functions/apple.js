// netlify/functions/apple.js
// Sales & Trends API — UI Installations & Deletions
// 100% UI-consistent (Units, Returns)

const crypto = require("crypto");

const APP_ID = "6737323008";          // Apple Store App ID
const VENDOR_NUMBER = "91041012";     // Your vendor number
const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";

// Create JWT for Apple API
function makeJwt() {
  const ISSUER = process.env.ASC_ISSUER_ID;
  const KEY_ID = process.env.ASC_KEY_ID;
  const PRIVATE_KEY = process.env.ASC_PRIVATE_KEY.replace(/\\n/g, "\n");

  const header = {
    alg: "ES256",
    kid: KEY_ID,
    typ: "JWT",
  };

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISSUER,
    iat: now,
    exp: now + 600, // 10 min
    aud: "appstoreconnect-v1",
  };

  const base64url = (input) =>
    Buffer.from(JSON.stringify(input))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

  const unsigned = `${base64url(header)}.${base64url(payload)}`;

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsigned);
  const signature = signer.sign(PRIVATE_KEY, "base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${unsigned}.${signature}`;
}

// MAIN FUNCTION (installs + deletes)
exports.handler = async (event) => {
  const qs = event.queryStringParameters || {};
  const date = qs.date;

  if (!date) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Missing date" }),
    };
  }

  try {
    const jwt = makeJwt();

    // Build Sales Report URL
    const url =
      `${ASC_BASE}/salesReports` +
      `?filter[frequency]=DAILY` +
      `&filter[reportType]=SALES` +
      `&filter[reportSubType]=SUMMARY` +
      `&filter[reportDate]=${date}` +
      `&filter[vendorNumber]=${VENDOR_NUMBER}`;

    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${jwt}` },
    });

    const text = await res.text();

    // CSV format response
    if (!res.ok) {
      return {
        statusCode: res.status,
        body: JSON.stringify({ error: text }),
      };
    }

    // CSV Parsing
    const rows = text.split("\n").filter(Boolean);
    if (rows.length < 2) {
      return {
        statusCode: 200,
        body: JSON.stringify({
          date,
          installs: 0,
          uninstalls: 0,
          note: "no-data",
        }),
      };
    }

    const header = rows[0].split(",");
    const idxUnits = header.indexOf("Units");
    const idxReturns = header.indexOf("Returns");

    let installs = 0;
    let uninstalls = 0;

    for (let r = 1; r < rows.length; r++) {
      const cols = rows[r].split(",");
      installs += Number(cols[idxUnits] || 0);
      uninstalls += Number(cols[idxReturns] || 0);
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        date,
        installs,
        uninstalls,
        source: "salesReports",
      }),
    };

  } catch (e) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: e.message }),
    };
  }
};
