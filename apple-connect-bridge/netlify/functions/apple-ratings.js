// apple-connect-bridge/netlify/functions/apple-ratings.js
// App Store Connect Customer Reviews API
// Liefert tägliche Review-Verteilung für ein Datum:
// rating_1 ... rating_5, rating_count, avg_rating

const crypto = require("crypto");

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

async function ascFetchJson(url, jwt) {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/json",
    },
  });

  const text = await res.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!res.ok) {
    throw new Error(`ASC HTTP ${res.status}: ${String(text).slice(0, 1200)}`);
  }

  if (data?.errors?.length) {
    throw new Error(`ASC errors: ${JSON.stringify(data.errors).slice(0, 1200)}`);
  }

  return data;
}

function normalizeDate(value) {
  if (!value) return "";
  return String(value).slice(0, 10);
}

exports.handler = async (event) => {
  const qs = event.queryStringParameters || {};
  const date = qs.date;               // YYYY-MM-DD
  const appId = qs.appId || process.env.APPLE_APP_ID;
  const debug = qs.debug === "1";

  if (!date) {
    return json(400, { error: "Missing query param: date (YYYY-MM-DD)" });
  }

  if (!appId) {
    return json(400, { error: "Missing appId query param or APPLE_APP_ID env var" });
  }

  try {
    const jwt = makeJwt();

    let url = `${ASC_BASE}/apps/${appId}/customerReviews?limit=200`;
    let page = 0;

    const stars = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    let matched = 0;
    let scanned = 0;
    const sample = [];

    while (url && page < 20) {
      page++;

      const data = await ascFetchJson(url, jwt);
      const rows = data.data || [];

      for (const row of rows) {
        scanned++;

        const attrs = row.attributes || {};
        const rating = Number(attrs.rating || 0);

        const reviewDate =
          normalizeDate(attrs.createdDate) ||
          normalizeDate(attrs.lastModifiedDate) ||
          normalizeDate(attrs.date);

        if (debug && sample.length < 10) {
          sample.push({
            id: row.id,
            rating,
            createdDate: attrs.createdDate || null,
            lastModifiedDate: attrs.lastModifiedDate || null,
            territory: attrs.territory || null,
            title: attrs.title || null,
          });
        }

        if (reviewDate !== date) continue;
        if (rating < 1 || rating > 5) continue;

        stars[rating]++;
        matched++;
      }

      url = data.links && data.links.next ? data.links.next : null;
    }

    const rating_count = matched;
    const avg_rating = matched
      ? Number(
          (
            (stars[1] * 1 +
              stars[2] * 2 +
              stars[3] * 3 +
              stars[4] * 4 +
              stars[5] * 5) / matched
          ).toFixed(2)
        )
      : "";

    return json(200, {
      date,
      appId,
      rating_1: stars[1],
      rating_2: stars[2],
      rating_3: stars[3],
      rating_4: stars[4],
      rating_5: stars[5],
      rating_count,
      avg_rating,
      source: "customerReviews",
      ...(debug ? { debug: { pagesScanned: page, reviewsScanned: scanned, sample } } : {}),
    });
  } catch (err) {
    return json(500, { error: err.message, source: "customerReviews" });
  }
};