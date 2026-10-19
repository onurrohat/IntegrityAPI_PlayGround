// Play Integrity verification backend.
//
// Flow: mobile app -> GET /challenge (receives a single-use requestHash)
//    -> creates the integrity token with this hash -> POST /verify { token }
//    -> this server has Google decode the token -> checks whether the decoded
//       requestDetails match a challenge it issued itself
//    -> if they match, a risk level is computed from the verdict.
//
// Authentication: a caller access token (see getCallerAccessToken) is exchanged
// through the IAM Credentials API for a playintegrity-scoped token by
// impersonating the "play-integrity-decoder" service account (playintegrity is a
// restricted scope, so it cannot be obtained directly through a user login).

const crypto = require("crypto");
const express = require("express");
const { execSync } = require("child_process");

const PORT = process.env.PORT || 8787;
const PACKAGE_NAME = "com.onuroktayr.integrity";
// Email of the service account that is impersonated to decode tokens, e.g.
// play-integrity-decoder@<project-id>.iam.gserviceaccount.com. Required.
const SERVICE_ACCOUNT = process.env.SERVICE_ACCOUNT;
if (!SERVICE_ACCOUNT) {
  console.error("SERVICE_ACCOUNT environment variable is not set (play-integrity-decoder@<project-id>.iam.gserviceaccount.com)");
  process.exit(1);
}

// Optional hardening settings - none of them is required; if one is left empty,
// the related check is skipped (the default behaviour stays unchanged).
const EXPECTED_CERT_SHA256 = process.env.EXPECTED_CERT_SHA256 || null;
const MIN_VERSION_CODE = process.env.MIN_VERSION_CODE ? Number(process.env.MIN_VERSION_CODE) : null;
const MIN_SDK_VERSION = process.env.MIN_SDK_VERSION ? Number(process.env.MIN_SDK_VERSION) : null;

const app = express();
app.use(express.json());

// gcloud executable used for local development; override with GCLOUD_BIN if it is not on PATH.
const GCLOUD_BIN = process.env.GCLOUD_BIN || "gcloud";

// K_SERVICE is set automatically in the Cloud Run runtime, but not in local development.
const ON_CLOUD_RUN = !!process.env.K_SERVICE;

// "Caller" access token: the impersonation call (getScopedAccessToken) uses it to
// have the play-integrity-decoder SA issue a playintegrity-scoped token.
//   - Local: the token of the user logged in with gcloud on this machine.
//   - Cloud Run: the service account's token from the metadata server (ADC).
// The impersonation step is the same in both cases, because playintegrity is a
// restricted scope that can be obtained neither from a user login nor from metadata.
let cloudAuth = null;
async function getCallerAccessToken() {
  if (ON_CLOUD_RUN) {
    if (!cloudAuth) {
      const { GoogleAuth } = require("google-auth-library");
      cloudAuth = new GoogleAuth({
        scopes: ["https://www.googleapis.com/auth/cloud-platform"],
      });
    }
    const client = await cloudAuth.getClient();
    const { token } = await client.getAccessToken();
    if (!token) throw new Error("could not obtain an access token from the metadata server");
    return token;
  }
  return execSync(`"${GCLOUD_BIN}" auth print-access-token`, { encoding: "utf8" }).trim();
}

async function getScopedAccessToken(callerToken) {
  const res = await fetch(
    `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SERVICE_ACCOUNT}:generateAccessToken`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${callerToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ scope: ["https://www.googleapis.com/auth/playintegrity"] }),
    }
  );
  if (!res.ok) {
    throw new Error(`generateAccessToken failed: ${res.status} ${await res.text()}`);
  }
  const data = await res.json();
  return data.accessToken;
}

async function decodeIntegrityToken(accessToken, integrityToken) {
  const res = await fetch(
    `https://playintegrity.googleapis.com/v1/${PACKAGE_NAME}:decodeIntegrityToken`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ integrity_token: integrityToken }),
    }
  );
  if (!res.ok) {
    throw new Error(`decodeIntegrityToken failed: ${res.status} ${await res.text()}`);
  }
  return res.json();
}

// --- Request binding (anti-replay) -----------------------------------------
//
// requestDetails.requestHash, together with requestPackageName and
// timestampMillis, binds the integrity token to one specific request. This
// server generates that hash itself, hands it out via /challenge, and on
// /verify checks that the decoded hash is one that IT issued earlier and that
// has not been used yet. Without this, a captured token could be replayed
// against another /verify call.

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const issuedChallenges = new Map(); // requestHash -> issuedAtMillis

function purgeExpiredChallenges() {
  const now = Date.now();
  for (const [hash, issuedAt] of issuedChallenges) {
    if (now - issuedAt > CHALLENGE_TTL_MS) issuedChallenges.delete(hash);
  }
}

app.get("/challenge", (_req, res) => {
  purgeExpiredChallenges();
  const requestHash = crypto.randomBytes(16).toString("base64");
  issuedChallenges.set(requestHash, Date.now());
  res.status(200).json({ requestHash });
});

function verifyRequestBinding(payload) {
  const rd = payload.requestDetails ?? {};
  const reasons = [];

  if (rd.requestPackageName && rd.requestPackageName !== PACKAGE_NAME) {
    reasons.push(`requestPackageName mismatch: expected ${PACKAGE_NAME}, got ${rd.requestPackageName}`);
  }

  if (!rd.requestHash || !issuedChallenges.has(rd.requestHash)) {
    reasons.push("requestHash was not issued by this server, or was already used (possible replay)");
  } else {
    issuedChallenges.delete(rd.requestHash); // single use
  }

  if (rd.timestampMillis) {
    const ageMs = Date.now() - Number(rd.timestampMillis);
    if (ageMs > CHALLENGE_TTL_MS) {
      reasons.push(`token request is stale (${Math.round(ageMs / 1000)}s old)`);
    }
  }

  return reasons;
}

// --- Risk policy -------------------------------------------------------------
//
// Google's Play Integrity best-practice advice: instead of a single "allow/deny"
// decision, compute a RISK LEVEL and let the client/business logic decide based on
// how sensitive the action is. Reason: UNEVALUATED is very common and not a sign of
// bad intent (it happens for new apps / low user counts); an empty device signal is
// not "bad" either, only "the absence of a good signal" - we cannot reliably tell a
// rooted device from one that has not been evaluated yet. So uncertain signals
// (UNEVALUATED, empty device verdict, etc.) are lowered to MEDIUM, not HIGH.
// evaluatePolicy() does not reject anything itself; it only returns a LOW/MEDIUM/HIGH
// risk level plus reasons, and /verify rejects HIGH.
// (Request binding is separate: it is a protocol violation check, not an uncertain
// trust signal - so if it fails we reject before the risk evaluation.)

function tierOf(value, goodValues, mediumValues) {
  if (goodValues.includes(value)) return "LOW";
  if (mediumValues.includes(value)) return "MEDIUM";
  return "HIGH";
}

function deviceTier(deviceVerdicts) {
  if (deviceVerdicts.includes("MEETS_STRONG_INTEGRITY")) return "LOW";
  if (deviceVerdicts.includes("MEETS_DEVICE_INTEGRITY")) return "LOW";
  if (deviceVerdicts.includes("MEETS_BASIC_INTEGRITY")) return "MEDIUM";
  // Empty array: the API does not distinguish "rooted" from "not evaluated yet" here.
  // Following Google's advice, we do not jump to a hard HIGH on this uncertainty.
  return "MEDIUM";
}

function activityTier(level) {
  if (level === "LEVEL_4") return "HIGH";
  if (level === "LEVEL_3") return "MEDIUM";
  return "LOW"; // LEVEL_1, LEVEL_2, UNEVALUATED, or not present at all
}

function playProtectTier(verdict) {
  switch (verdict) {
    case "NO_ISSUES":
    case undefined:
      return "LOW";
    case "NO_DATA":
    case "UNEVALUATED":
    case "POSSIBLE_RISK":
      return "MEDIUM";
    case "MEDIUM_RISK":
    case "HIGH_RISK":
      return "HIGH";
    default:
      return "MEDIUM";
  }
}

function appAccessTier(appsDetected) {
  if (appsDetected.includes("UNKNOWN_CONTROLLING") || appsDetected.includes("UNKNOWN_CAPTURING")) {
    return "HIGH";
  }
  if (appsDetected.some((a) => a.startsWith("UNKNOWN_"))) return "MEDIUM";
  return "LOW";
}

const RISK_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2 };

function worst(...tiers) {
  return tiers.reduce((w, t) => (RISK_RANK[t] > RISK_RANK[w] ? t : w), "LOW");
}

function evaluatePolicy(payload) {
  const deviceVerdicts = payload.deviceIntegrity?.deviceRecognitionVerdict ?? [];
  const appVerdict = payload.appIntegrity?.appRecognitionVerdict ?? "UNKNOWN";
  const licensingVerdict = payload.accountDetails?.appLicensingVerdict ?? "UNKNOWN";
  const packageName = payload.appIntegrity?.packageName;
  const certDigests = payload.appIntegrity?.certificateSha256Digest ?? [];
  const versionCode = payload.appIntegrity?.versionCode;
  const sdkVersion = payload.deviceIntegrity?.deviceAttributes?.sdkVersion;
  const activityLevel = payload.deviceIntegrity?.recentDeviceActivity?.deviceActivityLevel;
  const playProtectVerdict = payload.environmentDetails?.playProtectVerdict;
  const appsDetected = payload.environmentDetails?.appAccessRiskVerdict?.appsDetected ?? [];

  const reasons = [];

  // App integrity + package/cert/version pinning
  let appRisk = tierOf(appVerdict, ["PLAY_RECOGNIZED"], ["UNEVALUATED", "UNKNOWN"]);
  if (appRisk === "HIGH") reasons.push(`App package looks tampered or repackaged: ${appVerdict}`);
  if (appRisk === "MEDIUM") reasons.push(`App recognition not yet evaluated by Play: ${appVerdict}`);

  if (packageName && packageName !== PACKAGE_NAME) {
    appRisk = "HIGH";
    reasons.push(`appIntegrity.packageName mismatch: expected ${PACKAGE_NAME}, got ${packageName}`);
  }
  if (EXPECTED_CERT_SHA256 && certDigests.length > 0 && !certDigests.includes(EXPECTED_CERT_SHA256)) {
    appRisk = "HIGH";
    reasons.push("App signing certificate does not match the configured EXPECTED_CERT_SHA256");
  }
  if (MIN_VERSION_CODE && versionCode && Number(versionCode) < MIN_VERSION_CODE) {
    appRisk = worst(appRisk, "MEDIUM");
    reasons.push(`App versionCode ${versionCode} is below the required minimum ${MIN_VERSION_CODE}`);
  }

  // Device integrity + recent activity + optional min SDK
  let deviceRisk = deviceTier(deviceVerdicts);
  if (deviceVerdicts.length === 0) {
    reasons.push("Device integrity not confirmed (could be an emulator, a rooted device, or simply not yet evaluated by Google)");
  } else if (deviceRisk !== "LOW") {
    reasons.push(`Device only meets basic integrity: ${JSON.stringify(deviceVerdicts)}`);
  }
  const activityRisk = activityTier(activityLevel);
  if (activityRisk !== "LOW") {
    reasons.push(`Elevated token request activity in the last hour: ${activityLevel}`);
  }
  deviceRisk = worst(deviceRisk, activityRisk);
  if (MIN_SDK_VERSION && sdkVersion && sdkVersion < MIN_SDK_VERSION) {
    deviceRisk = worst(deviceRisk, "MEDIUM");
    reasons.push(`Device Android SDK ${sdkVersion} is below the required minimum ${MIN_SDK_VERSION}`);
  }

  // Account licensing
  const licenseRisk = tierOf(licensingVerdict, ["LICENSED"], ["UNEVALUATED", "UNKNOWN"]);
  if (licenseRisk === "HIGH") reasons.push(`Account does not hold a valid license: ${licensingVerdict}`);
  if (licenseRisk === "MEDIUM") reasons.push(`Account licensing not yet evaluated by Play: ${licensingVerdict}`);

  // Environment: Play Protect scan + other apps with elevated access
  const playProtectRisk = playProtectTier(playProtectVerdict);
  if (playProtectRisk !== "LOW") {
    reasons.push(`Play Protect status: ${playProtectVerdict ?? "not reported"}`);
  }
  const appAccessRisk = appAccessTier(appsDetected);
  if (appAccessRisk !== "LOW") {
    reasons.push(`Apps with elevated access detected alongside this app: ${JSON.stringify(appsDetected)}`);
  }
  const environmentRisk = worst(playProtectRisk, appAccessRisk);

  const riskLevel = worst(appRisk, deviceRisk, licenseRisk, environmentRisk);

  return {
    riskLevel,
    reasons,
    tiers: { app: appRisk, device: deviceRisk, account: licenseRisk, environment: environmentRisk },
    deviceVerdicts,
    appVerdict,
    licensingVerdict,
    packageName,
    versionCode,
    sdkVersion,
    activityLevel,
    playProtectVerdict,
    appsDetected,
  };
}

app.post("/verify", async (req, res) => {
  const { token } = req.body ?? {};
  if (!token) {
    return res.status(400).json({ error: "'token' field is required" });
  }

  try {
    const callerToken = await getCallerAccessToken();
    const scopedToken = await getScopedAccessToken(callerToken);
    const decoded = await decodeIntegrityToken(scopedToken, token);
    const payload = decoded.tokenPayloadExternal ?? {};

    const bindingErrors = verifyRequestBinding(payload);
    if (bindingErrors.length > 0) {
      console.error(`[verify] request binding failed: ${bindingErrors.join("; ")}`);
      return res.status(409).json({
        allowed: false,
        error: "request binding failed",
        reasons: bindingErrors,
      });
    }

    const policy = evaluatePolicy(payload);

    console.log(`[verify] riskLevel=${policy.riskLevel} reasons=${policy.reasons.join("; ") || "-"}`);

    // HIGH risk is hard-rejected here; LOW/MEDIUM allow the login (and the reasons are
    // shown on the dashboard). Since riskLevel is the worst of all areas, a SINGLE HIGH
    // signal is enough (e.g. only LEVEL_4 activity, an UNLICENSED account, a repackaged
    // app, or a packageName/certificate mismatch). Uncertain signals never reach HIGH,
    // so this rejection only happens on clearly bad signals.
    const allowed = policy.riskLevel !== "HIGH";
    res.status(allowed ? 200 : 403).json({
      allowed,
      riskLevel: policy.riskLevel,
      reasons: policy.reasons,
      tiers: policy.tiers,
      verdict: payload,
    });
  } catch (err) {
    console.error(err);
    res.status(502).json({ error: "decode failed", detail: String(err.message || err) });
  }
});

app.listen(PORT, () => {
  console.log(`Integrity verification server: http://localhost:${PORT}`);
  console.log(`Usage: GET /challenge  ->  { "requestHash": "..." }`);
  console.log(`       POST /verify  { "token": "<integrity token>" }`);
});