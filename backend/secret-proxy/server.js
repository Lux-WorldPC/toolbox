/**
 * @lwpc/toolbox — backend for Secure Message, Domain Checkup, What's My IP,
 * and Email Header Analyzer.
 *
 * Licence: MIT. https://github.com/Lux-WorldPC/toolbox
 *
 * Endpoints (see README.md for details):
 *
 *   Secure Message (E2E — server cannot decrypt stored blobs):
 *     POST /secret/api/create
 *     POST /secret/api/reveal
 *
 *   Domain Checkup:
 *     GET /api/domain-tools/ip-info    RIPE Stat enrichment
 *     GET /api/domain-tools/ssl        TLS certificate
 *     GET /api/domain-tools/whois      simplified WHOIS
 *     GET /api/domain-tools/detect     CMS/platform detection
 *     GET /api/domain-tools/mta-sts    MTA-STS policy
 *     GET /api/domain-tools/autodiscover   Microsoft autodiscover
 *     GET /api/domain-tools/autoconfig     Thunderbird autoconfig
 *
 *   What's My IP:
 *     GET /api/myip
 *
 *   Email Header Analyzer (optional — only for "receive report by email"):
 *     POST /api/email-report
 *
 * Security:
 *   - Listens on 127.0.0.1 by default (put a reverse proxy in front).
 *   - In-memory rate limiting: 20/min create, 60/min reveal and domain-tools.
 *   - Daily create quota: 12/IP (reset at UTC midnight). Whitelist IPs via env.
 *   - Cloudflare Turnstile required on create.
 *   - Secrets stored as opaque ciphertext the server cannot decrypt.
 *   - Cryptographically random IDs (crypto.randomBytes).
 *   - Zero NPM dependency — Node.js stdlib only.
 *
 * Start:  node server.js      (or node --env-file=.env server.js)
 */

'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* ══════════════════════════════════════════════════════════════
   CONFIGURATION

   Loaded from process.env (Node auto-loads a sibling .env file if
   you prefix `node --env-file=.env server.js`, or use the `dotenv`
   package). See .env.example in this directory for all supported keys.
   ══════════════════════════════════════════════════════════════ */

const SECRETS_DIR    = process.env.SECRETS_DIR    || './data/secrets';
const PORT           = parseInt(process.env.PORT  || '3100', 10);
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || '';
const MAILGUN_API_KEY  = process.env.MAILGUN_API_KEY  || '';
const MAILGUN_DOMAIN   = process.env.MAILGUN_DOMAIN   || '';
const MAILGUN_REGION   = process.env.MAILGUN_REGION   || 'eu';
const MAIL_FROM        = process.env.MAIL_FROM        || '';
const BCC_EMAIL        = process.env.BCC_EMAIL        || '';

/* Optional IP whitelist — bypasses the per-IP daily quota for `create`.
   Accepts a comma-separated list (e.g. `1.2.3.4,5.6.7.8`). */
const WHITELIST_IPS = (process.env.SCRT_WHITELIST_IPS || '')
  .split(',').map(function (ip) { return ip.trim(); }).filter(Boolean);

if (!TURNSTILE_SECRET) {
  console.error('[secret] TURNSTILE_SECRET is required (see .env.example)');
  process.exit(1);
}

/* Create storage dir if missing. */
if (!fs.existsSync(SECRETS_DIR)) {
  fs.mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o750 });
}

/* ══════════════════════════════════════════════════════════════
   RATE LIMITING — 20 req/min create, 60 req/min reveal
   ══════════════════════════════════════════════════════════════ */

const RATE_WINDOW = 60 * 1000;
const rateLimitMap = new Map();

function isRateLimited(ip, limit) {
  const now = Date.now();
  const key = ip + ':' + limit;
  let timestamps = rateLimitMap.get(key);
  if (!timestamps) {
    timestamps = [];
    rateLimitMap.set(key, timestamps);
  }
  while (timestamps.length > 0 && timestamps[0] < now - RATE_WINDOW) {
    timestamps.shift();
  }
  if (timestamps.length >= limit) return true;
  timestamps.push(now);
  return false;
}

/* Nettoyage périodique des IPs inactives */
setInterval(function () {
  const now = Date.now();
  for (const [key, timestamps] of rateLimitMap) {
    while (timestamps.length > 0 && timestamps[0] < now - RATE_WINDOW) {
      timestamps.shift();
    }
    if (timestamps.length === 0) rateLimitMap.delete(key);
  }
}, 5 * 60 * 1000);

/* ══════════════════════════════════════════════════════════════
   QUOTA JOURNALIER — 12 créations/jour par IP publique
   IP whitelist (unlimited create quota) — comma-separated list:
     SCRT_WHITELIST_IPS=1.2.3.4,5.6.7.8
   Compteurs en mémoire, reset automatique à minuit UTC.
   ══════════════════════════════════════════════════════════════ */

const DAILY_LIMIT = 12;
const dailyCountMap = new Map(); /* Map<IP, { count, date }> */

/* WHITELIST_IPS is already defined in the CONFIGURATION block above. */
if (WHITELIST_IPS.length > 0) {
  console.log('[secret] ' + WHITELIST_IPS.length + ' IP(s) whitelisted (unlimited create quota)');
}

/* Retourne la date du jour en UTC (YYYY-MM-DD) pour le reset à minuit */
function todayUTC() {
  return new Date().toISOString().substring(0, 10);
}

/* Formate une date ISO en heure locale Luxembourg (Europe/Luxembourg, gère CET/CEST).
   Entrée : ISO string (ex: "2026-04-20T13:42:15.123Z") ou Date.
   Sortie : "20/04/2026 15:42:15" (format fr-FR avec seconds). Ajouté 2026-04-20. */
function formatLuxembourgTime(input) {
  var d = (input instanceof Date) ? input : new Date(input);
  if (isNaN(d.getTime())) return String(input);
  return d.toLocaleString('fr-FR', {
    timeZone: 'Europe/Luxembourg',
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  }) + ' (Luxembourg)';
}

/* Vérifie si l'IP a atteint le quota journalier.
   Retourne false si OK (quota pas atteint), true si dépassé. */
function isDailyLimitReached(ip) {
  /* IPs whitelist → jamais limitées */
  if (WHITELIST_IPS.indexOf(ip) !== -1) return false;

  const today = todayUTC();
  let entry = dailyCountMap.get(ip);

  /* Nouveau jour ou nouvelle IP → reset */
  if (!entry || entry.date !== today) {
    entry = { count: 0, date: today };
    dailyCountMap.set(ip, entry);
  }

  if (entry.count >= DAILY_LIMIT) return true;
  entry.count++;
  return false;
}

/* Nettoyage des compteurs des jours précédents (toutes les heures) */
setInterval(function () {
  const today = todayUTC();
  for (const [ip, entry] of dailyCountMap) {
    if (entry.date !== today) dailyCountMap.delete(ip);
  }
}, 60 * 60 * 1000);

/* ══════════════════════════════════════════════════════════════
   NETTOYAGE SECRETS EXPIRÉS — toutes les heures
   ══════════════════════════════════════════════════════════════ */

function cleanupExpired() {
  try {
    const files = fs.readdirSync(SECRETS_DIR);
    const now = Date.now();
    let cleaned = 0;
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      try {
        const filePath = path.join(SECRETS_DIR, file);
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (data.expiresAt && new Date(data.expiresAt).getTime() < now) {
          fs.unlinkSync(filePath);
          cleaned++;
        }
      } catch (e) { /* fichier corrompu → supprimer */
        try { fs.unlinkSync(path.join(SECRETS_DIR, file)); } catch (e2) {}
      }
    }
    if (cleaned > 0) console.log('[secret] Nettoyage : ' + cleaned + ' secrets expirés supprimés');
  } catch (e) {
    console.error('[secret] Erreur nettoyage:', e.message);
  }
}

/* Nettoyage au démarrage + toutes les heures */
cleanupExpired();
setInterval(cleanupExpired, 60 * 60 * 1000);

/* ══════════════════════════════════════════════════════════════
   HELPERS
   ══════════════════════════════════════════════════════════════ */

function jsonResponse(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req, maxSize) {
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let size = 0;
    req.on('data', function (chunk) {
      size += chunk.length;
      if (size > maxSize) { req.destroy(); reject(new Error('Body trop volumineux')); }
      chunks.push(chunk);
    });
    req.on('end', function () { resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', reject);
  });
}

function httpsPost(url, headers, body) {
  return new Promise(function (resolve, reject) {
    const parsed = new URL(url);
    const req = https.request({
      hostname: parsed.hostname, port: 443, path: parsed.pathname,
      method: 'POST', headers: headers
    }, function (res) {
      const chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () { resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }); });
    });
    req.on('error', reject);
    req.setTimeout(10000, function () { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

/* Générer un ID aléatoire URL-safe (22 chars = 132 bits d'entropie) */
function generateId() {
  return crypto.randomBytes(16).toString('base64url');
}

/* Vérification Turnstile */
async function verifyTurnstile(token, remoteIp) {
  const formData = JSON.stringify({ secret: TURNSTILE_SECRET, response: token, remoteip: remoteIp });
  const result = await httpsPost(
    'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(formData) },
    formData
  );
  try { return JSON.parse(result.body).success === true; } catch (e) { return false; }
}

/* IP client */
function getClientIp(req) {
  return req.headers['x-forwarded-for']
    ? req.headers['x-forwarded-for'].split(',')[0].trim()
    : req.socket.remoteAddress;
}

/* ══════════════════════════════════════════════════════════════
   VALIDATION
   ══════════════════════════════════════════════════════════════ */

const VALID_EXPIRES = [300000, 1800000, 3600000, 86400000, 604800000, 2592000000];

function validateCreate(body) {
  if (!body || typeof body !== 'object') return 'Body JSON invalide';
  if (typeof body.encrypted !== 'string' || body.encrypted.length < 1)
    return 'encrypted manquant';
  if (body.encrypted.length > 2000000)
    return 'encrypted trop volumineux (max 2 Mo)';
  if (body.expiresIn && !VALID_EXPIRES.includes(body.expiresIn))
    return 'expiresIn invalide';
  if (!body.turnstileToken || typeof body.turnstileToken !== 'string')
    return 'turnstileToken manquant';
  return null;
}

function validateReveal(body) {
  if (!body || typeof body !== 'object') return 'Body JSON invalide';
  if (typeof body.id !== 'string' || body.id.length < 10 || body.id.length > 30)
    return 'id invalide';
  /* Protection path traversal */
  if (body.id.includes('/') || body.id.includes('\\') || body.id.includes('..'))
    return 'id invalide';
  return null;
}

/* ══════════════════════════════════════════════════════════════
   HANDLER — POST /secret/api/create
   Stocke un blob chiffré, retourne { id, expiresAt }
   ══════════════════════════════════════════════════════════════ */

async function handleCreate(req, res) {
  let rawBody;
  try { rawBody = await readBody(req, 2 * 1024 * 1024); } catch (e) {
    return jsonResponse(res, 413, { error: 'Payload trop volumineux' });
  }

  let body;
  try { body = JSON.parse(rawBody); } catch (e) {
    return jsonResponse(res, 400, { error: 'JSON invalide' });
  }

  const err = validateCreate(body);
  if (err) return jsonResponse(res, 400, { error: err });

  /* Vérifier Turnstile */
  const clientIp = getClientIp(req);

  /* Ancien quota journalier 12/jour supprimé le 2026-04-10.
     Remplacé par le quota client 10/30min (sessionStorage) + rate limiting par minute. */

  const turnstileOk = await verifyTurnstile(body.turnstileToken, clientIp);
  if (!turnstileOk) {
    return jsonResponse(res, 403, { error: 'Vérification Turnstile échouée' });
  }

  /* Calculer l'expiration */
  const expiresIn = body.expiresIn || 86400000;
  const expiresAt = new Date(Date.now() + expiresIn).toISOString();

  /* Générer un ID unique et stocker.
     notifyEmail (optionnel) : si renseigné, un email est envoyé au créateur quand le secret
     est révélé et détruit. L'email est stocké en clair (pas chiffré — pas partie du secret).
     Ajouté 2026-04-10. */
  const id = generateId();
  const secret = {
    encrypted: body.encrypted,
    hasPassword: !!body.hasPassword,
    expiresAt: expiresAt,
    createdAt: new Date().toISOString()
  };
  if (body.notifyEmail && typeof body.notifyEmail === 'string' && body.notifyEmail.indexOf('@') !== -1) {
    secret.notifyEmail = body.notifyEmail.trim().toLowerCase();
  }

  const filePath = path.join(SECRETS_DIR, id + '.json');
  try {
    fs.writeFileSync(filePath, JSON.stringify(secret), { mode: 0o640 });
  } catch (e) {
    console.error('[secret] Erreur écriture:', e.message);
    return jsonResponse(res, 500, { error: 'Erreur stockage' });
  }

  console.log('[secret] Créé: ' + id + ' (expire ' + expiresAt + ')');
  return jsonResponse(res, 200, { id: id, expiresAt: expiresAt });
}

/* ══════════════════════════════════════════════════════════════
   HANDLER — POST /secret/api/reveal
   Retourne le blob chiffré + SUPPRIME le fichier (usage unique).
   Si notifyEmail stocké → envoie email de notification au créateur (ajouté 2026-04-10).
   ══════════════════════════════════════════════════════════════ */

async function handleReveal(req, res) {
  let rawBody;
  try { rawBody = await readBody(req, 1024); } catch (e) {
    return jsonResponse(res, 413, { error: 'Payload trop volumineux' });
  }

  let body;
  try { body = JSON.parse(rawBody); } catch (e) {
    return jsonResponse(res, 400, { error: 'JSON invalide' });
  }

  const err = validateReveal(body);
  if (err) return jsonResponse(res, 400, { error: err });

  const filePath = path.join(SECRETS_DIR, body.id + '.json');

  /* Lire le fichier */
  let secret;
  try {
    secret = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    return jsonResponse(res, 404, { error: 'Secret introuvable ou déjà lu' });
  }

  /* Vérifier l'expiration */
  if (new Date(secret.expiresAt).getTime() < Date.now()) {
    try { fs.unlinkSync(filePath); } catch (e) {}
    return jsonResponse(res, 410, { error: 'Secret expiré' });
  }

  /* Supprimer le fichier IMMÉDIATEMENT (usage unique) */
  try { fs.unlinkSync(filePath); } catch (e) {}

  /* Notification email to the creator if notifyEmail was provided. */
  if (secret.notifyEmail) {
    sendMailgun(
      secret.notifyEmail,
      'Your secret has been read and destroyed',
      emailWrap('Notice',
        '<p style="margin:0 0 16px 0;">Hello,</p>' +
        '<p style="margin:0 0 16px 0;">The secret you created has been <b style="color:#1e2d5a;">read and permanently destroyed</b>.</p>' +
        '<table style="width:100%;margin:0 0 20px 0;border-collapse:collapse;" border="0" cellspacing="0" cellpadding="0">' +
          '<tr><td style="width:3px;background-color:#f1cb25;"><br></td>' +
          '<td style="padding:12px 16px;background-color:#F4F6FA;font-family:Arial,sans-serif;font-size:13px;color:#3A4A5C;">' +
            '<strong style="color:#1e2d5a;">ID:</strong> <code style="font-family:\'Courier New\',monospace;background:#E8ECF2;padding:2px 6px;border-radius:3px;">' + escapeHTML(body.id) + '</code><br>' +
            '<strong style="color:#1e2d5a;">Created:</strong> ' + escapeHTML(new Date(secret.createdAt).toISOString()) + '<br>' +
            '<strong style="color:#1e2d5a;">Read:</strong> ' + escapeHTML(new Date().toISOString()) + '<br>' +
            '<strong style="color:#1e2d5a;">Status:</strong> Permanently deleted from the server' +
          '</td></tr>' +
        '</table>' +
        '<p style="margin:0;font-size:12px;color:#7a8ab0;">If you did not create this secret, please ignore this message.</p>'
      )
    );
    console.log('[secret] Notification envoyée à ' + secret.notifyEmail);
  }

  console.log('[secret] Révélé et supprimé: ' + body.id);
  return jsonResponse(res, 200, {
    encrypted: secret.encrypted,
    hasPassword: secret.hasPassword
  });
}

/* ══════════════════════════════════════════════════════════════
   EMAIL WRAPPER — minimal, brand-agnostic HTML envelope.

   Used by:
     - handleReveal — notification to the creator when their secret is read
     - handleEmailReport — delivery of Email Header Analyzer reports

   Customize via env vars:
     BRAND_NAME   — name shown in the header (default: "toolbox")
     BRAND_URL    — clickable link on the header brand block (optional)
     BRAND_COLOR  — accent color for the header band (default: #3d5394)

   Deliberately tiny. Inline styles only (many email clients strip <style>).
   ══════════════════════════════════════════════════════════════ */

function emailWrap(dept, bodyHtml) {
  var brandName  = process.env.BRAND_NAME  || 'toolbox';
  var brandUrl   = process.env.BRAND_URL   || '';
  var brandColor = process.env.BRAND_COLOR || '#3d5394';
  var brand = brandUrl
    ? '<a href="' + brandUrl + '" style="color:#fff;text-decoration:none;">' + escapeHTML(brandName) + '</a>'
    : escapeHTML(brandName);
  return '<table style="width:100%;border-collapse:collapse;" border="0" cellspacing="0" cellpadding="0"><tbody>' +
    '<tr><td style="background-color:' + brandColor + ';padding:18px 24px;">' +
      '<span style="font-family:Arial,sans-serif;font-size:16px;font-weight:700;color:#fff;">' + brand + '</span>' +
      (dept ? ' &middot; <span style="font-family:\'Courier New\',monospace;font-size:11px;color:rgba(255,255,255,0.85);letter-spacing:1px;text-transform:uppercase;">' + escapeHTML(dept) + '</span>' : '') +
    '</td></tr>' +
    '<tr><td style="padding:28px 24px;background-color:#ffffff;">' +
      '<div style="font-family:Arial,sans-serif;font-size:14px;color:#3A4A5C;line-height:1.6;">' +
        bodyHtml +
      '</div>' +
      '<p style="margin:24px 0 0;font-family:Arial,sans-serif;font-size:11px;color:#b0b8c4;line-height:1.4;">This message is confidential. If you are not the intended recipient, please delete it and notify the sender.</p>' +
    '</td></tr>' +
    '</tbody></table>';
}

/* Send an email via Mailgun. */
async function sendMailgun(to, subject, htmlBody) {
  if (!MAILGUN_API_KEY || !MAILGUN_DOMAIN) {
    console.error('[secret] Mailgun non configuré (MAILGUN_API_KEY ou MAILGUN_DOMAIN manquant)');
    return false;
  }
  var host = MAILGUN_REGION === 'eu' ? 'api.eu.mailgun.net' : 'api.mailgun.net';
  var formParts = [
    'from=' + encodeURIComponent(MAIL_FROM || 'noreply@' + MAILGUN_DOMAIN),
    'to=' + encodeURIComponent(to),
    'subject=' + encodeURIComponent(subject),
    'html=' + encodeURIComponent(htmlBody)
  ];
  if (BCC_EMAIL) formParts.push('h:Reply-To=' + encodeURIComponent(BCC_EMAIL));
  var formBody = formParts.join('&');
  var auth = Buffer.from('api:' + MAILGUN_API_KEY).toString('base64');
  try {
    var result = await httpsPost(
      'https://' + host + '/v3/' + MAILGUN_DOMAIN + '/messages',
      {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(formBody),
        'Authorization': 'Basic ' + auth
      },
      formBody
    );
    return result.status >= 200 && result.status < 300;
  } catch (e) {
    console.error('[secret] Erreur Mailgun:', e.message);
    return false;
  }
}

/* Validation support-create */
function escapeHTML(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ══════════════════════════════════════════════════════════════
   DOMAIN TOOLS — analyse de domaine (ajouté 2026-04-09, Phase 4 2026-04-13)

   7 endpoints GET pour l'analyse de domaine (cf. aussi la doc en tête de fichier) :
     /api/domain-tools/ip-info?ip=X          → RIPE Stat (netname, org, ASN, CIDR, pays)
     /api/domain-tools/ssl?host=X&port=443   → TLS connect → certificat (site web)
     /api/domain-tools/detect?url=X          → fetch HTTP → CMS/plateforme
     /api/domain-tools/whois?domain=X        → system `whois` command
     /api/domain-tools/mta-sts?domain=X      → fetch mta-sts.txt + parse policy [Phase 4]
     /api/domain-tools/autodiscover?domain=X → CNAME M365 check + HTTP GET [Phase 4]
     /api/domain-tools/autoconfig?domain=X   → fetch + parse XML Thunderbird [Phase 4]

   La résolution DNS (A, AAAA, MX, TXT, CAA, SOA, TLSA, SRV, PTR, CNAME pour DNSSEC
   et FCrDNS et SPF récursif) se fait côté client via Cloudflare DoH. Ces endpoints
   backend sont pour les opérations que le navigateur ne peut pas faire :
     - TLS raw (tls.connect pour le cert du site)
     - Fetch HTTPS cross-origin (mta-sts, autodiscover, autoconfig — bloqués par CORS)
     - WHOIS (protocole whois:// natif)
     - RIPE Stat (garde le compteur serveur)

   Sécurité :
     - Ports whitelistés : 443, 465, 587 (pas de scan arbitraire)
     - Validation domaines/IPs (pas d'IPs privées)
     - Rate limiting : 60 req/min par IP (une analyse ≈ 20-25 requêtes depuis Phase 4)
     - Quota domaine : 10 analyses / 30 min par IP (voir isDomainQuotaReached)
     - Compteur RIPE Stat : max 1000 req/jour (reset minuit UTC)
   ══════════════════════════════════════════════════════════════ */

const tls = require('tls');
const net = require('net');

/* ── Quota Domain Checkup — 10 analyses / 30 min par IP ────────────────────
   Une analyse complète déclenche ~20-25 requêtes backend depuis Phase 4
   (ip-info initial, ssl site, whois, detect, ip-info par MX, mta-sts,
   autodiscover, autoconfig). Ce quota compte les « première requête d'une
   série » (ip-info) comme proxy du nombre d'analyses. Le client applique
   aussi un quota identique côté JS (sessionStorage) ; ce quota serveur est
   le filet de sécurité.
   IP whitelist (SCRT_WHITELIST_IPS env var) is unlimited.
   ──────────────────────────────────────────────────────────────────────────── */

const DOMAIN_QUOTA_MAX = 10;
const DOMAIN_QUOTA_WINDOW = 30 * 60 * 1000; /* 30 min en ms */
const domainQuotaMap = new Map(); /* Map<IP, number[]> (timestamps) */

function isDomainQuotaReached(ip) {
  /* IPs whitelist → jamais limitées */
  if (WHITELIST_IPS.indexOf(ip) !== -1) return false;

  var now = Date.now();
  var ts = domainQuotaMap.get(ip);
  if (!ts) { ts = []; domainQuotaMap.set(ip, ts); }

  /* Purger les timestamps hors fenêtre */
  while (ts.length > 0 && ts[0] < now - DOMAIN_QUOTA_WINDOW) ts.shift();

  if (ts.length >= DOMAIN_QUOTA_MAX) return true;
  ts.push(now);
  return false;
}

/* Nettoyage périodique des IPs inactives (toutes les 10 min) */
setInterval(function () {
  var now = Date.now();
  for (var [ip, ts] of domainQuotaMap) {
    while (ts.length > 0 && ts[0] < now - DOMAIN_QUOTA_WINDOW) ts.shift();
    if (ts.length === 0) domainQuotaMap.delete(ip);
  }
}, 10 * 60 * 1000);

/* Compteur RIPE Stat — max 1000 req/jour */
const RIPE_DAILY_LIMIT = 1000;
var ripeCounter = { count: 0, date: todayUTC() };

function isRipeLimitReached() {
  var today = todayUTC();
  if (ripeCounter.date !== today) { ripeCounter = { count: 0, date: today }; }
  if (ripeCounter.count >= RIPE_DAILY_LIMIT) return true;
  ripeCounter.count++;
  return false;
}

/* Validation IP (pas d'IPs privées) */
function isValidPublicIP(ip) {
  if (!ip || typeof ip !== 'string') return false;
  if (!/^[\d.:a-fA-F]+$/.test(ip)) return false;
  /* Bloquer les IPs privées/réservées */
  if (ip.startsWith('10.') || ip.startsWith('127.') || ip.startsWith('0.')) return false;
  if (ip.startsWith('192.168.') || ip.startsWith('169.254.')) return false;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return false;
  return true;
}

/* Validation hostname (domaine simple, pas d'injection) */
function isValidHostname(host) {
  if (!host || typeof host !== 'string') return false;
  if (host.length > 253) return false;
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/.test(host);
}

/* Ports autorisés pour les connexions TLS */
var ALLOWED_PORTS = [443, 465, 587];

/* Appel HTTPS GET (pour RIPE Stat) */
function httpsGet(url) {
  return new Promise(function (resolve, reject) {
    var parsed = new URL(url);
    https.get({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      headers: { 'Accept': 'application/json' },
      timeout: 10000
    }, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () { resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }); });
    }).on('error', reject).on('timeout', function () { reject(new Error('Timeout')); });
  });
}

/* ── GET /api/domain-tools/ip-info — RIPE Stat lookup ────── */
async function handleIpInfo(req, res) {
  var url = new URL(req.url, 'http://localhost');
  var ip = url.searchParams.get('ip');

  if (!isValidPublicIP(ip)) {
    return jsonResponse(res, 400, { error: 'IP invalide ou privée' });
  }
  if (isRipeLimitReached()) {
    return jsonResponse(res, 429, { error: 'Quota RIPE Stat atteint (1000/jour). Réessayez demain.' });
  }

  try {
    /* Appel RIPE Stat — network-info + whois en parallèle */
    var netResult = await httpsGet('https://stat.ripe.net/data/network-info/data.json?resource=' + encodeURIComponent(ip));
    var whoisResult = await httpsGet('https://stat.ripe.net/data/whois/data.json?resource=' + encodeURIComponent(ip));

    var netData = JSON.parse(netResult.body);
    var whoisData = JSON.parse(whoisResult.body);

    /* Extraire les informations réseau */
    var prefix = (netData.data && netData.data.prefix) || '';
    var asns = (netData.data && netData.data.asns) || [];

    /* Extraire les infos WHOIS (netname, organisation, pays, description).
       RIPE utilise des clés variées selon le RIR : org-name, OrgName, descr, organization. */
    var netname = '', org = '', country = '', descr = '';
    if (whoisData.data && whoisData.data.records) {
      var records = whoisData.data.records;
      for (var r = 0; r < records.length; r++) {
        for (var f = 0; f < records[r].length; f++) {
          var field = records[r][f];
          var k = field.key, v = field.value;
          if (k === 'netname' && !netname) netname = v;
          if ((k === 'org-name' || k === 'OrgName' || k === 'organization') && !org) org = v;
          if ((k === 'country' || k === 'Country') && !country) country = v;
          if (k === 'descr' && !descr) descr = v;
        }
      }
    }

    /* Fallback : si pas d'org, utiliser RIPE abuse-contact-finder pour l'org */
    if (!org && prefix) {
      try {
        var abuseResult = await httpsGet('https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=' + encodeURIComponent(ip));
        var abuseData = JSON.parse(abuseResult.body);
        if (abuseData.data && abuseData.data.authorities) {
          org = abuseData.data.authorities.join(', ');
        }
      } catch (e) {}
    }

    /* Décoder les entités HTML que RIPE peut retourner (ex: "P&amp;T" → "P&T") */
    function de(s) { return s ? s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>') : s; }
    return jsonResponse(res, 200, {
      ip: ip,
      prefix: prefix,
      asn: asns.length > 0 ? asns[0] : null,
      netname: de(netname),
      org: de(org || descr),
      country: country.toUpperCase()
    });

  } catch (e) {
    console.error('[domain-tools] Erreur ip-info:', e.message);
    return jsonResponse(res, 502, { error: 'Erreur RIPE Stat' });
  }
}

/* ── GET /api/domain-tools/ssl — certificat TLS ──────────── */
async function handleSsl(req, res) {
  var url = new URL(req.url, 'http://localhost');
  var host = url.searchParams.get('host');
  var port = parseInt(url.searchParams.get('port') || '443', 10);
  var starttls = url.searchParams.get('starttls') === 'true';

  if (!isValidHostname(host)) {
    return jsonResponse(res, 400, { error: 'Hostname invalide' });
  }
  if (ALLOWED_PORTS.indexOf(port) === -1) {
    return jsonResponse(res, 400, { error: 'Port non autorisé (443, 465, 587)' });
  }

  try {
    var cert;
    if (starttls && port === 587) {
      /* STARTTLS sur port 587 : connexion plain → EHLO → STARTTLS → upgrade TLS */
      cert = await getStarttlsCert(host, port);
    } else {
      /* TLS direct (443, 465) */
      cert = await getTlsCert(host, port);
    }

    if (!cert) {
      return jsonResponse(res, 502, { error: 'Impossible de récupérer le certificat' });
    }

    /* Parser les infos du certificat */
    var now = new Date();
    var validFrom = new Date(cert.valid_from);
    var validTo = new Date(cert.valid_to);
    var daysLeft = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

    var status = 'valid';
    if (validTo < now) status = 'expired';
    else if (daysLeft < 30) status = 'expiring';

    /* Déterminer le type (DV/OV/EV) depuis l'organisation dans le sujet */
    var certType = 'DV';
    if (cert.subject && cert.subject.O) {
      certType = cert.subject.businessCategory ? 'EV' : 'OV';
    }

    return jsonResponse(res, 200, {
      host: host,
      port: port,
      issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Unknown') : 'Unknown',
      subject: cert.subject ? (cert.subject.CN || '') : '',
      sans: cert.subjectaltname ? cert.subjectaltname.split(', ').map(function (s) { return s.replace('DNS:', ''); }) : [],
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      daysLeft: daysLeft,
      status: status,
      type: certType,
      serialNumber: cert.serialNumber || ''
    });

  } catch (e) {
    console.error('[domain-tools] Erreur ssl:', e.message);
    return jsonResponse(res, 502, { error: 'Erreur connexion TLS: ' + e.message });
  }
}

/* Récupérer le certificat via TLS direct (port 443, 465) */
function getTlsCert(host, port) {
  return new Promise(function (resolve, reject) {
    var socket = tls.connect({
      host: host,
      port: port,
      servername: host,
      rejectUnauthorized: false, /* accepter les certs auto-signés pour l'analyse */
      timeout: 8000
    }, function () {
      var cert = socket.getPeerCertificate(true);
      socket.destroy();
      resolve(cert && cert.subject ? cert : null);
    });
    socket.on('error', function (e) { reject(e); });
    socket.on('timeout', function () { socket.destroy(); reject(new Error('Timeout TLS')); });
  });
}

/* Récupérer le certificat via STARTTLS (port 587) */
function getStarttlsCert(host, port) {
  return new Promise(function (resolve, reject) {
    var socket = net.connect({ host: host, port: port, timeout: 8000 }, function () {
      var buffer = '';
      socket.setEncoding('utf8');
      socket.on('data', function (data) {
        buffer += data;
        /* Attendre le banner SMTP */
        if (buffer.indexOf('220 ') !== -1 && buffer.indexOf('\r\n') !== -1) {
          socket.write('EHLO toolbox.local\r\n');
          buffer = '';
        }
        /* Attendre la réponse EHLO */
        if (buffer.indexOf('250 ') !== -1 && buffer.indexOf('STARTTLS') !== -1) {
          socket.write('STARTTLS\r\n');
          buffer = '';
        }
        /* Attendre le 220 Ready pour STARTTLS */
        if (buffer.indexOf('220 ') !== -1 && buffer.indexOf('ready') !== -1) {
          /* Upgrade vers TLS */
          var tlsSocket = tls.connect({
            socket: socket,
            servername: host,
            rejectUnauthorized: false,
            timeout: 8000
          }, function () {
            var cert = tlsSocket.getPeerCertificate(true);
            tlsSocket.destroy();
            resolve(cert && cert.subject ? cert : null);
          });
          tlsSocket.on('error', function (e) { reject(e); });
        }
      });
    });
    socket.on('error', function (e) { reject(e); });
    socket.on('timeout', function () { socket.destroy(); reject(new Error('Timeout STARTTLS')); });
  });
}

/* ── GET /api/domain-tools/detect — détection CMS/plateforme ── */
/* ── GET /api/domain-tools/whois — WHOIS via system command ── */
async function handleWhois(req, res) {
  var url = new URL(req.url, 'http://localhost');
  var domain = url.searchParams.get('domain');

  if (!isValidHostname(domain)) {
    return jsonResponse(res, 400, { error: 'Domain invalide' });
  }

  var childProcess = require('child_process');
  try {
    var output = childProcess.execSync('whois ' + domain, { timeout: 10000, encoding: 'utf8', maxBuffer: 50000 });

    /* Parser le WHOIS brut — extraire les champs clés */
    var lines = output.split('\n');
    var data = { raw: '', registrant: '', org: '', country: '', nservers: [], created: '', expires: '', updated: '', registrar: '' };

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (line.startsWith('%') || !line) continue;
      data.raw += line + '\n';

      var colonIdx = line.indexOf(':');
      if (colonIdx === -1) continue;
      var key = line.substring(0, colonIdx).trim().toLowerCase();
      var val = line.substring(colonIdx + 1).trim();
      if (!val) continue;

      if (key === 'registrant' || key === 'org-name' || key === 'registrant-name') data.registrant = data.registrant || val;
      if (key === 'org' || key === 'organisation' || key === 'registrant organization') data.org = data.org || val;
      if (key === 'org-country' || key === 'registrant-country' || key === 'registrant country') data.country = data.country || val;
      if (key === 'nserver' || key === 'name server') data.nservers.push(val.toLowerCase());
      if (key === 'registered' || key === 'creation date' || key === 'created') data.created = data.created || val;
      if (key === 'expire' || key === 'registry expiry date' || key === 'expiry date') data.expires = data.expires || val;
      if (key === 'changed' || key === 'updated date' || key === 'last-update') data.updated = data.updated || val;
      if (key === 'registrar' || key === 'registrar-name') data.registrar = data.registrar || val;
      /* .lu specific */
      if (key === 'ownertype') data.org = data.org || (val === 'ORGANISATION' ? 'Organization' : val);
    }

    return jsonResponse(res, 200, data);
  } catch (e) {
    console.error('[domain-tools] Erreur whois:', e.message);
    return jsonResponse(res, 502, { error: 'WHOIS query failed' });
  }
}

async function handleDetect(req, res) {
  var url = new URL(req.url, 'http://localhost');
  var targetUrl = url.searchParams.get('url');

  if (!targetUrl || typeof targetUrl !== 'string') {
    return jsonResponse(res, 400, { error: 'URL requise' });
  }
  /* Valider et normaliser l'URL */
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }
  var parsedUrl;
  try { parsedUrl = new URL(targetUrl); } catch (e) {
    return jsonResponse(res, 400, { error: 'URL invalide' });
  }
  if (!isValidHostname(parsedUrl.hostname)) {
    return jsonResponse(res, 400, { error: 'Hostname invalide' });
  }

  try {
    /* Fetch la page d'accueil */
    var result = await httpsGet(targetUrl);
    var headers = {};
    var body = result.body || '';

    /* Analyser les headers et le body pour détecter la plateforme */
    var detected = [];

    /* WordPress */
    if (body.indexOf('/wp-content/') !== -1 || body.indexOf('/wp-includes/') !== -1) detected.push('WordPress');
    if (body.indexOf('name="generator" content="WordPress') !== -1) detected.push('WordPress');

    /* Wix */
    if (body.indexOf('wixstatic.com') !== -1 || body.indexOf('X-Wix') !== -1) detected.push('Wix');

    /* Squarespace */
    if (body.indexOf('squarespace.com') !== -1 || body.indexOf('sqsp.net') !== -1) detected.push('Squarespace');

    /* Shopify */
    if (body.indexOf('cdn.shopify.com') !== -1) detected.push('Shopify');

    /* Webflow */
    if (body.indexOf('webflow.io') !== -1 || body.indexOf('Webflow') !== -1) detected.push('Webflow');

    /* Next.js */
    if (body.indexOf('/_next/') !== -1) detected.push('Next.js');

    /* Hugo */
    if (body.indexOf('name="generator" content="Hugo') !== -1) detected.push('Hugo');

    /* Ghost */
    if (body.indexOf('name="generator" content="Ghost') !== -1) detected.push('Ghost');

    /* Joomla */
    if (body.indexOf('/media/jui/') !== -1 || body.indexOf('name="generator" content="Joomla') !== -1) detected.push('Joomla');

    /* Drupal */
    if (body.indexOf('X-Generator: Drupal') !== -1 || body.indexOf('X-Drupal') !== -1) detected.push('Drupal');

    /* Extraire le header Server depuis le body (les headers ne sont pas accessibles via httpsGet simple) */
    /* On va refaire la requête avec les headers */
    var serverHeader = '';
    var poweredBy = '';
    var metaGenerator = '';

    /* Extraire meta generator */
    var genMatch = body.match(/name=["']generator["']\s+content=["']([^"']+)["']/i);
    if (genMatch) metaGenerator = genMatch[1];

    /* Détection basée sur meta generator */
    if (metaGenerator && detected.length === 0) {
      detected.push(metaGenerator);
    }

    /* Cloudflare */
    if (body.indexOf('cf-ray') !== -1 || body.indexOf('__cf_bm') !== -1) {
      detected.push('Cloudflare (CDN/Proxy)');
    }

    return jsonResponse(res, 200, {
      url: targetUrl,
      platforms: detected.length > 0 ? detected : ['Custom / Non détecté'],
      metaGenerator: metaGenerator || null
    });

  } catch (e) {
    console.error('[domain-tools] Erreur detect:', e.message);
    return jsonResponse(res, 502, { error: 'Erreur fetch: ' + e.message });
  }
}

/* ══════════════════════════════════════════════════════════════
   DOMAIN TOOLS — MTA-STS / Autodiscover / Autoconfig (2026-04-13)
   Ces 3 endpoints font des fetch HTTPS que le navigateur ne peut pas
   faire (CORS). rejectUnauthorized:false pour ne pas échouer sur un
   cert expiré — on veut diagnostiquer, pas refuser la connexion.
   ══════════════════════════════════════════════════════════════ */

/* Helper HTTPS générique : GET/HEAD avec timeout, accepte certs invalides
   pour diagnostic. Retourne {status, body, tlsValid, error?}.
   tlsValid est capturé via l'event 'secureConnect' sur le socket — c'est le
   seul moment fiable où `socket.authorized` reflète la validation réelle.
   User-Agent au format "Mozilla/5.0 (compatible; ...)" : Cloudflare Bot Fight
   Mode bloque les UA custom non-navigateur avec 403, le préfixe "Mozilla/5.0
   (compatible;" est la convention pour les bots transparents acceptés (fix
   required to avoid 403 on Cloudflare-proxied targets). */
function httpsFetchRaw(targetUrl, method) {
  return new Promise(function (resolve) {
    var parsed;
    try { parsed = new URL(targetUrl); } catch (e) {
      return resolve({ error: 'Invalid URL' });
    }
    var tlsValid = false;
    var req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: method || 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; toolbox-domain-checker/1.0; +https://github.com/Lux-WorldPC/toolbox)' },
      timeout: 5000,
      rejectUnauthorized: false
    }, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        resolve({
          status: res.statusCode,
          body: Buffer.concat(chunks).toString('utf8'),
          tlsValid: tlsValid
        });
      });
    });
    req.on('socket', function (socket) {
      socket.on('secureConnect', function () {
        tlsValid = socket.authorized === true;
      });
    });
    req.on('error', function (e) { resolve({ error: e.code || e.message }); });
    req.on('timeout', function () { req.destroy(); resolve({ error: 'Timeout' }); });
    req.end();
  });
}

/* ── GET /api/domain-tools/mta-sts ──
   Fetch https://mta-sts.{domain}/.well-known/mta-sts.txt et parse la policy.
   Le TXT record _mta-sts.{domain} est vérifié côté client via DoH. */
async function handleMtaSts(req, res) {
  var url = new URL(req.url, 'http://localhost');
  var domain = url.searchParams.get('domain');
  if (!isValidHostname(domain)) {
    return jsonResponse(res, 400, { error: 'Domain invalide' });
  }
  var policyUrl = 'https://mta-sts.' + domain + '/.well-known/mta-sts.txt';
  var result = await httpsFetchRaw(policyUrl, 'GET');

  if (result.error) {
    return jsonResponse(res, 200, { found: false, reason: result.error });
  }
  if (result.status !== 200) {
    return jsonResponse(res, 200, { found: false, reason: 'HTTP ' + result.status });
  }

  /* Parse la policy — format ligne par ligne "key: value" (RFC 8461 §3.2) */
  var policy = { version: null, mode: null, maxAge: null, mx: [] };
  var lines = result.body.split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line || line.indexOf(':') === -1) continue;
    var k = line.substring(0, line.indexOf(':')).trim().toLowerCase();
    var v = line.substring(line.indexOf(':') + 1).trim();
    if (k === 'version') policy.version = v;
    else if (k === 'mode') policy.mode = v;
    else if (k === 'max_age') policy.maxAge = parseInt(v, 10);
    else if (k === 'mx') policy.mx.push(v);
  }
  return jsonResponse(res, 200, {
    found: true,
    tlsValid: result.tlsValid,
    policy: policy,
    raw: result.body.substring(0, 2000)
  });
}

/* ── GET /api/domain-tools/autodiscover ──
   Check de présence de l'endpoint Autodiscover (Exchange/M365).
   Stratégie en 2 étapes :
     1) Résolution DNS du CNAME autodiscover.{domain} — si ça pointe vers
        un endpoint M365 connu (autodiscover.outlook.com), c'est OK. Microsoft
        refuse les GET plain (connection reset), donc le check HTTP ne peut
        pas fonctionner pour M365 → le CNAME est la preuve suffisante.
     2) Tentative HTTP GET sur autodiscover.{domain} et {domain} racine, pour
        les Exchange on-prem qui répondent 200/401/301/302/405. */
async function handleAutodiscover(req, res) {
  var url = new URL(req.url, 'http://localhost');
  var domain = url.searchParams.get('domain');
  if (!isValidHostname(domain)) {
    return jsonResponse(res, 400, { error: 'Domain invalide' });
  }

  /* Étape 1 — résolution CNAME autodiscover.{domain} */
  var cnameTarget = null;
  var detectedProvider = null;
  try {
    var cnameRes = await new Promise(function (resolve) {
      dns.resolveCname('autodiscover.' + domain, function (err, addrs) {
        resolve(err ? null : (addrs && addrs[0]) || null);
      });
    });
    if (cnameRes) {
      cnameTarget = cnameRes.toLowerCase().replace(/\.$/, '');
      /* Microsoft a plusieurs domaines : outlook.com historique + cloud.microsoft
         (nouveau depuis 2024) + office365.com + protection.outlook.com */
      if (cnameTarget.indexOf('outlook.com') !== -1 ||
          cnameTarget.indexOf('office365.com') !== -1 ||
          cnameTarget.indexOf('cloud.microsoft') !== -1 ||
          cnameTarget.indexOf('microsoft.com') !== -1) {
        detectedProvider = 'Microsoft 365';
      } else if (cnameTarget.indexOf('googlemail.com') !== -1 ||
                 cnameTarget.indexOf('google.com') !== -1) {
        detectedProvider = 'Google Workspace';
      }
    }
  } catch (e) {}

  /* Étape 2 — check HTTP (pour Exchange on-prem et autres) */
  var candidates = [
    'https://autodiscover.' + domain + '/autodiscover/autodiscover.xml',
    'https://' + domain + '/autodiscover/autodiscover.xml'
  ];
  var results = [];
  for (var i = 0; i < candidates.length; i++) {
    var r = await httpsFetchRaw(candidates[i], 'GET');
    /* 200 = OK, 401/403 = auth required (existe), 405 = méthode refusée (existe),
       301/302 = redirect (typique Microsoft Exchange Online). */
    var present = !r.error && (r.status === 200 || r.status === 401 ||
                               r.status === 403 || r.status === 405 ||
                               r.status === 301 || r.status === 302);
    results.push({
      url: candidates[i],
      present: present,
      status: r.status || null,
      error: r.error || null,
      tlsValid: r.tlsValid || false
    });
    if (present) break;
  }
  var httpPresent = results.some(function (r) { return r.present; });
  var found = httpPresent || detectedProvider !== null;

  return jsonResponse(res, 200, {
    found: found,
    cnameTarget: cnameTarget,
    detectedProvider: detectedProvider,
    endpoints: results
  });
}

/* ── GET /api/domain-tools/autoconfig ──
   Récupère le XML Thunderbird autoconfig et extrait incoming/outgoing.
   Ordre de recherche :
     1) https://autoconfig.{domain}/mail/config-v1.1.xml  (auto-hébergé prioritaire)
     2) https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml
     3) https://autoconfig.thunderbird.net/v1.1/{domain}  (ISPDB Mozilla community)
   L'ISPDB est signalé par `source: "mozilla-ispdb"` dans la réponse — pour
   qu'un consultant puisse distinguer "le domaine publie lui-même" vs
   "la config vient de la community database". */
async function handleAutoconfig(req, res) {
  var url = new URL(req.url, 'http://localhost');
  var domain = url.searchParams.get('domain');
  if (!isValidHostname(domain)) {
    return jsonResponse(res, 400, { error: 'Domain invalide' });
  }
  var candidates = [
    { url: 'https://autoconfig.' + domain + '/mail/config-v1.1.xml?emailaddress=test@' + domain,
      source: 'self-hosted' },
    { url: 'https://' + domain + '/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=test@' + domain,
      source: 'well-known' },
    { url: 'https://autoconfig.thunderbird.net/v1.1/' + domain,
      source: 'mozilla-ispdb' }
  ];
  var xml = null;
  var sourceUrl = null;
  var sourceType = null;
  var tlsValid = false;
  for (var i = 0; i < candidates.length; i++) {
    var r = await httpsFetchRaw(candidates[i].url, 'GET');
    if (!r.error && r.status === 200 && r.body && r.body.indexOf('clientConfig') !== -1) {
      xml = r.body;
      sourceUrl = candidates[i].url;
      sourceType = candidates[i].source;
      tlsValid = r.tlsValid;
      break;
    }
  }
  if (!xml) {
    return jsonResponse(res, 200, { found: false });
  }

  /* Parser regex : extraire chaque <incomingServer type="..."> et <outgoingServer type="..."> */
  function parseServers(tag) {
    var servers = [];
    var re = new RegExp('<' + tag + '\\s+type="([^"]+)"[^>]*>([\\s\\S]*?)</' + tag + '>', 'g');
    var m;
    while ((m = re.exec(xml)) !== null) {
      var type = m[1];
      var block = m[2];
      function pick(field) {
        var mm = block.match(new RegExp('<' + field + '>([^<]+)</' + field + '>'));
        return mm ? mm[1].trim() : null;
      }
      servers.push({
        type: type,
        hostname: pick('hostname'),
        port: pick('port') ? parseInt(pick('port'), 10) : null,
        socketType: pick('socketType'),
        authentication: pick('authentication')
      });
    }
    return servers;
  }

  var providerMatch = xml.match(/<emailProvider[^>]*id="([^"]+)"/);
  return jsonResponse(res, 200, {
    found: true,
    source: sourceUrl,
    sourceType: sourceType,
    tlsValid: tlsValid,
    providerId: providerMatch ? providerMatch[1] : null,
    incoming: parseServers('incomingServer'),
    outgoing: parseServers('outgoingServer')
  });
}

/* ══════════════════════════════════════════════════════════════
   WHAT'S MY IP — ajouté 2026-04-10
   GET /api/myip?ip=X → reverse DNS + infos RIPE pour l'IP donnée.
   L'IP est fournie par le client (obtenue via Cloudflare trace côté navigateur,
   car HAProxy voit l'IP NATée interne 172.16.x.x, pas la vraie IP publique).
   Fallback sur X-Forwarded-For si pas de paramètre ?ip=.
   Retourne whitelisted:true si l'IP est dans SCRT_WHITELIST_IPS (quota client masqué).
   Reverse DNS via Node.js dns.reverse() natif.
   Infos réseau via RIPE Stat (même API que Domain Checkup ip-info).
   ══════════════════════════════════════════════════════════════ */

var dns = require('dns');

function reverseDns(ip) {
  return new Promise(function (resolve) {
    dns.reverse(ip, function (err, hostnames) {
      resolve(err ? null : (hostnames && hostnames[0]) || null);
    });
  });
}

async function handleMyIp(req, res) {
  /* L'IP peut être passée en paramètre ?ip=X (le JS client la récupère via Cloudflare trace,
     car HAProxy voit l'IP NATée interne, pas la vraie IP publique du visiteur).
     Si pas de paramètre → fallback sur X-Forwarded-For. */
  var url = new URL(req.url, 'http://localhost');
  var ip = url.searchParams.get('ip') || getClientIp(req);

  /* Reverse DNS */
  var rdns = await reverseDns(ip);

  /* RIPE Stat — même logique que handleIpInfo mais sans vérification isValidPublicIP
     (l'IP du client est toujours publique via HAProxy) */
  var ripeData = { org: '', netname: '', prefix: '', asn: null, country: '' };
  try {
    var netResult = await httpsGet('https://stat.ripe.net/data/network-info/data.json?resource=' + encodeURIComponent(ip));
    var whoisResult = await httpsGet('https://stat.ripe.net/data/whois/data.json?resource=' + encodeURIComponent(ip));
    var netD = JSON.parse(netResult.body);
    var whoisD = JSON.parse(whoisResult.body);

    ripeData.prefix = (netD.data && netD.data.prefix) || '';
    var asns = (netD.data && netD.data.asns) || [];
    if (asns.length) ripeData.asn = asns[0];

    if (whoisD.data && whoisD.data.records) {
      for (var r = 0; r < whoisD.data.records.length; r++) {
        for (var f = 0; f < whoisD.data.records[r].length; f++) {
          var field = whoisD.data.records[r][f];
          var k = field.key, v = field.value;
          if (k === 'netname' && !ripeData.netname) ripeData.netname = v;
          if ((k === 'org-name' || k === 'OrgName' || k === 'organization') && !ripeData.org) ripeData.org = v;
          if ((k === 'country' || k === 'Country') && !ripeData.country) ripeData.country = v;
          if (k === 'descr' && !ripeData.org) ripeData.org = v;
        }
      }
    }
  } catch (e) { /* RIPE indisponible — on retourne quand même l'IP */ }

  /* Décoder les entités HTML que RIPE peut retourner (ex: "P&amp;T" → "P&T").
     Sans ça, esc() côté JS double-encode → affiche "P&amp;T" à l'écran. */
  function decodeEntities(s) { return s ? s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>') : s; }

  return jsonResponse(res, 200, {
    ip: ip,
    reverse: rdns,
    org: decodeEntities(ripeData.org),
    netname: decodeEntities(ripeData.netname),
    prefix: ripeData.prefix,
    asn: ripeData.asn,
    country: ripeData.country ? ripeData.country.toUpperCase() : '',
    whitelisted: WHITELIST_IPS.indexOf(ip) !== -1
  });
}

/* ══════════════════════════════════════════════════════════════
   EMAIL REPORT — envoi du rapport d'analyse email par Mailgun (ajouté 2026-04-10)
   POST /api/email-report { to, subject, html }
   Le JS client construit le HTML du rapport, le backend l'envoie via Mailgun.
   Optional BCC via BCC_EMAIL env var.
   ══════════════════════════════════════════════════════════════ */

async function handleEmailReport(req, res) {
  var rawBody;
  try { rawBody = await readBody(req, 64 * 1024); } catch (e) {
    return jsonResponse(res, 413, { error: 'Payload trop volumineux' });
  }
  var body;
  try { body = JSON.parse(rawBody); } catch (e) {
    return jsonResponse(res, 400, { error: 'JSON invalide' });
  }

  if (!body.to || typeof body.to !== 'string' || body.to.indexOf('@') === -1) {
    return jsonResponse(res, 400, { error: 'Email invalide' });
  }
  if (!body.html || typeof body.html !== 'string') {
    return jsonResponse(res, 400, { error: 'Contenu manquant' });
  }

  var subject = body.subject || 'Email Header Analysis Report';
  var htmlContent = emailWrap('Report', body.html);

  if (!MAILGUN_API_KEY || !MAILGUN_DOMAIN) {
    return jsonResponse(res, 500, { error: 'Mailgun not configured' });
  }
  var host = MAILGUN_REGION === 'eu' ? 'api.eu.mailgun.net' : 'api.mailgun.net';
  var formParts = [
    'from=' + encodeURIComponent(MAIL_FROM || 'noreply@' + MAILGUN_DOMAIN),
    'to=' + encodeURIComponent(body.to.trim()),
    'subject=' + encodeURIComponent(subject),
    'html=' + encodeURIComponent(htmlContent)
  ];
  if (BCC_EMAIL) {
    formParts.push('bcc=' + encodeURIComponent(BCC_EMAIL));
    formParts.push('h:Reply-To=' + encodeURIComponent(BCC_EMAIL));
  }
  var formBody = formParts.join('&');
  var auth = Buffer.from('api:' + MAILGUN_API_KEY).toString('base64');

  try {
    var result = await httpsPost(
      'https://' + host + '/v3/' + MAILGUN_DOMAIN + '/messages',
      { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(formBody), 'Authorization': 'Basic ' + auth },
      formBody
    );
    if (result.status >= 200 && result.status < 300) {
      console.log('[email-report] Report sent to ' + body.to);
      return jsonResponse(res, 200, { ok: true });
    }
    console.error('[email-report] Mailgun ' + result.status + ': ' + result.body);
    return jsonResponse(res, 502, { error: 'Mailgun error' });
  } catch (e) {
    console.error('[email-report] Error:', e.message);
    return jsonResponse(res, 502, { error: 'Send failed' });
  }
}

/* ══════════════════════════════════════════════════════════════
   HTTP SERVER
   ══════════════════════════════════════════════════════════════ */

const server = http.createServer(async function (req, res) {
  const clientIp = getClientIp(req);

  if (req.method === 'POST' && req.url === '/secret/api/create') {
    if (isRateLimited(clientIp, 20)) {
      return jsonResponse(res, 429, { error: 'Trop de requêtes. Réessayez dans 1 minute.' });
    }
    try { await handleCreate(req, res); } catch (e) {
      console.error('[secret] Erreur create:', e);
      jsonResponse(res, 500, { error: 'Erreur interne' });
    }

  } else if (req.method === 'POST' && req.url === '/secret/api/reveal') {
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Trop de requêtes.' });
    }
    try { await handleReveal(req, res); } catch (e) {
      console.error('[secret] Erreur reveal:', e);
      jsonResponse(res, 500, { error: 'Erreur interne' });
    }

  /* ── Domain Tools endpoints ──
     Quota : 10 analyses / 30 min par IP (isDomainQuotaReached vérifié sur ip-info,
     car c'est le premier appel de chaque analyse). Whitelist IPs illimitées.
     Rate limit par minute en complément (isRateLimited). */
  } else if (req.method === 'GET' && req.url.startsWith('/api/domain-tools/ip-info')) {
    /* ip-info = premier appel d'une analyse → vérifie le quota 30 min */
    if (isDomainQuotaReached(clientIp)) {
      return jsonResponse(res, 429, { error: 'Voluntarily limited to 10 analyses per 30 min. Please try again later.' });
    }
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleIpInfo(req, res); } catch (e) {
      console.error('[domain-tools] Erreur ip-info:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  } else if (req.method === 'GET' && req.url.startsWith('/api/domain-tools/ssl')) {
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleSsl(req, res); } catch (e) {
      console.error('[domain-tools] Erreur ssl:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  } else if (req.method === 'GET' && req.url.startsWith('/api/domain-tools/whois')) {
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleWhois(req, res); } catch (e) {
      console.error('[domain-tools] Erreur whois:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  } else if (req.method === 'GET' && req.url.startsWith('/api/domain-tools/detect')) {
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleDetect(req, res); } catch (e) {
      console.error('[domain-tools] Erreur detect:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  } else if (req.method === 'GET' && req.url.startsWith('/api/domain-tools/mta-sts')) {
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleMtaSts(req, res); } catch (e) {
      console.error('[domain-tools] Erreur mta-sts:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  } else if (req.method === 'GET' && req.url.startsWith('/api/domain-tools/autodiscover')) {
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleAutodiscover(req, res); } catch (e) {
      console.error('[domain-tools] Erreur autodiscover:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  } else if (req.method === 'GET' && req.url.startsWith('/api/domain-tools/autoconfig')) {
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleAutoconfig(req, res); } catch (e) {
      console.error('[domain-tools] Erreur autoconfig:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  /* ── What's My IP ── */
  } else if (req.method === 'GET' && req.url.startsWith('/api/myip')) {
    if (isRateLimited(clientIp, 60)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleMyIp(req, res); } catch (e) {
      console.error('[myip] Erreur:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  /* ── eMail Checkup — envoi rapport par email ── */
  } else if (req.method === 'POST' && req.url === '/api/email-report') {
    if (isRateLimited(clientIp, 10)) {
      return jsonResponse(res, 429, { error: 'Too many requests.' });
    }
    try { await handleEmailReport(req, res); } catch (e) {
      console.error('[email-report] Erreur:', e);
      jsonResponse(res, 500, { error: 'Internal error' });
    }

  } else {
    jsonResponse(res, 404, { error: 'Endpoint non trouvé' });
  }
});

var LISTEN_HOST = process.env.LISTEN_HOST || '127.0.0.1';
server.listen(PORT, LISTEN_HOST, function () {
  console.log('[secret-proxy] Listening on ' + LISTEN_HOST + ':' + PORT);
  console.log('[secret-proxy] Secrets storage: ' + SECRETS_DIR);
});
