/**
 * Email Header Analyzer — détection spoofing + compromise/BEC + analyse PDF.
 * @lwpc/toolbox (MIT) — frontend. Backend : POST /api/email-report (optionnel,
 * utilisé uniquement si l'utilisateur demande le rapport par email).
 *
 * Phase 3 (2026-04-23) — détection boîte compromise / account takeover :
 *   Quand SPF+DKIM+DMARC passent, le spoofing est écarté mais la boîte
 *   peut être compromise (mail réellement envoyé depuis une session
 *   authentifiée). Les heuristiques d'auth ne suffisent plus — il faut
 *   lire le contenu. Signaux cumulés :
 *     - From == To (pattern mass-Bcc)
 *     - References chain contenant des tenants M365 sans rapport +
 *       domaines étrangers (reply-chain phishing)
 *     - Liens vers plateformes no-code fréquemment détournées (plasmic.run,
 *       netlify.app, vercel.app, pages.dev, firebaseapp.com, github.io, …)
 *     - Brand-in-subdomain (ex: kopstal.plasmic.run)
 *     - URL shorteners, IDN/Punycode, IP brute, anchor ≠ href
 *     - Phrases typiques kits phishing M365/OneDrive/SharePoint/DocuSign
 *   Verdict : score >= 6 ou (auth pass + score >= 4) → danger takeover,
 *             score >= 3 → warning suspicious.
 *   Bandeau critique : titre dynamique "Account takeover suspected" +
 *   liste des indicateurs + table des liens suspects détaillée.
 *
 * 100% client-side : le contenu de l'email ne quitte jamais le navigateur (privacy-first).
 * Supporte : headers bruts collés OU fichier .eml complet (copier-coller, upload ou drag & drop).
 *
 * Analyses de sécurité (détection de spoofing — 6 vérifications) :
 *   1. DKIM-Signature manquante mais Authentication-Results prétend dkim=pass → forgé
 *   2. Return-Path manquant → n'a pas suivi le chemin SMTP normal
 *   3. Received headers : hop Internet → destinataire manquant (tous internes à l'expéditeur)
 *      "Pas d'IP" (Outlook 365, cloud) ≠ "IP privée" — pas de faux positif.
 *   4. Authentication-Results : alerte uniquement si TOUS les AR viennent du sender
 *      et qu'aucun tiers (ARC, X-MS-Exchange) n'a vérifié.
 *   5. Timestamps identiques + IPs privées (indicateur cumulatif, pas seul).
 *   6. Return-Path misaligned vs From (Phase 2, relaxed organizational domain match)
 *
 * Parsers étendus Phase 2 (2026-04-13) — cf. section "PARSERS ÉTENDUS" :
 *   - parseAuthResults enrichi : compauth (Microsoft composite auth) + arc= result
 *   - parseArcChain : analyse ARC-Authentication-Results / Message-Signature / Seal
 *     avec détection du cv= sur le dernier seal pour valider la chaîne
 *   - parseMsAntispam : décode X-Forefront-Antispam-Report (SCL/BCL/PCL/SFV/CIP/CTRY/LANG/SFTY)
 *     + X-MS-Exchange-Organization-SCL + X-Microsoft-Antispam
 *   - parseListUnsubscribe : présence + one-click RFC 8058 (List-Unsubscribe-Post)
 *   - detectMailClient : 20+ clients mappés vers {name, version, platform} — Outlook,
 *     Thunderbird, Apple Mail iOS/macOS, Gmail, ProtonMail, Roundcube, Zoho, API transactionnels
 *   - detectEsp : détection Email Service Provider via signaux multiples (headers
 *     X-Mailgun/X-SG-/X-Mailchimp/X-Brevo/X-Klaviyo/X-HubSpot/..., Return-Path, Feedback-ID)
 *     → 20+ plateformes marketing + transactionnelles (Mailchimp, Brevo, MailerLite,
 *       HubSpot, Klaviyo, ActiveCampaign, ConvertKit, Campaign Monitor, Constant Contact,
 *       Mailgun, SendGrid, Amazon SES, Postmark, SparkPost, Mailjet, etc.)
 *   - checkAlignment : Return-Path vs From — organizational domain match (relaxed)
 *   - calcTotalDelay : délai total premier → dernier Received
 *
 * Rendu Phase 2 (2026-04-13) :
 *   - renderRouteTimeline : SVG vanilla (pas de lib) au-dessus du tableau Received.
 *     Markers circulaires numérotés, ligne horizontale, délais relatifs en badges,
 *     TLS indicator, IP + host court. Scroll horizontal si > largeur conteneur.
 *   - Summary : lignes enrichies (ESP badge, Mail client détecté, Return-Path +
 *     alignment, List-Unsubscribe + one-click)
 *   - DKIM card : ligne "ARC chain: valid (N hops)" si ARC présent
 *   - DMARC card : ligne "compauth=pass reason=100" si Microsoft
 *   - Nouvelle 5e carte "Microsoft Antispam" dans la section Authentication
 *   - Section Route titre : "— total X.Xs" (délai premier → dernier hop)
 *
 * Analyse pièces jointes PDF (.eml complet) :
 *   - Extraction MIME multipart (base64 → Uint8Array)
 *   - Métadonnées PDF basiques (Creator, Producer, dates) : regex sur le raw PDF
 *   - Nombre de pages : regex /Type /Page
 *   - Extraction texte complète via pdf.js (chargé dynamiquement, /js/pdf.min.mjs)
 *   - Détection IBANs (regex, flag rouge si pays ≠ LU pour entreprise LU)
 *   - Détection URLs (typosquatting visible)
 *   - Alerte Creator ≠ Producer : uniquement si paire inconnue (pas wkhtmltopdf+Qt, Chromium+Skia, etc.)
 *
 * Bandeau critique (#eml-critical) :
 *   Si des alertes "danger" sont détectées → bandeau rouge pulsant tout en haut des résultats,
 *   avec scroll automatique. Résume les red flags les plus graves.
 *   Titre dynamique (Phase 3) :
 *     - verdict compromise → "Account takeover suspected" (classe .eml-critical-compromise,
 *       pulse plus rapide + bordure jaune). i18n 4 langues via data-lbl-takeover.
 *     - autres dangers → "Suspicious email detected" (i18n via data-lbl-spoof).
 *
 * Actions (boutons en haut des résultats) :
 *   - "Envoyer au support" → sessionStorage ticket_prefill → redirige vers la page ticket
 *   - "Recevoir le rapport par email" → champ email → POST /api/email-report
 *     (Mailgun côté backend, BCC configurable via BCC_EMAIL env)
 *
 * Quota : 10 analyses / 30 min (sessionStorage 'eml_analyses').
 *   Bypass client : window.lwpcWhitelisted → skip quota + message "Whitelisted".
 * Réutilise les classes CSS Domain Checkup (.domain-card, .domain-badge, .domain-table, etc.).
 */
(function () {
  'use strict';

  /* API endpoint base — override via `window.LWPC_API_BASE = 'https://api.example.com'`
     before loading this script. Default: same-origin. */
  var API_BASE = (typeof window !== 'undefined' && window.LWPC_API_BASE) || '';

  /* Subject of the report email sent via /api/email-report — customizable. */
  var EMAIL_REPORT_SUBJECT = (typeof window !== 'undefined' && window.LWPC_EMAIL_REPORT_SUBJECT)
    || 'Email Header Analysis Report';

  var rawInput   = document.getElementById('eml-raw');
  var analyzeBtn = document.getElementById('eml-analyze');
  var clearBtn   = document.getElementById('eml-clear');
  var resultsDiv = document.getElementById('eml-results');
  var fileInput  = document.getElementById('eml-file');
  if (!rawInput || !analyzeBtn) return;

  /* ── Quota — 10 / 30 min (même pattern que les autres outils) ── */
  var QM = 10, QW = 30 * 60 * 1000, QK = 'eml_analyses';
  var qEl = document.getElementById('eml-quota-msg');
  function qGet() { try { var d = JSON.parse(sessionStorage.getItem(QK)); if (d && Array.isArray(d.ts)) return d; } catch (e) {} return { ts: [] }; }
  function qSave(d) { sessionStorage.setItem(QK, JSON.stringify(d)); }
  function qPurge() { var d = qGet(), n = Date.now(); d.ts = d.ts.filter(function (t) { return t > n - QW; }); qSave(d); return d; }
  function qCheck() { return window.lwpcWhitelisted || qPurge().ts.length < QM; }
  function qRecord() { var d = qPurge(); d.ts.push(Date.now()); qSave(d); }
  function qRemain() { return QM - qPurge().ts.length; }
  function qLbl(k, f) { return (qEl && qEl.dataset['lbl' + k]) || f; }
  function qUpdate() {
    if (window.lwpcWhitelisted || !qEl) return;
    var r = qRemain(), b = qLbl('Limited', 'Voluntarily limited to') + ' ' + QM + ' ' + qLbl('Unit', 'analyses') + ' / 30 min';
    if (r <= 0) { qEl.innerHTML = '⚠ ' + b + ' — <strong>0</strong> ' + qLbl('Remaining', 'remaining') + '. ' + qLbl('Blocked', 'Please try again later.'); qEl.classList.add('is-blocked'); analyzeBtn.disabled = true; }
    else { qEl.innerHTML = b + ' — <strong>' + r + '</strong> ' + qLbl('Remaining', 'remaining'); qEl.classList.remove('is-blocked'); analyzeBtn.disabled = false; }
    qEl.hidden = false;
  }
  qUpdate();

  /* ── Helpers ────────────────────────────────────────────── */

  function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  function badge(text, color) {
    var colors = { green: '#27ae60', yellow: '#f1c40f', red: '#e74c3c', blue: '#3d5394', gray: '#8b949e', orange: '#e67e22' };
    var bg = colors[color] || colors.gray;
    return '<span class="domain-badge" style="background:' + bg + '22;color:' + bg + ';border:1px solid ' + bg + '55">' + esc(text) + '</span>';
  }

  function row(label, value) {
    return '<div class="domain-row"><span class="domain-row-label">' + esc(label) + '</span><span class="domain-row-value">' + value + '</span></div>';
  }

  function setCard(id, html) { var el = document.getElementById(id); if (el) el.innerHTML = html; }

  /* ── Parsing des headers ────────────────────────────────── */

  function extractHeaders(raw) {
    /* Séparer les headers du body (double newline) */
    var norm = raw.replace(/\r\n/g, '\n');
    var headerEnd = norm.indexOf('\n\n');
    var headerBlock = headerEnd !== -1 ? norm.substring(0, headerEnd) : norm;

    /* Unfold les headers continuées (ligne suivante commence par espace/tab) */
    headerBlock = headerBlock.replace(/\n[ \t]+/g, ' ');

    var headers = {};
    var headersOrdered = []; /* pour garder l'ordre original */
    var lines = headerBlock.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var colonIdx = lines[i].indexOf(':');
      if (colonIdx === -1) continue;
      var key = lines[i].substring(0, colonIdx).trim();
      var keyLower = key.toLowerCase();
      var val = lines[i].substring(colonIdx + 1).trim();
      if (!headers[keyLower]) headers[keyLower] = [];
      headers[keyLower].push(val);
      headersOrdered.push({ key: key, keyLower: keyLower, value: val });
    }
    return { headers: headers, ordered: headersOrdered, rawHeaders: headerBlock };
  }

  function getFirst(h, key) { return (h[key] && h[key][0]) || ''; }
  function getAll(h, key) { return h[key] || []; }

  /* ── Extraire le domaine du To ──────────────────────────── */

  function extractDomain(addr) {
    var match = addr.match(/<([^>]+)>/) || addr.match(/([^\s,]+@[^\s,]+)/);
    if (match) {
      var parts = match[1].split('@');
      return parts.length > 1 ? parts[1].toLowerCase() : '';
    }
    return '';
  }

  /* ── Parse Authentication-Results (RFC 8601) ────────────────
     Extrait les résultats d'authentification d'UN ou PLUSIEURS headers AR.
     Chaque entry : {server, raw, spf, dkim, dmarc, compauth, compauthReason, arc}
     - spf/dkim/dmarc : mechanisms standard (pass/fail/softfail/neutral/none/temperror/permerror)
     - compauth (Phase 2, 2026-04-13) : résultat composite Microsoft M365 avec reason code
     - arc (Phase 2) : résumé de la chaîne ARC tel que vu par l'AR (distinct de parseArcChain
       qui analyse les headers ARC-* eux-mêmes)
     Retourne aussi un summary global : le premier résultat non-null rencontré pour chaque champ.
     ──────────────────────────────────────────────────────────── */

  function parseAuthResults(headers) {
    var results = [];
    var arHeaders = getAll(headers, 'authentication-results');
    for (var i = 0; i < arHeaders.length; i++) {
      var line = arHeaders[i];
      /* Extraire le serveur qui a émis ce header (premier mot avant le ;) */
      var server = '';
      var semiIdx = line.indexOf(';');
      if (semiIdx !== -1) server = line.substring(0, semiIdx).trim().toLowerCase();
      var entry = {
        server: server, raw: line,
        spf: null, dkim: null, dmarc: null,
        compauth: null, compauthReason: null, arc: null
      };
      var spfM = line.match(/spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)/i);
      if (spfM) entry.spf = spfM[1].toLowerCase();
      var dkimM = line.match(/dkim\s*=\s*(pass|fail|none|temperror|permerror)/i);
      if (dkimM) entry.dkim = dkimM[1].toLowerCase();
      var dmarcM = line.match(/dmarc\s*=\s*(pass|fail|none|temperror|permerror)/i);
      if (dmarcM) entry.dmarc = dmarcM[1].toLowerCase();
      /* compauth (Microsoft M365) : résultat composite SPF+DKIM+DMARC vu par Exchange.
         Ex: "compauth=pass reason=100" — reason 100 = pass, 001/002 = DMARC fail, etc. */
      var compM = line.match(/compauth\s*=\s*(pass|fail|softpass|none)/i);
      if (compM) entry.compauth = compM[1].toLowerCase();
      var reasonM = line.match(/compauth\s*=\s*\S+\s+reason\s*=\s*(\d+)/i);
      if (reasonM) entry.compauthReason = reasonM[1];
      /* arc= dans AR : résultat global de la chaîne ARC (pas à confondre avec
         ARC-Authentication-Results qui est un header distinct par hop). */
      var arcM = line.match(/arc\s*=\s*(pass|fail|none)/i);
      if (arcM) entry.arc = arcM[1].toLowerCase();
      results.push(entry);
    }
    /* Résumé global : le premier résultat de chaque type trouvé */
    var summary = { spf: null, dkim: null, dmarc: null, compauth: null,
                    compauthReason: null, arc: null, entries: results };
    for (var j = 0; j < results.length; j++) {
      if (!summary.spf && results[j].spf) summary.spf = results[j].spf;
      if (!summary.dkim && results[j].dkim) summary.dkim = results[j].dkim;
      if (!summary.dmarc && results[j].dmarc) summary.dmarc = results[j].dmarc;
      if (!summary.compauth && results[j].compauth) {
        summary.compauth = results[j].compauth;
        summary.compauthReason = results[j].compauthReason;
      }
      if (!summary.arc && results[j].arc) summary.arc = results[j].arc;
    }
    return summary;
  }

  function authBadge(result, name) {
    if (!result) return badge(name + ': not found', 'gray');
    if (result === 'pass') return badge(name + ': pass', 'green');
    if (result === 'fail') return badge(name + ': FAIL', 'red');
    if (result === 'softfail') return badge(name + ': softfail', 'orange');
    return badge(name + ': ' + result, 'gray');
  }

  /* ── Parse Received headers → hops ──────────────────────────
     Retourne un tableau de hops en ordre chronologique (Received est en ordre
     inverse dans les headers → on fait .reverse()). Chaque hop :
       {from, by, ip, date, dateObj, protocol, raw, delay}
     Le champ delay est calculé entre chaque hop et son prédécesseur (ms).
     Utilisé par renderRouteTimeline (Phase 2) + le tableau Route existant.
     ──────────────────────────────────────────────────────────── */

  function parseHops(headers) {
    var received = getAll(headers, 'received');
    var hops = [];
    for (var i = 0; i < received.length; i++) {
      var r = received[i];
      var hop = { from: '', by: '', ip: '', date: '', dateObj: null, protocol: '', raw: r };

      var fromM = r.match(/from\s+(\S+)/i);
      if (fromM) hop.from = fromM[1];
      var byM = r.match(/by\s+(\S+)/i);
      if (byM) hop.by = byM[1];

      /* IP — chercher dans [], puis dans () */
      var ipM = r.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
      if (!ipM) ipM = r.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/);
      if (ipM) hop.ip = ipM[1];

      /* Protocol */
      var protoM = r.match(/with\s+(E?SMTP\S*|MAPI|HTTP)/i);
      if (protoM) hop.protocol = protoM[1].toUpperCase();
      if (/TLS|tls/i.test(r)) hop.protocol = (hop.protocol ? hop.protocol + ' ' : '') + '(TLS)';

      /* Date — après le dernier ; */
      var semiIdx = r.lastIndexOf(';');
      if (semiIdx !== -1) {
        var dateStr = r.substring(semiIdx + 1).trim();
        var parsed = new Date(dateStr);
        if (!isNaN(parsed.getTime())) { hop.date = parsed.toISOString(); hop.dateObj = parsed; }
      }
      hops.push(hop);
    }

    /* Received headers sont en ordre inverse (dernier hop en premier) → inverser */
    hops.reverse();

    /* Calculer les délais entre hops */
    for (var j = 1; j < hops.length; j++) {
      if (hops[j].dateObj && hops[j - 1].dateObj) {
        hops[j].delay = hops[j].dateObj - hops[j - 1].dateObj;
      }
    }
    return hops;
  }

  function formatDelay(ms) {
    if (ms === undefined || ms === null) return '';
    if (ms < 0) return badge('⚠ ' + Math.round(ms / 1000) + 's', 'red');
    if (ms < 1000) return badge(ms + 'ms', 'green');
    var sec = Math.round(ms / 1000);
    if (sec < 60) return badge(sec + 's', sec > 10 ? 'orange' : 'green');
    var min = Math.round(sec / 60);
    return badge(min + 'min', min > 5 ? 'red' : 'orange');
  }

  function isPrivateIp(ip) {
    if (!ip) return false;
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.)/.test(ip)) return true;
    /* IPv6 ULA (fc00::/7), link-local (fe80::/10), loopback (::1) */
    if (/^::1$/.test(ip)) return true;
    if (/^[fF][cCdD]/.test(ip)) return true;
    if (/^[fF][eE][89aAbB]/.test(ip)) return true;
    return false;
  }

  /* ══════════════════════════════════════════════════════════════
     PARSERS ÉTENDUS — Phase 2 (ajouté 2026-04-13)
     ARC chain, Microsoft antispam scores, List-Unsubscribe, X-Mailer
     identification, Return-Path vs From alignment, total delivery delay.
     ══════════════════════════════════════════════════════════════ */

  /* ── ARC chain (RFC 8617) ───────────────────────────────────
     ARC préserve les résultats d'authentification à travers les forwarders.
     Chaque hop ajoute 3 headers (ARC-Authentication-Results, ARC-Message-Signature,
     ARC-Seal) numérotés avec i=1, i=2, i=3... Une chaîne valide a les 3 headers
     par instance et un ARC-Seal cv=pass sur le dernier. */
  function parseArcChain(headers) {
    var aar = getAll(headers, 'arc-authentication-results');
    var ams = getAll(headers, 'arc-message-signature');
    var seal = getAll(headers, 'arc-seal');
    var present = aar.length > 0 || ams.length > 0 || seal.length > 0;
    if (!present) return { present: false, hops: 0, valid: false };

    /* Extraire le plus grand i= trouvé — nombre de hops ARC */
    var maxI = 0;
    function scanI(list) {
      for (var k = 0; k < list.length; k++) {
        var m = list[k].match(/\bi\s*=\s*(\d+)/);
        if (m) {
          var n = parseInt(m[1], 10);
          if (n > maxI) maxI = n;
        }
      }
    }
    scanI(aar); scanI(ams); scanI(seal);

    /* Valid = 3 headers présents par instance + dernier Seal a cv=pass (chain valid) */
    var lastSealCv = null;
    for (var s = 0; s < seal.length; s++) {
      var cvM = seal[s].match(/\bcv\s*=\s*(none|pass|fail)/i);
      var iM = seal[s].match(/\bi\s*=\s*(\d+)/);
      if (cvM && iM && parseInt(iM[1], 10) === maxI) lastSealCv = cvM[1].toLowerCase();
    }
    /* cv=none est valide pour i=1 (premier hop), cv=pass pour les suivants */
    var valid = (maxI === aar.length && maxI === ams.length && maxI === seal.length &&
                 (lastSealCv === 'pass' || (maxI === 1 && lastSealCv === 'none')));

    return { present: true, hops: maxI, valid: valid, lastSealCv: lastSealCv };
  }

  /* ── Microsoft antispam — X-Forefront-Antispam-Report + SCL ──
     XFAR est une string compacte : CIP:1.2.3.4;CTRY:LU;LANG:en;SCL:1;PCL:0;...
     Champs principaux :
       CIP    Connecting IP
       CTRY   Country code
       LANG   Language
       SCL    Spam Confidence Level (0-9)
       BCL    Bulk Complaint Level (0-9)
       PCL    Phishing Confidence Level (0-8)
       SFV    Spam Filter Verdict (NSPM/SPM/SKN/SKI/SKB/SFE)
       SFTY   Safety Level (0..9) — 9.x = phish
       H      Helo hostname
       IPV    IPV:NLI / CAL / etc.
       SRV    Server routing */
  function parseMsAntispam(headers) {
    var xfar = getFirst(headers, 'x-forefront-antispam-report');
    var sclHeader = getFirst(headers, 'x-ms-exchange-organization-scl');
    var xMsAntispam = getFirst(headers, 'x-microsoft-antispam');
    var authAs = getFirst(headers, 'x-ms-exchange-organization-authas');
    var authSource = getFirst(headers, 'x-ms-exchange-organization-authsource');

    if (!xfar && !sclHeader && !xMsAntispam && !authAs) {
      return { present: false };
    }

    var fields = {};
    /* Parse XFAR (semicolon-separated key:value) */
    if (xfar) {
      var parts = xfar.split(';');
      for (var i = 0; i < parts.length; i++) {
        var kv = parts[i].trim();
        var colonIdx = kv.indexOf(':');
        if (colonIdx === -1) continue;
        var k = kv.substring(0, colonIdx).trim().toUpperCase();
        var v = kv.substring(colonIdx + 1).trim();
        fields[k] = v;
      }
    }
    /* X-Microsoft-Antispam a le même format, BCL y est souvent redondant */
    if (xMsAntispam) {
      var msParts = xMsAntispam.split(';');
      for (var j = 0; j < msParts.length; j++) {
        var msKv = msParts[j].trim();
        var msCi = msKv.indexOf(':');
        if (msCi === -1) continue;
        var msK = msKv.substring(0, msCi).trim().toUpperCase();
        var msV = msKv.substring(msCi + 1).trim();
        if (!fields[msK]) fields[msK] = msV;
      }
    }

    /* Fallback SCL depuis son header dédié si pas dans XFAR */
    if (!fields.SCL && sclHeader) fields.SCL = sclHeader.trim();

    return {
      present: true,
      fields: fields,
      authAs: authAs || null,
      authSource: authSource || null,
      rawXfar: xfar || null
    };
  }

  /* ── List-Unsubscribe (RFC 2369 + RFC 8058 one-click) ──
     Headers :
       List-Unsubscribe: <mailto:...>, <https://...>
       List-Unsubscribe-Post: List-Unsubscribe=One-Click (RFC 8058)
     L'header Post présent avec exactement "List-Unsubscribe=One-Click" confirme
     le support one-click (requis par Gmail/Yahoo pour les senders en volume depuis 2024). */
  function parseListUnsubscribe(headers) {
    var lu = getFirst(headers, 'list-unsubscribe');
    var luPost = getFirst(headers, 'list-unsubscribe-post');
    if (!lu) return { present: false };
    var oneClick = luPost && /List-Unsubscribe\s*=\s*One-Click/i.test(luPost);
    /* Extraire les URIs entre < > */
    var uris = [];
    var m, re = /<([^>]+)>/g;
    while ((m = re.exec(lu)) !== null) uris.push(m[1]);
    var hasMailto = uris.some(function (u) { return u.toLowerCase().indexOf('mailto:') === 0; });
    var hasHttps = uris.some(function (u) { return u.toLowerCase().indexOf('https://') === 0; });
    return {
      present: true,
      oneClick: oneClick,
      uris: uris,
      hasMailto: hasMailto,
      hasHttps: hasHttps
    };
  }

  /* ── Mail client detection (X-Mailer / User-Agent) ──
     Mapping des 20+ clients les plus courants vers {name, version, platform}.
     Ordre important : tester le plus spécifique d'abord. */
  function detectMailClient(headers) {
    var raw = getFirst(headers, 'x-mailer') || getFirst(headers, 'user-agent');
    if (!raw) return null;
    var r = raw;

    function match(re, name, platformFrom) {
      var m = r.match(re);
      if (!m) return null;
      var version = m[1] || '';
      var platform = platformFrom || '';
      return { name: name, version: version, platform: platform, raw: raw };
    }

    /* Ordre : plus spécifique d'abord — Outlook 365/webmail/desktop/mobile distincts */
    return (
      match(/Microsoft Outlook ([\d.]+)/i, 'Outlook', 'Desktop') ||
      match(/Microsoft-MacOutlook\/([\d.]+)/i, 'Outlook Mac', 'macOS') ||
      match(/Outlook-iOS\/([\d.]+)/i, 'Outlook Mobile', 'iOS') ||
      match(/Outlook-Android\/([\d.]+)/i, 'Outlook Mobile', 'Android') ||
      match(/^Microsoft CDO/i, 'Outlook / Exchange', 'Server') ||
      match(/Exchange Server ([\d.]+)/i, 'Exchange Server', 'Server') ||
      match(/OWA\/([\d.]+)/i, 'Outlook Web App', 'Webmail') ||
      (r.indexOf('Thunderbird') !== -1 ? match(/Thunderbird\/([\d.]+)/i, 'Thunderbird', 'Desktop') : null) ||
      (r.indexOf('Mozilla/') !== -1 && r.indexOf('Gecko') !== -1 && r.indexOf('Thunderbird') === -1 ? { name: 'Mozilla / Gecko', version: '', platform: 'Desktop', raw: raw } : null) ||
      match(/Apple Mail \(([\d.]+)\)/i, 'Apple Mail', 'macOS') ||
      match(/iPhone Mail (\S+)/i, 'Apple Mail', 'iOS') ||
      match(/iPad Mail (\S+)/i, 'Apple Mail', 'iPadOS') ||
      (r.indexOf('Android') !== -1 && r.indexOf('Mail') !== -1 ? { name: 'Android Mail', version: '', platform: 'Android', raw: raw } : null) ||
      match(/ProtonMail/i, 'ProtonMail', 'Webmail') ||
      match(/Zoho Mail/i, 'Zoho Mail', 'Webmail') ||
      match(/Roundcube Webmail\/([\d.]+)/i, 'Roundcube', 'Webmail') ||
      match(/SquirrelMail/i, 'SquirrelMail', 'Webmail') ||
      match(/Rainloop/i, 'RainLoop', 'Webmail') ||
      match(/Horde/i, 'Horde', 'Webmail') ||
      match(/^PHP\s*mailer/i, 'PHPMailer', 'Script') ||
      match(/Mailgun/i, 'Mailgun', 'API/Transactional') ||
      match(/SendGrid/i, 'SendGrid', 'API/Transactional') ||
      match(/Postmark/i, 'Postmark', 'API/Transactional') ||
      match(/Amazon SES/i, 'Amazon SES', 'API/Transactional') ||
      match(/Mailchimp/i, 'Mailchimp', 'Marketing') ||
      match(/^Nine\//i, 'Nine (Exchange)', 'Android') ||
      match(/BlueMail/i, 'BlueMail', 'Mobile') ||
      match(/Spark Desktop/i, 'Spark', 'Desktop') ||
      match(/Spark/i, 'Spark', 'Mobile') ||
      /* Fallback : name = premier mot, garde le raw dans les details */
      (function () {
        var firstWord = raw.split(/[\s\/]/)[0];
        return { name: firstWord, version: '', platform: '', raw: raw };
      })()
    );
  }

  /* ── Alignment Return-Path vs From ──
     RFC 5322 vs RFC 5321 (Envelope-From vs Header-From). Alignement DMARC :
     relaxed = organizational domain match, strict = exact domain match.
     On vérifie juste l'alignement relaxed ici (suffisant pour un indicateur visuel). */
  function checkAlignment(headers) {
    var rp = getFirst(headers, 'return-path');
    var from = getFirst(headers, 'from');
    if (!rp || !from) return { checked: false };
    var rpDomain = extractDomain(rp);
    var fromDomain = extractDomain(from);
    if (!rpDomain || !fromDomain) return { checked: false };

    /* Organizational domain = dernière 2 ou 3 labels (heuristique simple, pas PSL complet) */
    function orgDomain(d) {
      var parts = d.split('.');
      if (parts.length <= 2) return d;
      /* TLDs 2-level courants (.co.uk, .com.lu, .com.br, .org.uk) */
      var tld2 = parts.slice(-2).join('.');
      if (/^(co|com|org|net|ac|gov|edu)\.(uk|lu|br|au|nz|in|jp|kr|za)$/i.test(tld2)) {
        return parts.slice(-3).join('.');
      }
      return parts.slice(-2).join('.');
    }
    var rpOrg = orgDomain(rpDomain);
    var fromOrg = orgDomain(fromDomain);
    return {
      checked: true,
      rpDomain: rpDomain,
      fromDomain: fromDomain,
      relaxedMatch: rpOrg === fromOrg,
      strictMatch: rpDomain === fromDomain
    };
  }

  /* ── ESP detection (mailing/marketing/transactional platforms) ──
     Détecte les Email Service Providers via signaux multiples :
       1) Headers signature spécifiques (X-Mailgun-*, X-SG-*, X-Mailchimp-*, etc.)
       2) Domaine Return-Path (ex: bounce.mc.*, bounce-*.mailgun.org)
       3) DKIM d= domain qui mentionne l'ESP
       4) SPF includes connus (via l'include dans le raw)
     Retourne { detected: true, name, type, signals[] } ou { detected: false }.
     Type : "marketing" (Mailchimp, Brevo, HubSpot...) ou "transactional"
     (Mailgun, SendGrid, Postmark...) — pour colorer différemment. */
  function detectEsp(headers, rawText) {
    var signals = [];
    var detected = null;

    function check(name, type, test, reason) {
      if (detected) return;
      if (test) { detected = { name: name, type: type }; signals.push(reason); }
    }

    var rp = getFirst(headers, 'return-path').toLowerCase();
    var from = getFirst(headers, 'from').toLowerCase();
    var fromHost = getFirst(headers, 'x-originating-ip') || '';
    var xMailer = (getFirst(headers, 'x-mailer') || '').toLowerCase();
    var ua = (getFirst(headers, 'user-agent') || '').toLowerCase();

    function hasHeader(name) { return getAll(headers, name).length > 0; }
    function headerContains(name, substr) {
      var v = getFirst(headers, name).toLowerCase();
      return v.indexOf(substr) !== -1;
    }

    /* ── Transactional / API platforms ── */
    check('Mailgun', 'transactional',
      hasHeader('x-mailgun-sending-ip') || hasHeader('x-mailgun-variables') ||
      hasHeader('x-mailgun-track') || rp.indexOf('mailgun.org') !== -1 ||
      rp.indexOf('mg.') === 0,
      'Mailgun headers or return-path');

    check('SendGrid', 'transactional',
      hasHeader('x-sg-eid') || hasHeader('x-sg-id') ||
      rp.indexOf('sendgrid.net') !== -1 || rp.indexOf('sendgrid.com') !== -1 ||
      headerContains('received', 'sendgrid.net'),
      'SendGrid headers or return-path');

    check('Amazon SES', 'transactional',
      hasHeader('x-ses-outgoing') || hasHeader('x-ses-receipt') ||
      rp.indexOf('amazonses.com') !== -1 || rp.indexOf('.amazonses.') !== -1 ||
      headerContains('received', 'amazonses.com'),
      'Amazon SES headers or received');

    check('Postmark', 'transactional',
      hasHeader('x-pm-message-id') || hasHeader('x-postmark-message-id') ||
      rp.indexOf('postmarkapp.com') !== -1,
      'Postmark headers or return-path');

    check('SparkPost', 'transactional',
      hasHeader('x-msys-api') || hasHeader('x-sparkpost-*') ||
      rp.indexOf('sparkpostmail.com') !== -1,
      'SparkPost headers or return-path');

    check('SMTP2GO', 'transactional',
      hasHeader('x-smtp2go-msg-id') || rp.indexOf('smtp2go.net') !== -1,
      'SMTP2GO headers');

    /* ── Marketing / ESP platforms ── */
    check('Mailchimp', 'marketing',
      hasHeader('x-mc-user') || hasHeader('x-mc-bounce-alert') ||
      hasHeader('x-mailchimp-') || hasHeader('x-mcpf-job') ||
      headerContains('dkim-signature', 'mcsv.net') ||
      headerContains('dkim-signature', 'mailchimp') ||
      rp.indexOf('bounce.mc.') !== -1 || rp.indexOf('mail.mailchimp.com') !== -1 ||
      rp.indexOf('mcsv.net') !== -1,
      'Mailchimp headers or return-path');

    check('Brevo (ex-Sendinblue)', 'marketing',
      hasHeader('x-sib-id') || hasHeader('x-mailin-client') ||
      hasHeader('x-sib-client') || hasHeader('feedback-id') &&
        getFirst(headers, 'feedback-id').toLowerCase().indexOf('sib') !== -1 ||
      rp.indexOf('sendinblue.com') !== -1 || rp.indexOf('brevo.com') !== -1 ||
      rp.indexOf('mlsend') !== -1,
      'Brevo/Sendinblue headers or return-path');

    check('MailerLite', 'marketing',
      hasHeader('x-mailerlite-') || hasHeader('x-ml-') ||
      rp.indexOf('mlsend.com') !== -1 || rp.indexOf('mailerlite.com') !== -1,
      'MailerLite headers or return-path');

    check('HubSpot', 'marketing',
      hasHeader('x-hs-signature') || hasHeader('x-hubspot-') ||
      headerContains('x-report-abuse', 'hubspot') ||
      rp.indexOf('hubspot.') !== -1 || rp.indexOf('hubspotemail.net') !== -1 ||
      rp.indexOf('hs-email.net') !== -1,
      'HubSpot headers or return-path');

    check('Klaviyo', 'marketing',
      hasHeader('x-klaviyo') || rp.indexOf('klaviyomail.com') !== -1 ||
      rp.indexOf('klmail') !== -1,
      'Klaviyo headers or return-path');

    check('ActiveCampaign', 'marketing',
      hasHeader('x-ac-') || hasHeader('x-activehosted') ||
      rp.indexOf('activehosted.com') !== -1,
      'ActiveCampaign headers or return-path');

    check('ConvertKit / Kit', 'marketing',
      hasHeader('x-ck-') || rp.indexOf('convertkit') !== -1 ||
      rp.indexOf('.ck.page') !== -1,
      'ConvertKit headers or return-path');

    check('Campaign Monitor', 'marketing',
      hasHeader('x-cmail-campaign-id') || hasHeader('x-cmailgw-') ||
      rp.indexOf('cmail') !== -1,
      'Campaign Monitor headers or return-path');

    check('Constant Contact', 'marketing',
      hasHeader('x-cc-') || rp.indexOf('constantcontact.com') !== -1 ||
      rp.indexOf('in.constantcontact.com') !== -1,
      'Constant Contact headers or return-path');

    check('AWeber', 'marketing',
      hasHeader('x-aweber-') || rp.indexOf('aweber.com') !== -1,
      'AWeber headers or return-path');

    check('Drip', 'marketing',
      hasHeader('x-drip-') || rp.indexOf('getdrip.com') !== -1,
      'Drip headers or return-path');

    check('GetResponse', 'marketing',
      hasHeader('x-gr-') || rp.indexOf('getresponse.com') !== -1,
      'GetResponse headers or return-path');

    check('Omnisend', 'marketing',
      hasHeader('x-omnisend-') || rp.indexOf('omnisend.com') !== -1,
      'Omnisend headers or return-path');

    check('Mailjet', 'transactional',
      hasHeader('x-mj-') || hasHeader('x-mailjet-') ||
      rp.indexOf('mailjet.com') !== -1,
      'Mailjet headers or return-path');

    check('Twilio SendGrid Marketing', 'marketing',
      headerContains('feedback-id', 'mc') && hasHeader('x-sg-eid'),
      'SendGrid Marketing Campaigns signals');

    /* Fallback : si List-Unsubscribe présent + Feedback-ID → c'est probablement un ESP */
    if (!detected && hasHeader('list-unsubscribe') && hasHeader('feedback-id')) {
      detected = { name: 'Unknown ESP', type: 'marketing' };
      signals.push('List-Unsubscribe + Feedback-ID present (typical ESP pattern)');
    }

    if (!detected) return { detected: false };
    return { detected: true, name: detected.name, type: detected.type, signals: signals };
  }

  /* ── Total delivery delay ──
     Entre le premier Received (envoi) et le dernier (livraison finale).
     hops[] est déjà en ordre chronologique (parseHops a inversé l'ordre Received). */
  function calcTotalDelay(hops) {
    if (hops.length < 2) return null;
    var first = null, last = null;
    for (var i = 0; i < hops.length; i++) {
      if (hops[i].dateObj) {
        if (!first) first = hops[i].dateObj;
        last = hops[i].dateObj;
      }
    }
    if (!first || !last) return null;
    return last - first;
  }

  /* ══════════════════════════════════════════════════════════════
     RENDU TIMELINE SVG — Phase 2 (ajouté 2026-04-13)
     Dessine une ligne horizontale avec un marker circulaire par hop et
     affiche le délai relatif entre chaque. Responsive via scroll horizontal
     si trop de hops pour tenir dans le conteneur.
     ══════════════════════════════════════════════════════════════ */
  function renderRouteTimeline(hops) {
    if (!hops || hops.length === 0) return '';

    /* Dimensions */
    var hopWidth = 160;        /* espacement horizontal entre markers */
    var padLeft = 40;
    var padRight = 40;
    var svgHeight = 140;
    var yLine = 70;            /* ligne horizontale y */
    var svgWidth = padLeft + padRight + (hops.length - 1) * hopWidth;
    if (svgWidth < 400) svgWidth = 400;

    /* Palette (référence aux variables CSS via inline fill) */
    var lineColor = '#8b949e55';
    var dotColor = '#3d5394';
    var dotPrivate = '#e67e22';
    var textMain = '#0f1419';
    var textDim = '#8b949e';
    /* Dark mode — les couleurs CSS var ne sont pas lisibles côté JS, on utilise
       currentColor sur les textes et on garde le gris neutre pour les accents. */

    function shortHost(h) {
      if (!h) return '—';
      /* Garder les 3 derniers labels max pour éviter les textes énormes */
      var parts = h.replace(/[^a-z0-9.\-]/gi, '').split('.');
      if (parts.length > 3) parts = parts.slice(-3);
      return parts.join('.');
    }

    var svg = '<svg class="eml-timeline-svg" xmlns="http://www.w3.org/2000/svg" ' +
      'viewBox="0 0 ' + svgWidth + ' ' + svgHeight + '" ' +
      'width="' + svgWidth + '" height="' + svgHeight + '" ' +
      'role="img" aria-label="Email delivery path timeline">';

    /* Ligne horizontale (base) */
    svg += '<line x1="' + padLeft + '" y1="' + yLine + '" x2="' + (svgWidth - padRight) + '" y2="' + yLine + '" ' +
      'stroke="' + lineColor + '" stroke-width="2" stroke-dasharray="4 2"/>';

    /* Segments pleins entre markers + délais */
    for (var i = 0; i < hops.length; i++) {
      var cx = padLeft + i * hopWidth;
      var hop = hops[i];
      var isPriv = hop.ip && isPrivateIp(hop.ip);

      /* Segment plein entre i-1 et i */
      if (i > 0) {
        var prevX = padLeft + (i - 1) * hopWidth;
        svg += '<line x1="' + prevX + '" y1="' + yLine + '" x2="' + cx + '" y2="' + yLine + '" ' +
          'stroke="' + dotColor + '" stroke-width="3" opacity="0.6"/>';

        /* Badge délai au milieu du segment */
        if (hop.delay !== undefined && hop.delay !== null) {
          var midX = (prevX + cx) / 2;
          var delayTxt = '';
          if (hop.delay < 0) delayTxt = '⚠ ' + Math.round(hop.delay / 1000) + 's';
          else if (hop.delay < 1000) delayTxt = hop.delay + 'ms';
          else if (hop.delay < 60000) delayTxt = Math.round(hop.delay / 1000) + 's';
          else delayTxt = Math.round(hop.delay / 60000) + 'min';
          var delayColor = hop.delay < 0 ? '#e74c3c' :
                           hop.delay < 2000 ? '#27ae60' :
                           hop.delay < 10000 ? '#f1c40f' : '#e67e22';
          svg += '<rect x="' + (midX - 24) + '" y="' + (yLine - 28) + '" width="48" height="16" ' +
            'rx="3" fill="' + delayColor + '" opacity="0.85"/>';
          svg += '<text x="' + midX + '" y="' + (yLine - 16) + '" ' +
            'text-anchor="middle" fill="white" font-size="10" font-family="ui-monospace, monospace" ' +
            'font-weight="600">' + esc(delayTxt) + '</text>';
        }
      }

      /* Marker circulaire numéroté */
      svg += '<circle cx="' + cx + '" cy="' + yLine + '" r="10" ' +
        'fill="' + (isPriv ? dotPrivate : dotColor) + '" stroke="white" stroke-width="2"/>';
      svg += '<text x="' + cx + '" y="' + (yLine + 4) + '" ' +
        'text-anchor="middle" fill="white" font-size="11" font-weight="700" ' +
        'font-family="ui-monospace, monospace">' + (i + 1) + '</text>';

      /* Label "by" sous le marker (serveur destination du hop) */
      var lbl = shortHost(hop.by);
      svg += '<text x="' + cx + '" y="' + (yLine + 30) + '" ' +
        'text-anchor="middle" fill="currentColor" font-size="10" ' +
        'font-family="ui-monospace, monospace" font-weight="600">' + esc(lbl) + '</text>';

      /* IP en dessous (grisé) */
      if (hop.ip) {
        svg += '<text x="' + cx + '" y="' + (yLine + 46) + '" ' +
          'text-anchor="middle" fill="' + textDim + '" font-size="9" ' +
          'font-family="ui-monospace, monospace">' + esc(hop.ip) + '</text>';
      }

      /* Protocol badge au-dessus si TLS */
      if (/TLS/i.test(hop.protocol || '')) {
        svg += '<text x="' + cx + '" y="' + (yLine - 42) + '" ' +
          'text-anchor="middle" fill="#27ae60" font-size="9" ' +
          'font-family="ui-monospace, monospace" font-weight="600">🔒 TLS</text>';
      }
    }

    svg += '</svg>';

    return '<div class="eml-timeline-wrap" role="group" aria-label="Delivery timeline">' +
      '<div class="eml-timeline-scroll">' + svg + '</div></div>';
  }

  /* ══════════════════════════════════════════════════════════════
     DÉTECTION BOÎTE COMPROMISE / BEC — ajouté 2026-04-23
     Quand toute l'authentification passe (SPF+DKIM+DMARC), le spoofing
     est écarté mais la boîte peut être compromise. L'attaquant envoie
     un VRAI mail depuis une session authentifiée. On ne peut plus se
     fier aux headers d'authentification — il faut lire le contenu et
     les motifs structurels.
     ══════════════════════════════════════════════════════════════ */

  /* Décode quoted-printable (=XX + =<newline>). */
  function decodeQP(s) {
    return s.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, function (_, h) {
      return String.fromCharCode(parseInt(h, 16));
    });
  }

  /* Décode base64 en texte UTF-8 (pour bodies text/* encodés en base64). */
  function decodeB64Text(s) {
    try {
      var clean = s.replace(/[^A-Za-z0-9+/=]/g, '');
      var bin = atob(clean);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch (e) { return s; }
  }

  /* Extrait les parties text/plain + text/html du raw MIME.
     Ne traite que les body textuels (les pièces jointes restent à
     extractAttachments). Gère multipart récursif, 7bit/8bit/QP/base64. */
  function extractBody(raw) {
    var norm = raw.replace(/\r\n/g, '\n');
    var headerEnd = norm.indexOf('\n\n');
    if (headerEnd === -1) return { text: '', html: '' };
    var topHeaders = norm.substring(0, headerEnd).replace(/\n[ \t]+/g, ' ');
    var topBody = norm.substring(headerEnd + 2);

    var ctMatch = topHeaders.match(/content-type:\s*([^\n]+)/i);
    /* Garde la casse originale — les boundary MIME sont case-sensitive */
    var topCt = ctMatch ? ctMatch[1] : 'text/plain';

    var text = '', html = '';

    function handlePart(partHeaders, partBody) {
      /* Lowercase uniquement le contenu pour matcher — la casse est préservée dans partHeaders pour les boundaries */
      var ct = ((partHeaders.match(/content-type:\s*([^\n;]+)/i) || [,''])[1] || '').toLowerCase();
      var cte = ((partHeaders.match(/content-transfer-encoding:\s*([^\n;]+)/i) || [,''])[1] || '').toLowerCase().trim();
      var disp = ((partHeaders.match(/content-disposition:\s*([^\n;]+)/i) || [,''])[1] || '').toLowerCase().trim();
      if (disp === 'attachment') return;
      if (ct.indexOf('text/') !== 0) return;

      var decoded = partBody;
      if (cte === 'base64') decoded = decodeB64Text(partBody);
      else if (cte === 'quoted-printable') decoded = decodeQP(partBody);

      if (ct.indexOf('text/html') !== -1) html += decoded + '\n';
      else text += decoded + '\n';
    }

    function walk(block, ct) {
      var bMatch = ct.match(/boundary="?([^"\n;]+)"?/i);
      if (!bMatch) {
        var fakeHeaders = 'content-type: ' + ct + '\n' +
          (topHeaders.match(/content-transfer-encoding:[^\n]+/i) || [''])[0];
        handlePart(fakeHeaders, block);
        return;
      }
      /* Boundary préservée dans sa casse originale (MIME est case-sensitive) */
      var boundary = '--' + bMatch[1].trim();
      var parts = block.split(boundary);
      for (var i = 1; i < parts.length; i++) {
        var part = parts[i];
        if (part.trim() === '--' || part.trim() === '') continue;
        var phEnd = part.indexOf('\n\n');
        if (phEnd === -1) continue;
        var ph = part.substring(0, phEnd).replace(/\n[ \t]+/g, ' ');
        var pb = part.substring(phEnd + 2).replace(/\n--\s*$/, '');
        /* Preserve case pour reconnaître le sous-boundary */
        var partCtRaw = (ph.match(/content-type:\s*([^\n]+)/i) || [,'text/plain'])[1];
        if (partCtRaw.toLowerCase().indexOf('multipart/') === 0) walk(pb, partCtRaw);
        else handlePart(ph, pb);
      }
    }

    if (topCt.toLowerCase().indexOf('multipart/') === 0) walk(topBody, topCt);
    else {
      var fakeHeaders = 'content-type: ' + topCt + '\n' +
        (topHeaders.match(/content-transfer-encoding:[^\n]+/i) || [''])[0];
      handlePart(fakeHeaders, topBody);
    }

    return { text: text, html: html };
  }

  /* Retourne le domaine principal (eTLD+1 approximatif) — sans PSL complet
     mais avec la liste 2-level courante déjà utilisée dans checkAlignment. */
  function orgDomainOf(d) {
    if (!d) return '';
    d = d.toLowerCase();
    var parts = d.split('.');
    if (parts.length <= 2) return d;
    var tld2 = parts.slice(-2).join('.');
    if (/^(co|com|org|net|ac|gov|edu)\.(uk|lu|br|au|nz|in|jp|kr|za)$/i.test(tld2)) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  /* Tokenise References + In-Reply-To, extrait les domaines après @.
     Un Message-ID légitime suit une conversation cohérente : toutes les IDs
     devraient venir du même écosystème (même domaine, ou domaines de
     l'expéditeur/destinataire/domaine du fil). Des IDs provenant de tenants
     M365 sans rapport + un domaine tiers étranger = reply-chain phishing. */
  function parseReferencesChain(headers, fromDomain, toDomain) {
    var refs = getFirst(headers, 'references') + ' ' + getFirst(headers, 'in-reply-to');
    var re = /<[^>@\s]+@([^>\s]+)>/g;
    var rawDomains = [], orgs = {};
    var m;
    while ((m = re.exec(refs)) !== null) {
      var dom = m[1].toLowerCase().replace(/>$/, '');
      rawDomains.push(dom);
      var org = orgDomainOf(dom);
      orgs[org] = (orgs[org] || 0) + 1;
    }
    var orgList = Object.keys(orgs);
    var fromOrg = orgDomainOf(fromDomain);
    var toOrg = orgDomainOf(toDomain);
    /* Domaines totalement étrangers (ni expéditeur ni destinataire, ni infra M365) */
    var foreignOrgs = orgList.filter(function (o) {
      if (o === fromOrg || o === toOrg) return false;
      if (/^outlook\.com$/.test(o)) return false;
      return true;
    });
    /* Tenants M365 distincts : les préfixes uniques du style NAMPRD22/EURP194/CH3PR12
       dans les Message-IDs *.<tenant>.prod.outlook.com indiquent des boîtes M365
       sans rapport — pool de headers pour camouflage reply-chain. */
    var m365Tenants = {};
    for (var i = 0; i < rawDomains.length; i++) {
      var mm = rawDomains[i].match(/\.([a-z0-9]+)\.prod\.outlook\.com$/);
      if (mm) m365Tenants[mm[1]] = true;
    }
    return {
      present: rawDomains.length > 0,
      totalIds: rawDomains.length,
      uniqueOrgs: orgList,
      foreignOrgs: foreignOrgs,
      m365TenantsCount: Object.keys(m365Tenants).length
    };
  }

  /* From == To (même local@domain) + destinataire réel absent du To/Cc →
     pattern "auto-envoi avec Bcc en masse" utilisé dans les phishings
     depuis boîtes compromises (l'attaquant s'envoie à lui-même pour
     masquer la vraie liste de cibles en Bcc). */
  function detectSelfAddressed(headers) {
    var from = getFirst(headers, 'from').toLowerCase();
    var to = getFirst(headers, 'to').toLowerCase();
    var cc = getFirst(headers, 'cc').toLowerCase();
    function extractAddr(s) {
      var m = s.match(/<([^>]+)>/) || s.match(/([^\s,<>]+@[^\s,<>]+)/);
      return m ? m[1].trim().toLowerCase() : '';
    }
    var fromAddr = extractAddr(from);
    var toAddrs = to.split(',').map(extractAddr).filter(Boolean);
    var ccAddrs = cc.split(',').map(extractAddr).filter(Boolean);
    var selfAddressed = fromAddr && toAddrs.length === 1 && toAddrs[0] === fromAddr;
    var singleVisibleRecipient = toAddrs.length + ccAddrs.length <= 1;
    return {
      selfAddressed: !!selfAddressed,
      fromAddr: fromAddr,
      toAddrs: toAddrs,
      ccAddrs: ccAddrs,
      singleVisibleRecipient: singleVisibleRecipient
    };
  }

  /* Hôtes fréquemment détournés pour héberger des landing pages de phishing.
     Le principe : domaine parent "propre" donc passe la réputation, mais
     n'importe qui peut y créer un sous-domaine gratuitement. */
  var SUSPICIOUS_HOSTS = [
    'plasmic.run', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
    'web.app', 'firebaseapp.com', 'glitch.me', 'github.io', 'replit.app',
    'repl.co', 'replit.dev', 'notion.site', 'typedream.app', 'carrd.co',
    'wixsite.com', 'weebly.com', 'squarespace.com', 'webflow.io',
    'blob.core.windows.net', 'cloudfront.net', 'azurewebsites.net',
    'herokuapp.com', 'onrender.com', 'surge.sh', 'netlify.com',
    'codesandbox.io', 'stackblitz.io', 'bubbleapps.io', 'appspot.com'
  ];
  var URL_SHORTENERS = [
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'rebrand.ly',
    'cutt.ly', 'is.gd', 'buff.ly', 't.ly', 'shorturl.at', 'rb.gy',
    'tiny.cc', 'lnkd.in'
  ];

  /* Extrait les <a href> (avec texte d'ancre) et URLs brutes du body. */
  function extractBodyUrls(text, html) {
    var urls = [];
    var seen = {};

    /* Anchor tags dans le HTML */
    if (html) {
      var aRe = /<a\s[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
      var am;
      while ((am = aRe.exec(html)) !== null) {
        var href = am[1].trim();
        href = href.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
        /* Ignorer les ancres internes, mailto:, tel:, javascript:, data: */
        if (/^(#|mailto:|tel:|javascript:|data:)/i.test(href)) continue;
        /* Ancres avec href "bare hostname" (ex: kopstal.plasmic.run sans http://) :
           très suspect en soi — un mailer légitime écrit toujours une URL complète. */
        var bareHost = false;
        if (!/^https?:\/\//i.test(href)) {
          if (/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(\/|$)/i.test(href)) { bareHost = true; href = 'http://' + href; }
          else continue;
        }
        var anchor = am[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
        var key = 'a:' + href;
        if (!seen[key]) { seen[key] = true; urls.push({ href: href, anchor: anchor, source: 'anchor', bareHost: bareHost }); }
      }
    }

    /* URLs brutes (texte + html) pour capter ce qui n'est pas dans un <a> */
    var plainRe = /https?:\/\/[^\s<>"')]+/gi;
    var source = (text || '') + '\n' + (html || '');
    var pm;
    while ((pm = plainRe.exec(source)) !== null) {
      var u = pm[0].replace(/[.,;:!?)\]]+$/, '');
      var pk = 'p:' + u;
      if (!seen[pk]) { seen[pk] = true; urls.push({ href: u, anchor: '', source: 'plain' }); }
    }

    return urls;
  }

  /* Analyse chaque URL pour détecter les signes de phishing. */
  function detectSuspiciousHosts(urls, fromDomain, toDomain) {
    var flagged = [];
    var fromOrg = orgDomainOf(fromDomain);
    var toOrg = orgDomainOf(toDomain);

    for (var i = 0; i < urls.length; i++) {
      var u = urls[i];
      var reasons = [];
      var host = '';
      try { host = new URL(u.href).hostname.toLowerCase(); } catch (e) { continue; }
      if (!host) continue;

      /* Hébergement no-code suspect */
      var matchedHost = null;
      for (var j = 0; j < SUSPICIOUS_HOSTS.length; j++) {
        var sh = SUSPICIOUS_HOSTS[j];
        if (host === sh || host.endsWith('.' + sh)) { matchedHost = sh; break; }
      }
      if (matchedHost) {
        reasons.push('Suspect hosting (' + matchedHost + ')');
        /* Brand-in-subdomain : kopstal.plasmic.run — usurpation de marque */
        if (host.endsWith('.' + matchedHost)) {
          var sub = host.substring(0, host.length - matchedHost.length - 1);
          var firstLabel = sub.split('.')[0];
          var fromBrand = fromOrg.split('.')[0];
          var toBrand = toOrg.split('.')[0];
          if (firstLabel && (firstLabel === fromBrand || firstLabel === toBrand)) {
            reasons.push('Brand in subdomain (' + firstLabel + ')');
          }
        }
      }

      /* URL shortener */
      for (var k = 0; k < URL_SHORTENERS.length; k++) {
        if (host === URL_SHORTENERS[k] || host.endsWith('.' + URL_SHORTENERS[k])) {
          reasons.push('URL shortener'); break;
        }
      }

      /* Bare hostname href (no scheme in original) — mailer légitime = URL complète toujours */
      if (u.bareHost) reasons.push('Bare hostname as href (no http/https scheme)');

      /* Punycode / IDN */
      if (/(^|\.)xn--/.test(host)) reasons.push('Punycode (IDN) hostname');

      /* IP au lieu d'un hostname */
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) reasons.push('Raw IP as hostname');

      /* Ancre texte ≠ href (détection simple : l'ancre contient une URL différente) */
      if (u.anchor && /https?:\/\//i.test(u.anchor)) {
        var anchorUrl = (u.anchor.match(/https?:\/\/[^\s]+/i) || [''])[0];
        try {
          var anchorHost = new URL(anchorUrl).hostname.toLowerCase();
          if (anchorHost && anchorHost !== host) {
            reasons.push('Anchor shows ' + anchorHost + ' but links to ' + host);
          }
        } catch (e) {}
      }

      if (reasons.length > 0) {
        flagged.push({ href: u.href, host: host, anchor: u.anchor, reasons: reasons });
      }
    }
    return flagged;
  }

  /* Phrases typiques des kits de phishing M365/OneDrive/SharePoint/DocuSign.
     Insensible à la casse, tolère les balises inline entre mots. */
  function detectPhishingCopy(text, html) {
    var combined = (text + '\n' + html.replace(/<[^>]+>/g, ' ')).toLowerCase().replace(/\s+/g, ' ');
    var patterns = [
      { re: /invited you to (view|edit|access)/, label: 'OneDrive/SharePoint invite pattern' },
      { re: /has shared (a |the )?(document|file|folder)/, label: 'SharePoint share pattern' },
      { re: /view (document|file|invoice|attachment)/, label: 'Generic "view document" CTA' },
      { re: /secure(d)? document/, label: '"Secure document" lure' },
      { re: /(onedrive|sharepoint) (online|for business)/, label: 'Microsoft-branded lure' },
      { re: /you have received a (new )?(secure|encrypted) (message|email)/, label: 'Secure message lure' },
      { re: /docusign|adobe sign|dropbox transfer/, label: 'E-signature platform lure' },
      { re: /your (mailbox|account) (has been|will be) (suspended|blocked|deactivated|upgraded)/, label: 'Account threat lure' },
      { re: /verify your (account|identity|password)/, label: 'Credential harvest lure' },
      { re: /click here to (review|confirm|continue|proceed)/, label: 'Generic phishing CTA' }
    ];
    var matched = [];
    for (var i = 0; i < patterns.length; i++) {
      if (patterns[i].re.test(combined)) matched.push(patterns[i].label);
    }
    return matched;
  }

  /* Moteur de verdict — retourne un score cumulé + alertes + liens suspects.
     Seuils :
       score >= 6 : danger "Account takeover suspected"
       score >= 3 : warning "Suspicious content"
     Les signaux se renforcent mutuellement — aucun seul ne suffit
     (un mail légitime peut avoir From=To, ou un lien netlify.app). */
  function detectCompromiseSignals(headers, auth, hops, body, urls, fromDomain, toDomain) {
    var score = 0, signals = [], alerts = [];

    var self = detectSelfAddressed(headers);
    if (self.selfAddressed) {
      score += 2;
      signals.push('From == To (mass-Bcc pattern)');
    }

    var refs = parseReferencesChain(headers, fromDomain, toDomain);
    if (refs.foreignOrgs.length > 0) {
      score += 2;
      signals.push('References chain contains unrelated domain(s): ' + refs.foreignOrgs.slice(0, 3).join(', '));
    }
    if (refs.m365TenantsCount >= 3) {
      score += 1;
      signals.push(refs.m365TenantsCount + ' unrelated M365 tenants in References (reply-chain camouflage)');
    }

    var suspiciousLinks = detectSuspiciousHosts(urls, fromDomain, toDomain);
    for (var i = 0; i < suspiciousLinks.length; i++) {
      var link = suspiciousLinks[i];
      var add = 0;
      if (link.reasons.some(function (r) { return r.indexOf('Suspect hosting') === 0; })) add = Math.max(add, 3);
      if (link.reasons.some(function (r) { return r.indexOf('Brand in subdomain') === 0; })) add += 2;
      if (link.reasons.some(function (r) { return r.indexOf('URL shortener') === 0; })) add = Math.max(add, 2);
      if (link.reasons.some(function (r) { return r.indexOf('Anchor shows') === 0; })) add += 1;
      if (link.reasons.some(function (r) { return r.indexOf('Punycode') === 0; })) add += 1;
      if (link.reasons.some(function (r) { return r.indexOf('Bare hostname') === 0; })) add += 2;
      if (link.reasons.some(function (r) { return r.indexOf('Raw IP') === 0; })) add += 2;
      score += add;
    }
    if (suspiciousLinks.length > 0) {
      signals.push(suspiciousLinks.length + ' suspicious link' +
        (suspiciousLinks.length > 1 ? 's' : '') + ' in body');
    }

    var copyMatches = detectPhishingCopy(body.text, body.html);
    if (copyMatches.length > 0) {
      score += Math.min(copyMatches.length, 3);
      signals.push('Phishing copy patterns: ' + copyMatches.slice(0, 2).join(' · '));
    }

    /* Authentication all-pass renforce le diagnostic compromise (vs spoofing) */
    var authAllPass = auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass';
    var verdict = null;
    if (score >= 6 || (authAllPass && score >= 4)) {
      verdict = 'compromise';
      alerts.push({ level: 'danger', compromise: true,
        text: 'ACCOUNT TAKEOVER SUSPECTED — authentication passes but content shows ' + signals.length +
          ' phishing indicator' + (signals.length > 1 ? 's' : '') +
          '. The sender mailbox is likely compromised; do NOT click any link, do NOT reply. Warn the sender through a different channel.' });
    } else if (score >= 3) {
      verdict = 'suspicious';
      alerts.push({ level: 'warning', compromise: true,
        text: 'Suspicious content detected (score ' + score + '). ' + signals.join(' · ') +
          '. Verify with the sender through a different channel before acting.' });
    }

    return {
      score: score,
      verdict: verdict,
      signals: signals,
      alerts: alerts,
      suspiciousLinks: suspiciousLinks,
      selfAddressed: self,
      references: refs,
      phishingCopy: copyMatches
    };
  }

  /* ══════════════════════════════════════════════════════════════
     DÉTECTION DE SPOOFING — 6 vérifications clés
     5 checks initiaux (2026-04-10) + 1 ajouté Phase 2 :
       1. DKIM-Signature manquante avec AR dkim=pass (forgé)
       2. Return-Path manquant
       3. Hop Internet → destinataire manquant (tous privés)
       4. AR émis uniquement par l'expéditeur sans tiers
       5. Timestamps identiques cumulés avec IPs privées
       6. Return-Path misaligned vs From (ajouté Phase 2 — hors de detectAlerts,
          traité directement dans renderResults pour accéder à l'objet alignment)
     ══════════════════════════════════════════════════════════════ */

  function detectAlerts(headers, auth, hops) {
    var alerts = [];
    var toDomain = extractDomain(getFirst(headers, 'to'));
    var fromDomain = extractDomain(getFirst(headers, 'from'));

    /* ── 1. DKIM-Signature manquante mais Authentication-Results prétend dkim=pass ── */
    var hasDkimSig = getAll(headers, 'dkim-signature').length > 0;
    if (auth.dkim === 'pass' && !hasDkimSig) {
      alerts.push({ level: 'danger',
        text: 'DKIM-Signature header is MISSING but Authentication-Results claims dkim=pass. This is a strong indicator of forgery — no signature means no verification was possible, someone fabricated the result.' });
    } else if (!hasDkimSig && auth.dkim !== 'pass') {
      alerts.push({ level: 'warning', text: 'No DKIM-Signature header found. The email is not cryptographically signed.' });
    } else if (hasDkimSig && auth.dkim === 'pass') {
      alerts.push({ level: 'success', text: 'DKIM signature present and verified (pass).' });
    }

    /* ── 2. Return-Path manquant ── */
    var hasReturnPath = getAll(headers, 'return-path').length > 0;
    if (!hasReturnPath) {
      alerts.push({ level: 'warning',
        text: 'Return-Path header is missing. Every email received via SMTP should have a Return-Path added by the recipient\'s server. Its absence suggests the email did not follow the normal SMTP path.' });
    }

    /* ── 3. Received headers — hop Internet → destinataire manquant ── */
    if (hops.length > 0 && toDomain) {
      var hasRecipientHop = false;
      for (var i = 0; i < hops.length; i++) {
        var byLower = (hops[i].by || '').toLowerCase();
        /* Le serveur destinataire devrait apparaître dans au moins un "by" */
        if (byLower.indexOf(toDomain) !== -1 || byLower.indexOf(toDomain.split('.')[0]) !== -1) {
          hasRecipientHop = true;
          break;
        }
      }
      if (!hasRecipientHop) {
        /* "Tous privés" = au moins 1 IP présente ET toutes les IPs sont privées.
           Si aucun hop n'a d'IP (cloud Outlook 365), on ne déclenche PAS l'alerte. */
        var hasAnyIpR = hops.some(function (hop) { return !!hop.ip; });
        var allIpsPrivate = hasAnyIpR && hops.every(function (hop) { return !hop.ip || isPrivateIp(hop.ip); });
        if (allIpsPrivate) {
          /* Tous les hops sont internes → fort indicateur de spoofing */
          alerts.push({ level: 'danger',
            text: 'All Received hops use private IPs only (' + fromDomain + ' internal network). The Internet hop from ' + fromDomain + ' to ' + toDomain + ' is MISSING. A legitimate email would show the recipient\'s mail server (' + toDomain + ') in at least one "by" field.' });
        }
        /* Si des IPs publiques sont présentes (Mailgun, SendGrid, etc.), c'est normal
           que le domaine destinataire n'apparaisse pas dans "by" — pas d'alerte. */
      }
    }

    /* ── 4. Authentication-Results émis par l'expéditeur uniquement ── */
    /* L'alerte ne se déclenche que si TOUS les AR viennent du domaine expéditeur,
       ET qu'aucun header tiers d'authentification n'existe (ARC, X-MS-Exchange, etc.).
       Office 365 utilise ARC-Authentication-Results et X-MS-Exchange-Organization-AuthAs
       au lieu du standard Authentication-Results. */
    if (auth.entries.length > 0 && toDomain && fromDomain) {
      var hasNonSenderAR = false;
      var hasSenderOnlyAR = false;
      for (var j = 0; j < auth.entries.length; j++) {
        var arServer = auth.entries[j].server;
        if (arServer.indexOf(fromDomain) !== -1) {
          hasSenderOnlyAR = true;
        } else {
          hasNonSenderAR = true;
        }
      }
      /* Vérifier aussi les headers tiers : ARC, X-MS-Exchange, X-Google-DKIM */
      var hasArc = getAll(headers, 'arc-authentication-results').length > 0;
      var hasMsAuth = getAll(headers, 'x-ms-exchange-organization-authas').length > 0 ||
                      getAll(headers, 'x-ms-exchange-organization-authsource').length > 0;
      var hasThirdParty = hasNonSenderAR || hasArc || hasMsAuth;

      if (hasSenderOnlyAR && !hasThirdParty) {
        alerts.push({ level: 'danger',
          text: 'ALL Authentication-Results were issued by the sender\'s server (' + fromDomain + '). No third-party or recipient server verified this email. The sender is self-validating — these results have NO security value.' });
      } else if (hasThirdParty) {
        alerts.push({ level: 'success', text: 'Authentication verified by a third-party or recipient server — trusted source.' });
      }
    }

    /* ── 5. Cohérence des timestamps ── */
    if (hops.length >= 2) {
      var allSameTimestamp = true;
      var hasNegativeDelay = false;
      for (var k = 1; k < hops.length; k++) {
        if (hops[k].dateObj && hops[k - 1].dateObj) {
          if (Math.abs(hops[k].dateObj - hops[k - 1].dateObj) > 2000) allSameTimestamp = false;
          if (hops[k].dateObj - hops[k - 1].dateObj < -5000) hasNegativeDelay = true;
        }
      }
      /* Timestamps identiques = suspect uniquement si AUSSI tous les hops ont des IPs privées explicites.
         "pas d'IP" (Outlook 365, cloud) ≠ "IP privée" — ne pas confondre.
         Sur un LAN rapide (Exchange local), 3 hops à la même seconde est normal. */
      var hasAnyIp = hops.some(function (hop) { return !!hop.ip; });
      var allExplicitPrivate = hasAnyIp && hops.every(function (hop) { return !hop.ip || isPrivateIp(hop.ip); });
      if (allSameTimestamp && hops.length >= 3 && allExplicitPrivate) {
        alerts.push({ level: 'warning',
          text: 'All Received timestamps are nearly identical AND all IPs are private. Combined with other indicators, this suggests the headers may have been fabricated.' });
      }
      if (hasNegativeDelay) {
        alerts.push({ level: 'warning',
          text: 'Negative delay detected between hops — a later hop has an earlier timestamp. This can indicate forged or reordered Received headers.' });
      }
    }

    /* ── Bonus : SPF / DMARC résultats ── */
    if (auth.spf === 'fail') alerts.push({ level: 'danger', text: 'SPF failed — the sender IP is not authorized to send for this domain.' });
    if (auth.spf === 'softfail') alerts.push({ level: 'warning', text: 'SPF softfail — the sender IP is not explicitly authorized.' });
    if (auth.dmarc === 'fail') alerts.push({ level: 'danger', text: 'DMARC failed — this email does not pass the domain\'s authentication policy.' });

    /* Si tout semble OK mais qu'aucune alerte grave n'a été levée */
    if (auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass' && hasDkimSig && hasReturnPath) {
      alerts.push({ level: 'success',
        text: 'SPF, DKIM (with signature) and DMARC all passed from a trusted source. This email appears legitimate, but always verify the sender address and content carefully.' });
    }

    /* Originating IP */
    var origIp = getFirst(headers, 'x-originating-ip').replace(/[\[\]]/g, '');
    if (origIp && isPrivateIp(origIp)) {
      alerts.push({ level: 'info', text: 'Originating IP is private: ' + origIp + '. The email was composed from the internal network.' });
    }

    return alerts;
  }

  /* ══════════════════════════════════════════════════════════════
     EXTRACTION PIÈCES JOINTES (MIME) + ANALYSE PDF
     Parse le body MIME multipart, extrait les pièces jointes base64,
     analyse les PDF : métadonnées, nombre de pages, IBANs, URLs.
     ══════════════════════════════════════════════════════════════ */

  function extractAttachments(raw) {
    var norm = raw.replace(/\r\n/g, '\n');
    var attachments = [];

    /* Trouver le boundary principal */
    var boundaryMatch = norm.match(/boundary="?([^"\n;]+)"?/i);
    if (!boundaryMatch) return attachments;
    var boundary = '--' + boundaryMatch[1].trim();

    /* File d'attente propre (évite de muter le tableau qu'on itère). */
    var queue = norm.split(boundary).slice(1);
    while (queue.length > 0) {
      var part = queue.shift();
      if (part.trim() === '--' || part.trim() === '') continue;

      var partHeaderEnd = part.indexOf('\n\n');
      if (partHeaderEnd === -1) continue;
      var partHeaders = part.substring(0, partHeaderEnd).toLowerCase();
      var partBody = part.substring(partHeaderEnd + 2).trim();

      var subBoundaryMatch = partHeaders.match(/boundary="?([^"\n;]+)"?/i);
      if (subBoundaryMatch) {
        var subBoundary = '--' + subBoundaryMatch[1].trim();
        var subParts = part.split(subBoundary).slice(1);
        for (var s = 0; s < subParts.length; s++) queue.push(subParts[s]);
        continue;
      }

      /* Est-ce une pièce jointe ? */
      var isAttach = partHeaders.indexOf('attachment') !== -1 || partHeaders.indexOf('application/') !== -1;
      if (!isAttach) continue;

      /* Nom du fichier */
      var nameMatch = part.substring(0, partHeaderEnd).match(/name="?([^"\n;]+)"?/i);
      var filename = nameMatch ? nameMatch[1].trim() : 'unknown';

      /* Content-Type */
      var ctMatch = partHeaders.match(/content-type:\s*([^\n;]+)/i);
      var contentType = ctMatch ? ctMatch[1].trim() : '';

      /* Encoding */
      var isBase64 = partHeaders.indexOf('base64') !== -1;

      /* Décoder le contenu */
      var decoded = null;
      if (isBase64) {
        try {
          /* Nettoyer les espaces/newlines du base64 */
          var clean = partBody.replace(/[^A-Za-z0-9+/=]/g, '');
          var bin = atob(clean);
          decoded = new Uint8Array(bin.length);
          for (var b = 0; b < bin.length; b++) decoded[b] = bin.charCodeAt(b);
        } catch (e) { decoded = null; }
      }

      attachments.push({
        filename: filename,
        contentType: contentType,
        size: decoded ? decoded.length : partBody.length,
        decoded: decoded,
        raw: partBody
      });
    }
    return attachments;
  }

  /* Analyse PDF basique (métadonnées depuis le raw) — synchrone */
  function analyzePdfBasic(bytes) {
    var result = { metadata: {}, pages: 0 };
    var text = '';
    for (var i = 0; i < Math.min(bytes.length, 50000); i++) text += String.fromCharCode(bytes[i]);
    var creatorM = text.match(/\/Creator\s*\(([^)]+)\)/);
    if (creatorM) result.metadata.Creator = creatorM[1];
    var producerM = text.match(/\/Producer\s*\(([^)]+)\)/);
    if (producerM) result.metadata.Producer = producerM[1];
    var creationM = text.match(/\/CreationDate\s*\(([^)]+)\)/);
    if (creationM) result.metadata.CreationDate = creationM[1];
    var modM = text.match(/\/ModDate\s*\(([^)]+)\)/);
    if (modM) result.metadata.ModDate = modM[1];
    var pageMatches = text.match(/\/Type\s*\/Page[^s]/g);
    result.pages = pageMatches ? pageMatches.length : 0;
    return result;
  }

  /* Analyse PDF approfondie via pdf.js (extraction texte complète) — async.
     pdf.js est chargé dynamiquement uniquement quand un PDF est détecté.
     Cherche les IBANs, URLs, et génère des alertes de fraude. */
  async function analyzePdfFull(bytes, basicResult) {
    var result = {
      metadata: basicResult.metadata, pages: basicResult.pages,
      ibans: [], urls: [], foreignIbans: [], alerts: [], fullText: ''
    };

    try {
      /* Charger pdf.js dynamiquement. Le fichier .mjs exporte globalThis.pdfjsLib.
         On le charge via un <script> classique car le JS Hugo pipeline n'est pas un module ES. */
      if (!window.pdfjsLib) {
        await new Promise(function (resolve, reject) {
          var s = document.createElement('script');
          s.src = '/js/pdf.min.mjs';
          s.onload = resolve;
          s.onerror = function () { reject(new Error('Failed to load pdf.js')); };
          document.head.appendChild(s);
        });
      }
      var pdfjsLib = window.pdfjsLib;
      pdfjsLib.GlobalWorkerOptions.workerSrc = '/js/pdf.worker.min.mjs';

      var pdf = await pdfjsLib.getDocument({ data: bytes }).promise;
      result.pages = pdf.numPages;

      /* Extraire le texte de toutes les pages */
      var fullText = '';
      for (var p = 1; p <= pdf.numPages; p++) {
        var page = await pdf.getPage(p);
        var content = await page.getTextContent();
        var pageText = content.items.map(function (item) { return item.str; }).join(' ');
        fullText += pageText + '\n';
      }
      result.fullText = fullText;
      console.log('[email-headers] PDF text extracted (' + fullText.length + ' chars):', fullText.substring(0, 500));
      console.log('[email-headers] IBANs search:', fullText.match(/[A-Z]{2}\d{2}[\s]?[\dA-Z\s]{4,34}/g));

      /* ── IBANs ── */
      var ibanRegex = /[A-Z]{2}\d{2}[\s]?[\dA-Z\s]{4,34}/g;
      var ibanMatch;
      var seen = {};
      while ((ibanMatch = ibanRegex.exec(fullText)) !== null) {
        var iban = ibanMatch[0].replace(/\s/g, '');
        if (iban.length >= 15 && iban.length <= 34 && !seen[iban]) {
          seen[iban] = true;
          result.ibans.push(iban);
          var country = iban.substring(0, 2);
          if (country !== 'LU') {
            result.foreignIbans.push({ iban: iban, country: country });
          }
        }
      }

      /* ── URLs ── */
      var urlRegex = /https?:\/\/[^\s)<>"']+|www\.[^\s)<>"']+\.[a-z]{2,}/gi;
      var urlMatch;
      var seenUrls = {};
      while ((urlMatch = urlRegex.exec(fullText)) !== null) {
        var url = urlMatch[0].replace(/[)\]}>.,]+$/, '');
        if (!seenUrls[url] && url.length > 8) { seenUrls[url] = true; result.urls.push(url); }
      }

    } catch (e) {
      /* pdf.js non disponible ou erreur — on continue avec les données basiques */
      console.error('[email-headers] pdf.js extraction FAILED:', e.message, e);
    }

    /* ── Alertes PDF ── */

    if (result.pages > 1) {
      result.alerts.push({ level: 'warning',
        text: 'PDF has ' + result.pages + ' pages. Simple invoices are usually 1 page. An extra page with bank details could be a fraud attempt.' });
    }
    if (result.foreignIbans.length > 0) {
      for (var f = 0; f < result.foreignIbans.length; f++) {
        result.alerts.push({ level: 'danger',
          text: 'Foreign IBAN detected: ' + result.foreignIbans[f].iban + ' (country: ' + result.foreignIbans[f].country + '). If the sender is a Luxembourg company, a non-LU IBAN is highly suspicious.' });
      }
    }
    /* Creator ≠ Producer — alerter uniquement si les outils sont vraiment différents.
       Paires normales (même outil) : wkhtmltopdf+Qt, Chromium+Skia, Chrome+Skia,
       Firefox+Firefox, Safari+macOS, Word+Word, LibreOffice+LibreOffice, etc. */
    if (result.metadata.Creator && result.metadata.Producer &&
        result.metadata.Creator !== result.metadata.Producer) {
      var c = (result.metadata.Creator || '').toLowerCase();
      var p = (result.metadata.Producer || '').toLowerCase();
      var knownPairs = [
        [/wkhtmltopdf|webkit/, /qt/], [/chromium|chrome/, /skia/],
        [/firefox/, /firefox/], [/safari|apple/, /macos|apple|quartz/],
        [/word|office/, /word|office/], [/libreoffice/, /libreoffice/],
        [/zoho/, /zoho|wkhtmltopdf|qt/], [/odoo/, /odoo|wkhtmltopdf|qt|reportlab/],
        [/reportlab/, /reportlab/], [/itext/, /itext/], [/jasper/, /jasper|itext/]
      ];
      var isKnownPair = knownPairs.some(function (pair) { return pair[0].test(c) && pair[1].test(p); });
      if (!isKnownPair) {
        result.alerts.push({ level: 'info',
          text: 'PDF Creator (' + result.metadata.Creator + ') differs from Producer (' + result.metadata.Producer + '). This can indicate the document was re-exported or modified with a different tool.' });
      }
    }

    return result;
  }

  /* ── Rendu ──────────────────────────────────────────────── */

  async function renderResults(raw) {
    var parsed = extractHeaders(raw);
    var h = parsed.headers;
    var auth = parseAuthResults(h);
    var hops = parseHops(h);
    /* Phase 2 : parsers étendus */
    var arc = parseArcChain(h);
    var msAs = parseMsAntispam(h);
    var listUnsub = parseListUnsubscribe(h);
    var mailClient = detectMailClient(h);
    var esp = detectEsp(h, raw);
    var alignment = checkAlignment(h);
    var totalDelay = calcTotalDelay(hops);
    var alerts = detectAlerts(h, auth, hops);

    /* Compromise / BEC detection (2026-04-23) — body-level heuristics */
    var body = extractBody(raw);
    var bodyUrls = extractBodyUrls(body.text, body.html);
    var fromDomain = extractDomain(getFirst(h, 'from'));
    var toDomain = extractDomain(getFirst(h, 'to'));
    var compromise = detectCompromiseSignals(h, auth, hops, body, bodyUrls, fromDomain, toDomain);
    for (var ci2 = 0; ci2 < compromise.alerts.length; ci2++) alerts.push(compromise.alerts[ci2]);

    /* Return-Path vs From misalignment → alerte warning (Phase 2) */
    if (alignment.checked && !alignment.relaxedMatch) {
      alerts.push({ level: 'warning',
        text: 'Return-Path (' + alignment.rpDomain + ') is NOT aligned with From (' + alignment.fromDomain +
          '). This can indicate a forwarded email, a mailing list, or a spoofing attempt. DMARC strict alignment would fail.' });
    }

    /* Trier alertes : danger en premier, puis warning, info, success */
    var order = { danger: 0, warning: 1, info: 2, success: 3 };
    alerts.sort(function (a, b) { return (order[a.level] || 9) - (order[b.level] || 9); });

    /* ── Résumé (enrichi Phase 2) ── */
    var summaryHtml = '';
    summaryHtml += row('From', '<strong>' + esc(getFirst(h, 'from')) + '</strong>');
    summaryHtml += row('To', esc(getFirst(h, 'to')));
    summaryHtml += row('Subject', '<strong>' + esc(getFirst(h, 'subject')) + '</strong>');
    summaryHtml += row('Date', esc(getFirst(h, 'date')));
    var msgId = getFirst(h, 'message-id');
    if (msgId) summaryHtml += row('Message-ID', '<code style="font-size:0.72rem;">' + esc(msgId) + '</code>');

    /* ESP detection — affichage prominent si détecté (Phase 2) */
    if (esp.detected) {
      var espColor = esp.type === 'marketing' ? 'orange' :
                     esp.type === 'transactional' ? 'blue' : 'gray';
      var espLine = badge(esp.name, espColor) + ' ' +
                    '<span class="eml-esp-type">(' + esc(esp.type) + ')</span>';
      summaryHtml += row('Mailing service', espLine);
    }

    /* Mail client — badge + version + plateforme (Phase 2) */
    if (mailClient) {
      var clientLabel = mailClient.name;
      if (mailClient.version) clientLabel += ' ' + mailClient.version;
      var clientHtml = badge(clientLabel, 'blue');
      if (mailClient.platform) clientHtml += ' ' + badge(mailClient.platform, 'gray');
      clientHtml += ' <span class="eml-client-raw">' + esc(mailClient.raw) + '</span>';
      summaryHtml += row('Mailer', clientHtml);
    }

    /* Return-Path avec badge alignment (Phase 2) */
    var returnPath = getFirst(h, 'return-path');
    if (returnPath) {
      var rpHtml = '<code>' + esc(returnPath) + '</code>';
      if (alignment.checked) {
        rpHtml += ' ' + (alignment.strictMatch
          ? badge('aligned (strict) ✓', 'green')
          : alignment.relaxedMatch
            ? badge('aligned (relaxed) ✓', 'green')
            : badge('misaligned ⚠', 'orange'));
      }
      summaryHtml += row('Return-Path', rpHtml);
    } else {
      summaryHtml += row('Return-Path', badge('MISSING', 'red'));
    }

    /* List-Unsubscribe — présence + one-click (Phase 2, RFC 8058) */
    if (listUnsub.present) {
      var luHtml = listUnsub.oneClick
        ? badge('one-click ✓ (RFC 8058)', 'green')
        : badge('present (no one-click)', 'yellow');
      if (listUnsub.hasHttps) luHtml += ' ' + badge('HTTPS', 'gray');
      if (listUnsub.hasMailto) luHtml += ' ' + badge('mailto', 'gray');
      summaryHtml += row('List-Unsubscribe', luHtml);
    }

    setCard('eml-summary', summaryHtml);

    /* ── Auth (DKIM enrichi + DMARC compauth — Phase 2) ── */
    var spfHtml = authBadge(auth.spf, 'SPF');
    var dkimHtml = authBadge(auth.dkim, 'DKIM');
    var hasDkimSig = getAll(h, 'dkim-signature').length > 0;
    dkimHtml += '<br>' + (hasDkimSig ? badge('Signature present', 'green') : badge('No DKIM-Signature header', 'red'));
    /* ARC chain (Phase 2) */
    if (arc.present) {
      var arcColor = arc.valid ? 'green' : 'orange';
      var arcLabel = 'ARC chain: ' + (arc.valid ? 'valid' : 'present');
      arcLabel += ' (' + arc.hops + ' hop' + (arc.hops > 1 ? 's' : '') + ')';
      dkimHtml += '<br>' + badge(arcLabel, arcColor);
    }

    var dmarcHtml = authBadge(auth.dmarc, 'DMARC');
    /* compauth Microsoft (Phase 2) */
    if (auth.compauth) {
      var compColor = auth.compauth === 'pass' ? 'green' :
                      auth.compauth === 'softpass' ? 'yellow' : 'red';
      var compLabel = 'compauth=' + auth.compauth;
      if (auth.compauthReason) compLabel += ' (reason=' + auth.compauthReason + ')';
      dmarcHtml += '<br>' + badge(compLabel, compColor);
    }
    /* Qui a émis les Authentication-Results ? */
    if (auth.entries.length > 0) {
      for (var ae = 0; ae < auth.entries.length; ae++) {
        var srv = auth.entries[ae].server;
        if (srv) {
          var toDom = extractDomain(getFirst(h, 'to'));
          var isTrusted = srv.indexOf(toDom) !== -1;
          spfHtml += '<br><span style="font-size:0.7rem;color:var(--text-3);">by ' + esc(srv) + (isTrusted ? ' ✓' : ' ⚠') + '</span>';
          break;
        }
      }
    }
    setCard('eml-spf', spfHtml);
    setCard('eml-dkim', dkimHtml);
    setCard('eml-dmarc', dmarcHtml);

    /* ── Spam Score (inchangé — SmarterMail/SpamAssassin) ── */
    var spamStatus = getFirst(h, 'x-spam-status');
    var spamWeight = getFirst(h, 'x-smartermail-totalspamweight');
    var spamHtml = '';
    if (spamStatus) spamHtml += row('Status', spamStatus.toLowerCase().indexOf('yes') !== -1 ? badge('SPAM', 'red') : badge('Clean', 'green'));
    if (spamWeight) spamHtml += row('Weight', spamWeight === '0' ? badge('0', 'green') : badge(spamWeight, parseInt(spamWeight) > 5 ? 'red' : 'orange'));
    if (!spamHtml) spamHtml = badge('No SpamAssassin / SmarterMail headers', 'gray');
    setCard('eml-spam', spamHtml);

    /* ── Microsoft Antispam (Phase 2, 5e carte) ── */
    var msHtml = '';
    if (msAs.present) {
      var f = msAs.fields || {};
      if (f.SCL !== undefined) {
        var scl = parseInt(f.SCL, 10);
        var sclColor = scl <= 1 ? 'green' : scl <= 4 ? 'yellow' : scl <= 6 ? 'orange' : 'red';
        var sclMeaning = scl === -1 ? '(safelisted)' :
                         scl === 0 ? '(clean)' : scl === 1 ? '(non-spam)' :
                         scl <= 4 ? '(suspicious)' : scl <= 6 ? '(likely spam)' : '(high confidence spam)';
        msHtml += row('SCL', badge(f.SCL, sclColor) + ' ' +
          '<span class="eml-ms-meaning">' + sclMeaning + '</span>');
      }
      if (f.BCL !== undefined) {
        var bcl = parseInt(f.BCL, 10);
        var bclColor = bcl === 0 ? 'green' : bcl <= 3 ? 'yellow' : bcl <= 6 ? 'orange' : 'red';
        msHtml += row('BCL', badge(f.BCL, bclColor) +
          ' <span class="eml-ms-meaning">(Bulk Complaint Level)</span>');
      }
      if (f.PCL !== undefined) {
        var pcl = parseInt(f.PCL, 10);
        var pclColor = pcl === 0 ? 'green' : pcl <= 2 ? 'yellow' : 'red';
        msHtml += row('PCL', badge(f.PCL, pclColor) +
          ' <span class="eml-ms-meaning">(Phishing Confidence Level)</span>');
      }
      if (f.SFV) {
        /* SFV verdicts : NSPM=non-spam, SPM=spam, SKN=safe sender, SKI=ignored (bypass),
           SKB=blocked by user, SFE=filtering disabled */
        var sfvMap = { NSPM: 'non-spam', SPM: 'spam', SKN: 'safelisted',
                       SKI: 'skip (whitelisted)', SKB: 'blocked', SFE: 'filter disabled' };
        var sfvLbl = sfvMap[f.SFV] || f.SFV;
        var sfvColor = (f.SFV === 'NSPM' || f.SFV === 'SKN') ? 'green' :
                       (f.SFV === 'SPM' || f.SFV === 'SKB') ? 'red' : 'orange';
        msHtml += row('SFV', badge(f.SFV, sfvColor) +
          ' <span class="eml-ms-meaning">(' + sfvLbl + ')</span>');
      }
      if (f.SFTY) msHtml += row('SFTY', badge(f.SFTY, 'orange') +
        ' <span class="eml-ms-meaning">(Safety — 9.x = phish)</span>');
      if (f.CIP) msHtml += row('CIP', '<code>' + esc(f.CIP) + '</code>');
      if (f.CTRY) msHtml += row('Country', badge(f.CTRY, 'blue'));
      if (f.LANG) msHtml += row('Lang', badge(f.LANG, 'gray'));
      if (f.IPV) msHtml += row('IPV', '<code>' + esc(f.IPV) + '</code>');
      if (msAs.authAs) msHtml += row('AuthAs', '<code>' + esc(msAs.authAs) + '</code>');
      if (msAs.authSource) msHtml += row('AuthSource', '<code style="font-size:0.7rem;">' + esc(msAs.authSource) + '</code>');
      if (!msHtml) msHtml = badge('Headers present but no decodable fields', 'gray');
    } else {
      msHtml = badge('No Microsoft antispam headers', 'gray') +
        '<p class="domain-hint">Only present on M365 / Exchange Online mail flow.</p>';
    }
    setCard('eml-ms-antispam', msHtml);

    /* ── Route : timeline SVG + tableau (Phase 2) ── */
    var routeEl = document.getElementById('eml-route');
    var timelineEl = document.getElementById('eml-timeline');
    var totalDelayEl = document.getElementById('eml-total-delay');

    /* Titre section : délai total de livraison */
    if (totalDelayEl) {
      if (totalDelay !== null) {
        var tdTxt = totalDelay < 1000 ? (totalDelay + 'ms')
                  : totalDelay < 60000 ? (Math.round(totalDelay / 100) / 10 + 's')
                  : (Math.round(totalDelay / 6000) / 10 + 'min');
        totalDelayEl.textContent = ' — total ' + tdTxt;
      } else {
        totalDelayEl.textContent = '';
      }
    }

    if (hops.length > 0) {
      /* Timeline SVG au-dessus (Phase 2) */
      if (timelineEl) timelineEl.innerHTML = renderRouteTimeline(hops);

      /* Tableau en-dessous (conservé pour copier-coller) */
      var tHtml = '<div class="domain-table-wrap"><table class="domain-table"><thead><tr>' +
        '<th>#</th><th>From</th><th>By</th><th>IP</th><th>Protocol</th><th>Time</th><th>Delay</th>' +
        '</tr></thead><tbody>';
      for (var i = 0; i < hops.length; i++) {
        var hop = hops[i];
        var ipCell = hop.ip ? (isPrivateIp(hop.ip) ? badge(hop.ip + ' (private)', 'orange') : '<code>' + esc(hop.ip) + '</code>') : '—';
        var timeStr = hop.dateObj ? hop.dateObj.toLocaleTimeString('fr-LU', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
        tHtml += '<tr><td>' + (i + 1) + '</td>' +
          '<td><code style="font-size:0.7rem;">' + esc(hop.from || '—') + '</code></td>' +
          '<td><code style="font-size:0.7rem;">' + esc(hop.by || '—') + '</code></td>' +
          '<td>' + ipCell + '</td>' +
          '<td>' + (hop.protocol ? badge(hop.protocol, /TLS/i.test(hop.protocol) ? 'green' : 'gray') : '—') + '</td>' +
          '<td style="white-space:nowrap;">' + timeStr + '</td>' +
          '<td>' + formatDelay(hop.delay) + '</td></tr>';
      }
      tHtml += '</tbody></table></div>';
      routeEl.innerHTML = tHtml;
    } else {
      if (timelineEl) timelineEl.innerHTML = '';
      routeEl.innerHTML = badge('No Received headers found', 'gray');
    }

    /* Pièces jointes (extraction MIME + analyse PDF) */
    var attachSection = document.getElementById('eml-attach-section');
    var attachEl = document.getElementById('eml-attachments');
    var attachments = extractAttachments(raw);
    if (attachments.length > 0) {
      var attHtml = '';
      for (var ai = 0; ai < attachments.length; ai++) {
        var att = attachments[ai];
        var sizeKB = (att.size / 1024).toFixed(1);
        attHtml += '<div class="domain-card" style="margin-bottom:1rem;">';
        attHtml += '<h3>' + esc(att.filename) + '</h3>';
        attHtml += '<div class="domain-card-body">';
        attHtml += row('Type', badge(att.contentType || 'unknown', 'gray'));
        attHtml += row('Size', sizeKB + ' KB');

        /* Analyse PDF (basique immédiate + texte complet via pdf.js async) */
        if (att.filename.toLowerCase().indexOf('.pdf') !== -1 && att.decoded) {
          var basic = analyzePdfBasic(att.decoded);
          if (basic.pages) attHtml += row('Pages', basic.pages === 1 ? badge('1 page', 'green') : badge(basic.pages + ' pages', 'orange'));
          if (basic.metadata.Creator) attHtml += row('Creator', '<code>' + esc(basic.metadata.Creator) + '</code>');
          if (basic.metadata.Producer) attHtml += row('Producer', '<code>' + esc(basic.metadata.Producer) + '</code>');
          if (basic.metadata.CreationDate) attHtml += row('Created', '<code>' + esc(basic.metadata.CreationDate) + '</code>');
          if (basic.metadata.ModDate) attHtml += row('Modified', '<code>' + esc(basic.metadata.ModDate) + '</code>');
          /* Placeholder pour le texte extrait — sera rempli par pdf.js */
          attHtml += '<div id="pdf-deep-' + ai + '"><div class="domain-skeleton" style="margin-top:0.5rem;"></div><span style="font-size:0.7rem;color:var(--text-3);">Extracting text with pdf.js...</span></div>';
          /* Lancer l'analyse approfondie en async */
          (function (idx, decoded, basicRes) {
            analyzePdfFull(decoded, basicRes).then(function (pdf) {
              var deepEl = document.getElementById('pdf-deep-' + idx);
              if (!deepEl) return;
              var deepHtml = '';
              if (pdf.ibans.length > 0) {
                var ibanHtml = pdf.ibans.map(function (ib) {
                  var country = ib.substring(0, 2);
                  return badge(ib.substring(0, 4) + ' ... ' + ib.substring(ib.length - 4), country === 'LU' ? 'green' : 'red') +
                    ' <span style="font-size:0.7rem;color:var(--text-3);">(' + country + ')</span>';
                }).join(' ');
                deepHtml += row('IBANs found', ibanHtml);
              }
              if (pdf.urls.length > 0) {
                var urlHtml = pdf.urls.map(function (u) { return '<code style="font-size:0.7rem;">' + esc(u) + '</code>'; }).join('<br>');
                deepHtml += row('URLs found', urlHtml);
              }
              if (pdf.pages) deepHtml += row('Pages (pdf.js)', pdf.pages === 1 ? badge('1 page', 'green') : badge(pdf.pages + ' pages', 'orange'));
              if (!deepHtml) deepHtml = '<span style="font-size:0.72rem;color:var(--text-3);">No IBANs or URLs found in PDF text.</span>';
              deepEl.innerHTML = deepHtml;
              /* Ajouter les alertes PDF aux alertes existantes */
              if (pdf.alerts.length > 0) {
                var alertsEl = document.getElementById('eml-alerts');
                var alertsSection = document.getElementById('eml-alerts-section');
                var icons = { danger: '🚨', warning: '⚠️', info: 'ℹ️', success: '✅' };
                var newAlerts = '';
                for (var pa = 0; pa < pdf.alerts.length; pa++) {
                  newAlerts += '<div class="eml-alert eml-alert-' + pdf.alerts[pa].level + '">' +
                    '<span class="eml-alert-icon">' + (icons[pdf.alerts[pa].level] || '') + '</span>' +
                    '<span>' + esc(pdf.alerts[pa].text) + '</span></div>';
                }
                if (alertsEl) alertsEl.innerHTML = newAlerts + alertsEl.innerHTML;
                if (alertsSection) alertsSection.style.display = '';
              }
            });
          })(ai, att.decoded, basic);
        }
        attHtml += '</div></div>';
      }
      attachEl.innerHTML = attHtml;
      attachSection.style.display = '';
    } else {
      attachSection.style.display = 'none';
    }

    /* Re-trier alertes (les alertes PDF viennent d'être ajoutées) */
    alerts.sort(function (a, b) { return (order[a.level] || 9) - (order[b.level] || 9); });

    /* Alertes */
    var alertsSection = document.getElementById('eml-alerts-section');
    var alertsEl = document.getElementById('eml-alerts');
    if (alerts.length > 0) {
      var icons = { danger: '🚨', warning: '⚠️', info: 'ℹ️', success: '✅' };
      var aHtml = '';
      for (var a = 0; a < alerts.length; a++) {
        aHtml += '<div class="eml-alert eml-alert-' + alerts[a].level + '">' +
          '<span class="eml-alert-icon">' + (icons[alerts[a].level] || '') + '</span>' +
          '<span>' + esc(alerts[a].text) + '</span></div>';
      }
      alertsEl.innerHTML = aHtml;
      alertsSection.style.display = '';
    } else {
      alertsSection.style.display = 'none';
    }

    /* Raw */
    document.getElementById('eml-raw-display').textContent = parsed.rawHeaders;

    /* ── Bandeau critique — rouge pulsant en haut si danger détecté ──
       Titre dynamique : "compromise" (takeover) prend le pas sur "spoofing". */
    var criticalEl = document.getElementById('eml-critical');
    var dangerAlerts = alerts.filter(function (a) { return a.level === 'danger'; });
    if (dangerAlerts.length > 0 && criticalEl) {
      var isCompromise = compromise.verdict === 'compromise';
      var ds = criticalEl.dataset || {};
      var critTitle = isCompromise
        ? (ds.lblTakeover || '⛔ Account takeover suspected — DO NOT click any link')
        : (ds.lblSpoof || '⛔ Suspicious email detected');
      var lblIndicators = ds.lblIndicators || 'Indicators:';
      var lblSuspicious = ds.lblSuspicious || 'Suspicious links:';
      var critHtml = '<p class="eml-critical-title">' + esc(critTitle) + '</p>';
      for (var ci = 0; ci < dangerAlerts.length; ci++) {
        critHtml += '<p class="eml-critical-text">• ' + esc(dangerAlerts[ci].text) + '</p>';
      }
      if (isCompromise && compromise.signals.length > 0) {
        critHtml += '<p class="eml-critical-text" style="margin-top:0.75rem;"><strong>' + esc(lblIndicators) + '</strong></p>';
        critHtml += '<ul class="eml-critical-list">';
        for (var si = 0; si < compromise.signals.length; si++) {
          critHtml += '<li>' + esc(compromise.signals[si]) + '</li>';
        }
        critHtml += '</ul>';
      }
      if (compromise.suspiciousLinks.length > 0) {
        critHtml += '<p class="eml-critical-text" style="margin-top:0.75rem;"><strong>' + esc(lblSuspicious) + '</strong></p>';
        critHtml += '<ul class="eml-critical-list">';
        for (var li = 0; li < compromise.suspiciousLinks.length; li++) {
          var sl = compromise.suspiciousLinks[li];
          critHtml += '<li><code>' + esc(sl.host) + '</code> — ' + esc(sl.reasons.join('; ')) + '</li>';
        }
        critHtml += '</ul>';
      }
      criticalEl.innerHTML = critHtml;
      criticalEl.className = 'eml-critical' + (isCompromise ? ' eml-critical-compromise' : '');
      criticalEl.style.display = 'block';
    } else if (criticalEl) {
      criticalEl.style.display = 'none';
      criticalEl.className = 'eml-critical';
    }

    resultsDiv.style.display = 'block';
    clearBtn.style.display = '';
    var actionsEl = document.getElementById('eml-actions');
    if (actionsEl) actionsEl.style.display = '';

    /* Scroll vers le bandeau critique ou les alertes */
    if (criticalEl && criticalEl.style.display !== 'none') {
      criticalEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else if (alertsSection.style.display !== 'none') {
      alertsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  /* ── Events ─────────────────────────────────────────────── */

  analyzeBtn.addEventListener('click', function () {
    var raw = rawInput.value.trim();
    if (!raw) return;
    if (!qCheck()) { qUpdate(); return; }
    qRecord(); qUpdate();
    renderResults(raw);
  });

  clearBtn.addEventListener('click', function () {
    rawInput.value = '';
    resultsDiv.style.display = 'none';
    clearBtn.style.display = 'none';
    var crit = document.getElementById('eml-critical');
    if (crit) crit.style.display = 'none';
    var acts = document.getElementById('eml-actions');
    if (acts) acts.style.display = 'none';
    var repWrap = document.getElementById('eml-report-email-wrap');
    if (repWrap) repWrap.style.display = 'none';
    if (fileInput) fileInput.value = '';
  });

  rawInput.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyzeBtn.click();
  });

  /* .eml file upload */
  if (fileInput) {
    fileInput.addEventListener('change', function () {
      if (!fileInput.files.length) return;
      var reader = new FileReader();
      reader.onload = function () {
        rawInput.value = reader.result;
        analyzeBtn.click();
      };
      reader.readAsText(fileInput.files[0]);
    });
  }

  /* Drag & drop .eml */
  rawInput.addEventListener('dragover', function (e) { e.preventDefault(); rawInput.style.borderColor = 'var(--blue)'; });
  rawInput.addEventListener('dragleave', function () { rawInput.style.borderColor = ''; });
  rawInput.addEventListener('drop', function (e) {
    e.preventDefault();
    rawInput.style.borderColor = '';
    if (e.dataTransfer.files.length) {
      var reader = new FileReader();
      reader.onload = function () {
        rawInput.value = reader.result;
        analyzeBtn.click();
      };
      reader.readAsText(e.dataTransfer.files[0]);
    }
  });

  /* ══════════════════════════════════════════════════════════════
     BOUTONS ACTIONS — Envoyer au support + Recevoir rapport par email
     ══════════════════════════════════════════════════════════════ */

  /* Génère le HTML du rapport (résumé textuel des résultats pour l'email) */
  function buildReportHtml() {
    var critEl = document.getElementById('eml-critical');
    var summaryEl = document.getElementById('eml-summary');
    var alertsEl = document.getElementById('eml-alerts');
    var routeEl = document.getElementById('eml-route');
    var attachEl = document.getElementById('eml-attachments');

    var html = '';

    /* Bandeau critique */
    if (critEl && critEl.style.display !== 'none') {
      html += '<div style="background:#dc2626;color:#fff;padding:12px 16px;border-radius:8px;margin-bottom:16px;">' + critEl.innerHTML + '</div>';
    }

    /* Résumé */
    if (summaryEl) html += '<h3 style="color:#1e2d5a;font-size:14px;margin:16px 0 8px;">Summary</h3>' + summaryEl.innerHTML;

    /* Alertes */
    if (alertsEl && alertsEl.innerHTML) html += '<h3 style="color:#1e2d5a;font-size:14px;margin:16px 0 8px;">Alerts</h3>' + alertsEl.innerHTML;

    /* Route */
    if (routeEl && routeEl.innerHTML) html += '<h3 style="color:#1e2d5a;font-size:14px;margin:16px 0 8px;">Route</h3>' + routeEl.innerHTML;

    /* Attachments */
    if (attachEl && attachEl.innerHTML) html += '<h3 style="color:#1e2d5a;font-size:14px;margin:16px 0 8px;">Attachments</h3>' + attachEl.innerHTML;

    return html;
  }

  /* Envoyer au support — même pattern que What's My IP (ticket_prefill) */
  var sendSupportBtn = document.getElementById('eml-send-support');
  if (sendSupportBtn) {
    sendSupportBtn.addEventListener('click', function () {
      var summaryEl = document.getElementById('eml-summary');
      if (!summaryEl) return;
      /* Extraire le texte du résumé */
      var from = '', to = '', subject = '';
      summaryEl.querySelectorAll('.domain-row').forEach(function (r) {
        var label = r.querySelector('.domain-row-label');
        var value = r.querySelector('.domain-row-value');
        if (!label || !value) return;
        var l = label.textContent.trim();
        var v = value.textContent.trim();
        if (l === 'From') from = v;
        if (l === 'To') to = v;
        if (l === 'Subject') subject = v;
      });
      var alertsEl = document.getElementById('eml-alerts');
      var alertTexts = [];
      if (alertsEl) alertsEl.querySelectorAll('.eml-alert').forEach(function (a) { alertTexts.push('• ' + a.textContent.trim()); });

      var ticketSubject = 'eMail Checkup: ' + (subject || from || 'suspicious email');
      var ticketDesc = 'From: ' + from + '\nTo: ' + to + '\nSubject: ' + subject +
        '\n\n--- Alerts ---\n' + (alertTexts.length ? alertTexts.join('\n') : 'No alerts');

      sessionStorage.setItem('ticket_prefill', JSON.stringify({ subject: ticketSubject, description: ticketDesc }));
      var lang = document.documentElement.lang || 'lb';
      location.href = '/' + lang + '/contact/ticket/';
    });
  }

  /* Recevoir rapport par email */
  var sendReportBtn = document.getElementById('eml-send-report');
  var reportEmailWrap = document.getElementById('eml-report-email-wrap');
  var reportEmailInput = document.getElementById('eml-report-email');
  var reportConfirmBtn = document.getElementById('eml-report-confirm');
  var reportStatus = document.getElementById('eml-report-status');

  if (sendReportBtn && reportEmailWrap) {
    sendReportBtn.addEventListener('click', function () {
      reportEmailWrap.style.display = reportEmailWrap.style.display === 'none' ? 'block' : 'none';
      if (reportEmailInput) reportEmailInput.focus();
    });
  }

  if (reportConfirmBtn && reportEmailInput) {
    reportConfirmBtn.addEventListener('click', function () {
      var email = reportEmailInput.value.trim();
      if (!email || email.indexOf('@') === -1) return;

      reportConfirmBtn.disabled = true;
      reportConfirmBtn.textContent = '...';

      var html = buildReportHtml();
      fetch(API_BASE + '/api/email-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: email,
          subject: EMAIL_REPORT_SUBJECT,
          html: html
        })
      }).then(function (r) {
        if (r.ok) {
          if (reportStatus) { reportStatus.textContent = '✓ ' + (document.getElementById('eml-quota-msg')?.dataset.lblBlocked ? 'Sent!' : 'Report sent!'); reportStatus.style.color = '#27ae60'; }
        } else {
          if (reportStatus) { reportStatus.textContent = '✕ Error'; reportStatus.style.color = '#e74c3c'; }
        }
      }).catch(function () {
        if (reportStatus) { reportStatus.textContent = '✕ Network error'; reportStatus.style.color = '#e74c3c'; }
      }).finally(function () {
        reportConfirmBtn.disabled = false;
        reportConfirmBtn.textContent = '→';
      });
    });
  }

})();
