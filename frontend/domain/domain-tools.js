/**
 * Domain Checkup — DNS, SSL, RIPE, CMS, WHOIS, DNSSEC, CAA, BIMI, MTA-STS, DANE, SPF recursive
 * @lwpc/toolbox (MIT) — frontend.
 *
 * Backend endpoints expected at `API_BASE` (default: same-origin):
 *   GET /api/domain-tools/ip-info, /ssl, /whois, /detect,
 *       /mta-sts, /autodiscover, /autoconfig
 *
 * Client-side (Cloudflare DoH https://cloudflare-dns.com/dns-query, JSON format) :
 *   - DNS : A, AAAA, MX, TXT, CAA, SOA, TLSA, SRV, PTR, CNAME
 *   - Flag AD pour DNSSEC (via dohQueryFull)
 *   - FCrDNS : reverse PTR → forward A → match (via fcrDnsCheck)
 *   - SPF récursif : suit include:/redirect=, compte lookups RFC 7208 (via resolveSpfTree)
 *
 * Backend (/api/domain-tools/, Node.js 127.0.0.1:3100) :
 *   - ip-info       : RIPE Stat API → netname, org, ASN, CIDR, pays
 *   - ssl           : tls.connect() → certificat (443 pour le site web uniquement)
 *   - detect        : HTTP fetch → analyse headers/body → CMS/plateforme
 *   - whois         : system `whois` → registrant, registrar, NS, dates
 *   - mta-sts       : fetch mta-sts.txt + parse policy (2026-04-13)
 *   - autodiscover  : check CNAME M365 + HTTP GET endpoint (2026-04-13)
 *   - autoconfig    : parse XML Thunderbird, fallback Mozilla ISPDB (2026-04-13)
 *
 * 4 sections affichées progressivement :
 *   1. Website Hosting (5 cartes) : DNS/Network, WHOIS/RDAP, SSL, CMS, DNS Security
 *   2. Mail Intelligence : MX table avec TLSA (DANE) + FCrDNS.
 *      ⚠ Pas de colonne "SSL" : la TLS réelle sur port 25 ne peut pas être
 *      testée depuis notre serveur (port 25 sortant fermé + 465/587 ne sont
 *      PAS des ports MX mais submission). Lien vers internet.nl/mail/{domain}/
 *      pour un audit externe complet.
 *   3. Email Security (5 cartes) : SPF récursif, DMARC, DKIM (15 sel), BIMI, MTA-STS
 *   4. Email Client Config : Autodiscover, Autoconfig (Thunderbird), SRV records
 *
 * Quota client : 10 analyses / 30 min (sessionStorage + backend filet de sécurité).
 *   Labels i18n via data-lbl-* sur #domain-quota-msg (4 langues).
 *   Bypass optionnel côté client : window.lwpcWhitelisted = true.
 *
 * Gère les MX qui pointent directement vers une IP (ex: zenner.lu → 213.135.240.135).
 * Détection mail providers LU : POST Luxembourg (pt.lu), Visual Online (vo.lu), internet.lu.
 *
 * ⚠ Après modification, supprimer resources/ et rebuild (Hugo cache les assets).
 */
(function () {
  'use strict';

  /* API endpoint base — override via `window.LWPC_API_BASE = 'https://api.example.com'`
     before loading this script. Default: same-origin. */
  var API_BASE = (typeof window !== 'undefined' && window.LWPC_API_BASE) || '';

  var input      = document.getElementById('domain-input');
  var analyzeBtn = document.getElementById('domain-analyze');
  var results    = document.getElementById('domain-results');
  var quotaMsg   = document.getElementById('domain-quota-msg');
  if (!input || !analyzeBtn) return;

  /* ══════════════════════════════════════════════════════════════
     QUOTA CLIENT — 10 analyses / 30 min (volontairement limité)
     Stocké en sessionStorage pour persister entre rechargements.
     Le backend applique aussi un quota (filet de sécurité).
     ══════════════════════════════════════════════════════════════ */

  var QUOTA_MAX = 10;
  var QUOTA_WINDOW = 30 * 60 * 1000; /* 30 min en ms */
  var QUOTA_KEY = 'domain_analyses';

  function getQuotaData() {
    try {
      var d = JSON.parse(sessionStorage.getItem(QUOTA_KEY));
      if (d && Array.isArray(d.ts)) return d;
    } catch (e) {}
    return { ts: [] };
  }

  function saveQuotaData(d) {
    sessionStorage.setItem(QUOTA_KEY, JSON.stringify(d));
  }

  function checkQuota() {
    if (window.lwpcWhitelisted) return true;
    var d = getQuotaData();
    var now = Date.now();
    /* Purge les timestamps expirés */
    d.ts = d.ts.filter(function (t) { return t > now - QUOTA_WINDOW; });
    saveQuotaData(d);
    return d.ts.length < QUOTA_MAX;
  }

  function recordAnalysis() {
    var d = getQuotaData();
    var now = Date.now();
    d.ts = d.ts.filter(function (t) { return t > now - QUOTA_WINDOW; });
    d.ts.push(now);
    saveQuotaData(d);
  }

  function getQuotaRemaining() {
    var d = getQuotaData();
    var now = Date.now();
    d.ts = d.ts.filter(function (t) { return t > now - QUOTA_WINDOW; });
    return QUOTA_MAX - d.ts.length;
  }

  function quotaLabel(key, fallback) {
    return (quotaMsg && quotaMsg.dataset['lbl' + key]) || fallback;
  }

  function updateQuotaDisplay() {
    if (window.lwpcWhitelisted || !quotaMsg) return;
    var remaining = getQuotaRemaining();
    var base = quotaLabel('Limited', 'Voluntarily limited to') + ' ' + QUOTA_MAX + ' ' +
               quotaLabel('Unit', 'analyses') + ' / 30 min';
    if (remaining <= 0) {
      quotaMsg.innerHTML = '⚠ ' + base + ' — <strong>0</strong> ' +
        quotaLabel('Remaining', 'remaining') + '. ' + quotaLabel('Blocked', 'Please try again later.');
      quotaMsg.classList.add('is-blocked');
      analyzeBtn.disabled = true;
    } else {
      quotaMsg.innerHTML = base + ' — <strong>' + remaining + '</strong> ' +
        quotaLabel('Remaining', 'remaining');
      quotaMsg.classList.remove('is-blocked');
      analyzeBtn.disabled = false;
    }
    quotaMsg.hidden = false;
  }

  /* Init display */
  updateQuotaDisplay();

  /* ══════════════════════════════════════════════════════════════
     CLOUDFLARE DoH — DNS queries
     ══════════════════════════════════════════════════════════════ */

  async function dohQuery(name, type) {
    var resp = await fetch(
      'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=' + type,
      { headers: { 'Accept': 'application/dns-json' } }
    );
    var data = await resp.json();
    return (data.Answer || []).map(function (a) { return { type: a.type, data: a.data.replace(/"/g, '') }; });
  }

  /* Variante qui retourne aussi le flag AD (Authenticated Data) pour DNSSEC.
     Cloudflare DoH renvoie AD:true si la réponse est validée DNSSEC. */
  async function dohQueryFull(name, type) {
    var resp = await fetch(
      'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=' + type,
      { headers: { 'Accept': 'application/dns-json' } }
    );
    var data = await resp.json();
    return {
      ad: data.AD === true,
      status: data.Status,
      answers: (data.Answer || []).map(function (a) { return { type: a.type, data: a.data.replace(/"/g, '') }; })
    };
  }

  /* PTR query pour FCrDNS : construit in-addr.arpa à partir d'une IPv4.
     (IPv6 non géré ici — usage marginal pour les MX.) */
  async function dohReverse(ip) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
    var parts = ip.split('.').reverse().join('.');
    var records = await dohQuery(parts + '.in-addr.arpa', 'PTR');
    return records.length ? records[0].data.replace(/\.$/, '') : null;
  }

  /* FCrDNS = Forward-Confirmed Reverse DNS.
     1) reverse PTR sur l'IP → hostname
     2) forward A sur le hostname → IPs
     3) vérifie que l'IP initiale est dans la liste
     Retourne {ok, ptr, error?}. */
  async function fcrDnsCheck(ip) {
    try {
      var ptr = await dohReverse(ip);
      if (!ptr) return { ok: false, ptr: null, error: 'No PTR' };
      var forward = await dohQuery(ptr, 'A');
      var ips = forward.map(function (r) { return r.data; });
      return { ok: ips.indexOf(ip) !== -1, ptr: ptr, forwardIps: ips };
    } catch (e) {
      return { ok: false, ptr: null, error: 'Query error' };
    }
  }

  /* ══════════════════════════════════════════════════════════════
     SPF RÉCURSIF — suit include: / redirect= et compte les lookups DNS.
     Limite RFC 7208 : 10 lookups max. a/mx/ptr/exists comptent aussi.
     Construit un arbre {domain, record, mechanisms[], includes[], errors[]}.
     ══════════════════════════════════════════════════════════════ */
  async function resolveSpfTree(domain, depth, counter, visited) {
    depth = depth || 0;
    counter = counter || { count: 0, exceeded: false };
    visited = visited || {};
    if (visited[domain]) {
      return { domain: domain, record: null, mechanisms: [], includes: [],
               errors: ['Loop detected'] };
    }
    visited[domain] = true;
    if (depth > 10) {
      counter.exceeded = true;
      return { domain: domain, record: null, mechanisms: [], includes: [],
               errors: ['Max depth exceeded'] };
    }

    var node = { domain: domain, record: null, mechanisms: [], includes: [], errors: [] };
    var txt;
    try { txt = await dohQuery(domain, 'TXT'); }
    catch (e) { node.errors.push('TXT query failed'); return node; }

    var spf = null;
    for (var i = 0; i < txt.length; i++) {
      if (txt[i].data.indexOf('v=spf1') === 0) { spf = txt[i].data; break; }
    }
    if (!spf) { node.errors.push('No SPF record'); return node; }
    node.record = spf;

    var parts = spf.split(/\s+/);
    for (var p = 1; p < parts.length; p++) {
      var mech = parts[p];
      node.mechanisms.push(mech);

      /* Count DNS lookups (RFC 7208 §4.6.4) */
      if (mech === 'a' || mech.indexOf('a:') === 0 || mech.indexOf('a/') === 0 ||
          mech === 'mx' || mech.indexOf('mx:') === 0 || mech.indexOf('mx/') === 0 ||
          mech.indexOf('ptr') === 0 || mech.indexOf('exists:') === 0) {
        counter.count++;
      }

      if (mech.indexOf('include:') === 0) {
        counter.count++;
        var incDomain = mech.substring(8).replace(/\.$/, '');
        if (counter.count > 10) { counter.exceeded = true; continue; }
        var child = await resolveSpfTree(incDomain, depth + 1, counter, visited);
        node.includes.push(child);
      } else if (mech.indexOf('redirect=') === 0) {
        counter.count++;
        var redDomain = mech.substring(9).replace(/\.$/, '');
        if (counter.count > 10) { counter.exceeded = true; continue; }
        var redChild = await resolveSpfTree(redDomain, depth + 1, counter, visited);
        redChild.isRedirect = true;
        node.includes.push(redChild);
      }
    }
    return node;
  }

  /* Liste étendue de sélecteurs DKIM courants (15 cap — décision 2026-04-13).
     Plus c'est long, plus l'analyse est lente. */
  var DKIM_SELECTORS = [
    'default', 'selector1', 'selector2', 'google', 'dkim', 'k1',
    's1', 's2', 'mail', 'mandrill', 'mxvault',
    'protonmail', 'protonmail2', 'protonmail3', 'cm'
  ];

  /* ══════════════════════════════════════════════════════════════
     BACKEND + HELPERS
     ══════════════════════════════════════════════════════════════ */

  async function apiCall(endpoint, params) {
    var qs = Object.keys(params).map(function (k) { return k + '=' + encodeURIComponent(params[k]); }).join('&');
    var resp = await fetch(API_BASE + '/api/domain-tools/' + endpoint + '?' + qs);
    return resp.json();
  }

  function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  function badge(text, color) {
    var colors = { green: '#27ae60', yellow: '#f1c40f', red: '#e74c3c', blue: '#3d5394', gray: '#8b949e', orange: '#e67e22' };
    var bg = colors[color] || colors.gray;
    return '<span class="domain-badge" style="background:' + bg + '22;color:' + bg + ';border:1px solid ' + bg + '55">' + esc(text) + '</span>';
  }

  function codeBlock(text) {
    return '<div class="domain-code-wrap"><code class="domain-code">' + esc(text) + '</code>' +
      '<button class="domain-copy-btn" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent)">Copy</button></div>';
  }

  function row(label, value) {
    return '<div class="domain-row"><span class="domain-row-label">' + esc(label) + '</span><span class="domain-row-value">' + value + '</span></div>';
  }

  function setCard(id, html) { var el = document.getElementById(id); if (el) el.innerHTML = html; }
  function setError(id, msg) { setCard(id, '<span class="domain-error">' + esc(msg) + '</span>'); }

  /* Detect if a string is an IP address (not a hostname) */
  function isIP(str) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(str) || str.indexOf(':') !== -1; }

  /* ══════════════════════════════════════════════════════════════
     SECTION 1 — Website Hosting
     analyzeWebsite() remplit les 4 cartes originales (fusionné 2026-04-10) :
       DNS/Network (A/AAAA + RIPE IP info fusionnés), WHOIS/RDAP, SSL, CMS
     La 5e carte "DNS Security" (DNSSEC/CAA/SOA) ajoutée en Phase 4 est
     gérée séparément par analyzeDnsSecurity() plus bas.
     NS supprimé de DNS/Network (déjà dans WHOIS/RDAP).
     ══════════════════════════════════════════════════════════════ */

  async function analyzeWebsite(domain) {
    /* DNS A + AAAA + IP Info (fusionnés dans une seule carte) */
    try {
      var aRecords = await dohQuery(domain, 'A');
      var aaaaRecords = await dohQuery(domain, 'AAAA');
      var ipv4 = aRecords.map(function (r) { return r.data; });
      var ipv6 = aaaaRecords.map(function (r) { return r.data; });
      var html = '';
      if (ipv4.length) html += row('IPv4', ipv4.map(function (ip) { return '<code>' + esc(ip) + '</code>'; }).join(' '));
      if (ipv6.length) html += row('IPv6', ipv6.map(function (ip) { return '<code>' + esc(ip) + '</code>'; }).join(' '));
      if (!ipv4.length && !ipv6.length) {
        setCard('dns-body', '<span class="domain-error">No A/AAAA records</span>');
      } else {
        setCard('dns-body', html);
        /* RIPE IP Info — enrichit la même carte avec org, ASN, CIDR, pays */
        if (ipv4.length) {
          apiCall('ip-info', { ip: ipv4[0] }).then(function (d) {
            if (d.error) return;
            var h = '';
            if (d.org) h += row('Organization', '<strong>' + esc(d.org) + '</strong>');
            if (d.netname) h += row('Netname', esc(d.netname));
            if (d.prefix) h += row('CIDR', '<code>' + esc(d.prefix) + '</code>');
            if (d.asn) h += row('ASN', badge('AS' + d.asn, 'blue'));
            if (d.country) h += row('Country', badge(d.country, 'gray'));
            if (h) {
              var el = document.getElementById('dns-body');
              if (el) el.innerHTML += '<div class="domain-divider"></div>' + h;
            }
          }).catch(function () {});
        }
      }
    } catch (e) { setError('dns-body', 'DNS error'); }

    /* WHOIS — via backend (system whois command, supporte .lu et tous les TLDs) */
    apiCall('whois', { domain: domain }).then(function (d) {
      if (d.error) { setCard('whois-body', badge('WHOIS not available', 'gray')); return; }
      var h = '';
      if (d.registrant) h += row('Registrant', '<strong>' + esc(d.registrant) + '</strong>');
      if (d.org && d.org !== d.registrant) h += row('Organization', esc(d.org));
      if (d.country) h += row('Country', badge(d.country, 'gray'));
      if (d.registrar) h += row('Registrar', esc(d.registrar));
      if (d.created) h += row('Created', esc(d.created));
      if (d.expires) h += row('Expires', esc(d.expires));
      if (d.updated) h += row('Updated', esc(d.updated));
      if (d.nservers && d.nservers.length) {
        h += row('Nameservers', d.nservers.map(function (ns) { return '<code>' + esc(ns) + '</code>'; }).join('<br>'));
      }
      setCard('whois-body', h || 'No WHOIS data');
    }).catch(function () { setCard('whois-body', badge('WHOIS query failed', 'gray')); });

    /* SSL Certificate */
    apiCall('ssl', { host: domain, port: 443 }).then(function (d) {
      if (d.error) { setError('ssl-body', d.error); return; }
      var statusBadge = d.status === 'valid' ? badge('Valid ✓', 'green')
        : d.status === 'expiring' ? badge('Expiring ⚠', 'yellow')
        : badge('Expired ✕', 'red');
      var h = row('Issuer', '<strong>' + esc(d.issuer) + '</strong>');
      h += row('Status', statusBadge + ' — ' + d.daysLeft + ' days left');
      h += row('Type', badge(d.type, 'blue'));
      h += row('Valid', esc(d.validFrom.substring(0, 10)) + ' → ' + esc(d.validTo.substring(0, 10)));
      if (d.sans && d.sans.length) h += row('SANs', d.sans.map(function (s) { return '<code>' + esc(s) + '</code>'; }).join(' '));
      setCard('ssl-body', h);
    }).catch(function () { setError('ssl-body', 'TLS connection error'); });

    /* CMS Detection */
    apiCall('detect', { url: domain }).then(function (d) {
      if (d.error) { setError('cms-body', d.error); return; }
      var h = d.platforms.map(function (p) { return badge(p, 'blue'); }).join(' ');
      if (d.metaGenerator) h += '<br>' + row('Meta Generator', '<code>' + esc(d.metaGenerator) + '</code>');
      setCard('cms-body', h);
    }).catch(function () { setError('cms-body', 'Detection error'); });
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION 2 — Mail Intelligence
     Table MX : Priority | MX Server | Provider | IP / Network (+FCrDNS) | TLSA
     Colonnes ajoutées Phase 4 (2026-04-13) : TLSA (DANE) + badge FCrDNS.
     Colonne SSL retirée Phase 4 : 465/587 ne sont PAS des ports MX (submission
     client, pas delivery), et le port 25 sortant est fermé sur notre serveur.
     Un lien externe vers internet.nl/mail/{domain}/ est ajouté sous la table
     pour l'audit TLS MX complet.
     Handles both hostname MX and direct IP MX (e.g. "10 213.135.240.135").
     ══════════════════════════════════════════════════════════════ */

  async function analyzeMail(domain) {
    var mailBody = document.getElementById('mail-body');
    try {
      var mxRecords = await dohQuery(domain, 'MX');
      if (!mxRecords.length) {
        mailBody.innerHTML = '<span class="domain-error">No MX records found</span>';
        return;
      }

      /* Parse MX : "10 mail.example.com." or "10 213.135.240.135" */
      var mxList = mxRecords.map(function (r) {
        var parts = r.data.split(' ');
        var host = (parts[1] || parts[0] || '').replace(/\.$/, '');
        var prio = parseInt(parts[0], 10);
        /* If first part is not a number, the whole thing is the host */
        if (isNaN(prio)) { host = r.data.replace(/\.$/, ''); prio = 0; }
        return { priority: prio, host: host, isIp: isIP(host) };
      }).sort(function (a, b) { return a.priority - b.priority; });

      var html = '<div class="domain-table-wrap"><table class="domain-table"><thead><tr>' +
        '<th>Priority</th><th>MX Server</th><th>Provider</th>' +
        '<th>IP / Network</th><th>TLSA</th>' +
        '</tr></thead><tbody>';

      for (var i = 0; i < mxList.length; i++) {
        var mx = mxList[i];
        var provider = detectMailProvider(mx.host);
        html += '<tr><td>' + mx.priority + '</td><td><code>' + esc(mx.host) + '</code></td>';
        html += '<td>' + badge(provider, 'blue') + '</td>';
        html += '<td id="mx-ip-' + i + '"><div class="domain-skeleton-sm"></div></td>';
        html += '<td id="mx-tlsa-' + i + '"><div class="domain-skeleton-sm"></div></td></tr>';
      }
      html += '</tbody></table></div>';
      /* Lien vers l'audit externe Internet.nl.
         La TLS réelle sur port 25 (delivery MX) ne peut pas être testée depuis
         notre serveur : port 25 sortant fermé par l'hébergeur, et 465/587 ne
         sont PAS des ports MX mais des ports submission (usage client). Le
         label "SSL" qu'on affichait avant était donc trompeur → retiré.
         La colonne TLSA (DANE) reste informative car elle atteste qu'un MX
         impose TLS quand elle est présente. */
      html += '<p class="domain-mx-audit"><a href="https://internet.nl/mail/' +
        encodeURIComponent(domain) + '/" target="_blank" rel="noopener">' +
        'Full MX TLS audit (internet.nl) →</a>' +
        '<span class="domain-hint"> TLS on port 25 requires an external scanner.</span></p>';
      mailBody.innerHTML = html;

      /* Resolve IP + RIPE + SSL for each MX */
      mxList.forEach(function (mx, idx) {
        var ipPromise;
        if (mx.isIp) {
          /* MX points directly to an IP — use it as-is */
          ipPromise = Promise.resolve(mx.host);
          var cell = document.getElementById('mx-ip-' + idx);
          if (cell) cell.innerHTML = '<code>' + esc(mx.host) + '</code>';
        } else {
          /* MX is a hostname — resolve via DoH */
          ipPromise = dohQuery(mx.host, 'A').then(function (records) {
            var ip = records.length ? records[0].data : null;
            var cell = document.getElementById('mx-ip-' + idx);
            if (cell) cell.innerHTML = ip ? '<code>' + esc(ip) + '</code>' : '—';
            return ip;
          });
        }

        /* RIPE Info + FCrDNS for MX IP */
        ipPromise.then(function (ip) {
          if (!ip) return;
          /* RIPE */
          apiCall('ip-info', { ip: ip }).then(function (d) {
            var cell = document.getElementById('mx-ip-' + idx);
            if (cell && d.org) cell.innerHTML += ' ' + badge(d.org, 'gray');
            if (cell && d.country) cell.innerHTML += ' ' + badge(d.country, 'gray');
          });
          /* FCrDNS : forward→reverse→forward match.
             Vert si les deux sens concordent, orange sinon. */
          fcrDnsCheck(ip).then(function (fc) {
            var cell = document.getElementById('mx-ip-' + idx);
            if (!cell) return;
            if (fc.ok) {
              cell.innerHTML += ' ' + badge('FCrDNS ✓', 'green');
            } else if (fc.ptr) {
              cell.innerHTML += ' ' + badge('FCrDNS ✕', 'orange');
            } else {
              cell.innerHTML += ' ' + badge('No PTR', 'gray');
            }
          });
        });

        /* TLSA / DANE — DoH sur _25._tcp.{mx_host}.
           La plupart des MX n'en ont pas, donc — par défaut. */
        if (!mx.isIp) {
          dohQuery('_25._tcp.' + mx.host, 'TLSA').then(function (records) {
            var cell = document.getElementById('mx-tlsa-' + idx);
            if (!cell) return;
            cell.innerHTML = records.length
              ? badge('Present ✓', 'green')
              : '<span class="domain-dim">—</span>';
          }).catch(function () {
            var cell = document.getElementById('mx-tlsa-' + idx);
            if (cell) cell.innerHTML = '<span class="domain-dim">—</span>';
          });
        } else {
          var tlsaCell = document.getElementById('mx-tlsa-' + idx);
          if (tlsaCell) tlsaCell.innerHTML = '<span class="domain-dim">—</span>';
        }
      });

    } catch (e) {
      mailBody.innerHTML = '<span class="domain-error">MX query error</span>';
    }
  }

  function detectMailProvider(host) {
    var h = host.toLowerCase();
    if (h.indexOf('.mail.protection.outlook.com') !== -1) return 'Microsoft 365';
    if (h.indexOf('.google.com') !== -1 || h.indexOf('.googlemail.com') !== -1) return 'Google Workspace';
    if (h.indexOf('.ovh.net') !== -1 || h.indexOf('.ovh.com') !== -1) return 'OVH';
    if (h.indexOf('.protonmail.ch') !== -1 || h.indexOf('.proton.me') !== -1) return 'ProtonMail';
    if (h.indexOf('.zoho.') !== -1) return 'Zoho Mail';
    if (h.indexOf('.mimecast.') !== -1) return 'Mimecast';
    if (h.indexOf('.pphosted.com') !== -1) return 'Proofpoint';
    if (h.indexOf('.secureserver.net') !== -1) return 'GoDaddy';
    if (h.indexOf('.icloud.com') !== -1) return 'iCloud';
    if (h.indexOf('.ionos.') !== -1 || h.indexOf('.1and1.') !== -1) return 'IONOS';
    if (h.indexOf('pt.lu') !== -1) return 'POST Luxembourg';
    if (h.indexOf('vo.lu') !== -1) return 'Visual Online (LU)';
    if (h.indexOf('internet.lu') !== -1) return 'internet.lu';
    if (isIP(h)) return 'Direct IP';
    return 'Other';
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION 3 — Email Security
     analyzeSecurity() remplit 3 cartes : SPF (récursif), DMARC, DKIM (15 sel).
     Les 2 autres cartes de la section (BIMI, MTA-STS) sont gérées séparément
     par analyzeBimi() et analyzeMtaSts() — voir plus bas.
     Phase 4 (2026-04-13) : SPF désormais résolu récursivement via
     resolveSpfTree() + compteur RFC 7208 + arbre pliable <details>.
     ══════════════════════════════════════════════════════════════ */

  /* Rendu récursif d'un noeud de l'arbre SPF résolu (details/summary natifs). */
  function renderSpfTreeNode(node) {
    if (!node) return '';
    var label = esc(node.domain) + (node.isRedirect ? ' <em>(redirect)</em>' : '');
    var html = '<li><code>' + label + '</code>';
    if (node.errors && node.errors.length) {
      html += ' ' + node.errors.map(function (e) { return badge(e, 'red'); }).join(' ');
    }
    if (node.includes && node.includes.length) {
      html += '<ul class="domain-spf-subtree">';
      node.includes.forEach(function (c) { html += renderSpfTreeNode(c); });
      html += '</ul>';
    }
    html += '</li>';
    return html;
  }

  async function analyzeSecurity(domain) {
    /* SPF — résolution récursive + compteur lookups (RFC 7208, limite 10) */
    try {
      var counter = { count: 0, exceeded: false };
      var tree = await resolveSpfTree(domain, 0, counter, {});
      if (!tree.record) {
        setCard('spf-body', badge('No SPF record', 'red'));
      } else {
        var lookupColor = counter.exceeded ? 'red' : counter.count > 8 ? 'orange' : 'green';
        var h = codeBlock(tree.record);
        h += '<div class="domain-badges">' + parseSpf(tree.record) + '</div>';
        h += row('DNS lookups', badge(counter.count + '/10', lookupColor) +
                 (counter.exceeded ? ' ' + badge('Exceeded RFC limit', 'red') : ''));
        if (tree.includes.length) {
          h += '<details class="domain-spf-tree"><summary>SPF lookup tree (' +
               tree.includes.length + ' direct includes)</summary><ul>';
          tree.includes.forEach(function (c) { h += renderSpfTreeNode(c); });
          h += '</ul></details>';
        }
        setCard('spf-body', h);
      }
    } catch (e) { setError('spf-body', 'SPF query error'); }

    /* DMARC */
    try {
      var dmarcRecords = await dohQuery('_dmarc.' + domain, 'TXT');
      var dmarcRecord = null;
      for (var i = 0; i < dmarcRecords.length; i++) {
        if (dmarcRecords[i].data.indexOf('v=DMARC1') !== -1) { dmarcRecord = dmarcRecords[i].data; break; }
      }
      if (dmarcRecord) {
        var h = codeBlock(dmarcRecord);
        h += '<div class="domain-badges">' + parseDmarc(dmarcRecord) + '</div>';
        setCard('dmarc-body', h);
      } else {
        setCard('dmarc-body', badge('No DMARC record', 'red'));
      }
    } catch (e) { setError('dmarc-body', 'DMARC query error'); }

    /* DKIM — 15 sélecteurs courants (DKIM_SELECTORS défini plus haut) */
    var dkimHtml = '';
    var found = 0;
    var promises = DKIM_SELECTORS.map(function (sel) {
      return dohQuery(sel + '._domainkey.' + domain, 'TXT').then(function (records) {
        if (records.length) {
          found++;
          dkimHtml += '<div class="domain-dkim-item">' + badge(sel, 'green') + codeBlock(records[0].data) + '</div>';
        }
      }).catch(function () {});
    });
    await Promise.all(promises);
    setCard('dkim-body', found > 0 ? dkimHtml
      : badge('No common DKIM selectors found', 'yellow') +
        '<p class="domain-hint">DKIM selectors are infinite — this only checks ' + DKIM_SELECTORS.length + ' common ones.</p>');
  }

  function parseSpf(record) {
    var parts = record.split(/\s+/);
    var html = '';
    for (var i = 1; i < parts.length; i++) {
      var p = parts[i];
      if (p === '+all') html += badge('+all (PASS all)', 'red');
      else if (p === '~all') html += badge('~all (SoftFail)', 'yellow');
      else if (p === '-all') html += badge('-all (FAIL)', 'green');
      else if (p === '?all') html += badge('?all (Neutral)', 'gray');
      else if (p.indexOf('include:') === 0) html += badge(p, 'blue');
      else if (p.indexOf('ip4:') === 0 || p.indexOf('ip6:') === 0) html += badge(p, 'gray');
      else if (p === 'mx' || p === 'a') html += badge(p, 'gray');
      else if (p.indexOf('redirect=') === 0) html += badge(p, 'blue');
    }
    return html;
  }

  function parseDmarc(record) {
    var tags = {};
    record.replace(/^v=DMARC1;?\s*/, '').split(/;\s*/).forEach(function (part) {
      var eq = part.indexOf('=');
      if (eq !== -1) tags[part.substring(0, eq).trim()] = part.substring(eq + 1).trim();
    });
    var html = '';
    if (tags.p === 'reject') html += badge('p=reject', 'green');
    else if (tags.p === 'quarantine') html += badge('p=quarantine', 'yellow');
    else if (tags.p === 'none') html += badge('p=none', 'red');
    if (tags.sp) html += badge('sp=' + tags.sp, 'gray');
    if (tags.rua) html += badge('rua=' + tags.rua, 'blue');
    if (tags.ruf) html += badge('ruf=' + tags.ruf, 'blue');
    if (tags.pct) html += badge('pct=' + tags.pct, 'gray');
    if (tags.adkim) html += badge('adkim=' + tags.adkim, 'gray');
    if (tags.aspf) html += badge('aspf=' + tags.aspf, 'gray');
    return html;
  }

  /* ══════════════════════════════════════════════════════════════
     CARTE "DNS Security" — DNSSEC + CAA + SOA (ajouté 2026-04-13)
     ══════════════════════════════════════════════════════════════ */
  async function analyzeDnsSecurity(domain) {
    var h = '';

    /* DNSSEC via flag AD de la réponse DoH */
    try {
      var full = await dohQueryFull(domain, 'A');
      h += row('DNSSEC', full.ad
        ? badge('Validated (AD flag)', 'green')
        : badge('Not validated', 'orange'));
    } catch (e) {
      h += row('DNSSEC', badge('Query error', 'red'));
    }

    /* CAA records (type 257) — restreint quelles CA peuvent émettre des certs */
    try {
      var caa = await dohQuery(domain, 'CAA');
      if (caa.length) {
        h += row('CAA', caa.map(function (r) {
          return '<code>' + esc(r.data) + '</code>';
        }).join('<br>'));
      } else {
        h += row('CAA', badge('None', 'gray') +
          ' <span class="domain-dim">(any CA can issue)</span>');
      }
    } catch (e) {
      h += row('CAA', badge('Query error', 'red'));
    }

    /* SOA (Start of Authority) — serveur primaire + email admin */
    try {
      var soa = await dohQuery(domain, 'SOA');
      if (soa.length) {
        var soaParts = soa[0].data.split(/\s+/);
        h += row('SOA primary', '<code>' + esc(soaParts[0] || '?') + '</code>');
        if (soaParts[1]) {
          /* L'email admin est encodé "user.example.com" → "user@example.com" */
          var email = soaParts[1].replace(/\.$/, '').replace(/\./, '@');
          h += row('SOA admin', '<code>' + esc(email) + '</code>');
        }
      } else {
        h += row('SOA', badge('None', 'gray'));
      }
    } catch (e) {
      h += row('SOA', badge('Query error', 'red'));
    }

    setCard('dnssec-body', h || '—');
  }

  /* ══════════════════════════════════════════════════════════════
     CARTE "BIMI" — Brand Indicators for Message Identification
     TXT default._bimi.{domain} : v=BIMI1; l=<logo_url>; a=<VMC_url>
     ══════════════════════════════════════════════════════════════ */
  async function analyzeBimi(domain) {
    try {
      var records = await dohQuery('default._bimi.' + domain, 'TXT');
      var bimi = null;
      for (var i = 0; i < records.length; i++) {
        if (records[i].data.indexOf('v=BIMI1') === 0) { bimi = records[i].data; break; }
      }
      if (!bimi) {
        setCard('bimi-body', badge('No BIMI record', 'gray') +
          '<p class="domain-hint">BIMI displays your logo in supporting email clients (Gmail, Yahoo, Apple Mail).</p>');
        return;
      }
      var h = codeBlock(bimi);
      var tags = {};
      bimi.replace(/^v=BIMI1;?\s*/, '').split(/;\s*/).forEach(function (part) {
        var eq = part.indexOf('=');
        if (eq !== -1) tags[part.substring(0, eq).trim()] = part.substring(eq + 1).trim();
      });
      if (tags.l) h += row('Logo (l=)', '<code>' + esc(tags.l) + '</code>');
      if (tags.a) h += row('VMC (a=)', '<code>' + esc(tags.a) + '</code>');
      setCard('bimi-body', h);
    } catch (e) {
      setError('bimi-body', 'BIMI query error');
    }
  }

  /* ══════════════════════════════════════════════════════════════
     CARTE "MTA-STS" — RFC 8461
     1) DoH TXT _mta-sts.{domain} → preuve de publication
     2) Backend fetch https://mta-sts.{domain}/.well-known/mta-sts.txt
        → parse mode / max_age / mx
     ══════════════════════════════════════════════════════════════ */
  async function analyzeMtaSts(domain) {
    var h = '';

    /* Étape 1 : TXT DoH */
    try {
      var records = await dohQuery('_mta-sts.' + domain, 'TXT');
      var txtRec = null;
      for (var i = 0; i < records.length; i++) {
        if (records[i].data.indexOf('v=STSv1') === 0) { txtRec = records[i].data; break; }
      }
      if (!txtRec) {
        setCard('mtasts-body', badge('No MTA-STS record', 'gray') +
          '<p class="domain-hint">MTA-STS enforces TLS for inbound SMTP (RFC 8461).</p>');
        return;
      }
      h += row('DNS record', '<code>' + esc(txtRec) + '</code>');
    } catch (e) {
      setError('mtasts-body', 'MTA-STS DNS error');
      return;
    }

    /* Étape 2 : backend fetch de la policy */
    try {
      var policy = await apiCall('mta-sts', { domain: domain });
      if (!policy.found) {
        h += row('Policy file', badge('Not fetched', 'orange') +
          ' <span class="domain-dim">' + esc(policy.reason || '') + '</span>');
        setCard('mtasts-body', h);
        return;
      }
      var modeColor = policy.policy.mode === 'enforce' ? 'green'
                    : policy.policy.mode === 'testing' ? 'yellow' : 'red';
      h += row('Mode', badge(policy.policy.mode || '?', modeColor));
      if (policy.policy.maxAge) {
        var days = Math.round(policy.policy.maxAge / 86400);
        h += row('Max age', days + ' days');
      }
      if (policy.policy.mx && policy.policy.mx.length) {
        h += row('Allowed MX', policy.policy.mx.map(function (m) {
          return '<code>' + esc(m) + '</code>';
        }).join('<br>'));
      }
      if (!policy.tlsValid) {
        h += row('TLS cert', badge('Invalid', 'orange'));
      }
      setCard('mtasts-body', h);
    } catch (e) {
      setError('mtasts-body', 'MTA-STS fetch error');
    }
  }

  /* ══════════════════════════════════════════════════════════════
     SECTION 4 — Email Client Config (ajouté 2026-04-13)
     Autodiscover (Exchange/M365), Autoconfig (Thunderbird), SRV records.
     ══════════════════════════════════════════════════════════════ */
  async function analyzeClientConfig(domain) {
    /* Autodiscover — backend check de présence uniquement (GET sans auth).
       Un endpoint réel nécessite un POST XML, mais la présence suffit pour
       confirmer la config côté DNS+serveur. */
    apiCall('autodiscover', { domain: domain }).then(function (d) {
      if (d.error) { setError('autodiscover-body', d.error); return; }
      if (!d.found) {
        setCard('autodiscover-body', badge('Not configured', 'gray') +
          '<p class="domain-hint">No CNAME and no HTTP endpoint responding at <code>autodiscover.' +
          esc(domain) + '</code>.</p>');
        return;
      }
      var h = badge('Configured ✓', 'green');
      /* Détection via CNAME DNS (prioritaire — M365 refuse les GET HTTP) */
      if (d.detectedProvider) {
        h += row('Provider', badge(d.detectedProvider, 'blue'));
      }
      if (d.cnameTarget) {
        h += row('CNAME', '<code>autodiscover.' + esc(domain) + ' → ' +
                 esc(d.cnameTarget) + '</code>');
      }
      /* Endpoints HTTP répondants (Exchange on-prem typiquement) */
      d.endpoints.forEach(function (ep) {
        if (ep.present) {
          h += row('HTTP endpoint', '<code>' + esc(ep.url) + '</code> — HTTP ' + ep.status +
            (ep.tlsValid ? ' ' + badge('TLS ✓', 'green') : ''));
        }
      });
      setCard('autodiscover-body', h);
    }).catch(function () { setError('autodiscover-body', 'Autodiscover check failed'); });

    /* Autoconfig (Thunderbird) — XML parsé côté backend, on affiche
       les serveurs incoming/outgoing extraits. */
    apiCall('autoconfig', { domain: domain }).then(function (d) {
      if (d.error) { setError('autoconfig-body', d.error); return; }
      if (!d.found) {
        setCard('autoconfig-body', badge('Not configured', 'gray') +
          '<p class="domain-hint">No <code>config-v1.1.xml</code> found at autoconfig.' +
          esc(domain) + '.</p>');
        return;
      }
      var h = '';
      /* Signaler si la config vient de la community DB Mozilla vs auto-hébergée.
         En consulting c'est une info importante : "le domaine publie sa config"
         vs "la config est devinée par Thunderbird via la DB community". */
      if (d.sourceType === 'mozilla-ispdb') {
        h += row('Source', badge('Mozilla ISPDB (community)', 'gray'));
      } else if (d.sourceType === 'self-hosted') {
        h += row('Source', badge('Self-hosted ✓', 'green'));
      } else if (d.sourceType === 'well-known') {
        h += row('Source', badge('/.well-known/ ✓', 'green'));
      }
      if (d.providerId) h += row('Provider ID', '<code>' + esc(d.providerId) + '</code>');
      function renderServer(s) {
        var port = s.port ? ':' + s.port : '';
        var ssl = s.socketType ? ' ' + badge(s.socketType, s.socketType === 'SSL' || s.socketType === 'STARTTLS' ? 'green' : 'orange') : '';
        return '<code>' + esc(s.type.toUpperCase()) + '</code> ' +
               '<code>' + esc((s.hostname || '?') + port) + '</code>' + ssl;
      }
      if (d.incoming && d.incoming.length) {
        h += row('Incoming', d.incoming.map(renderServer).join('<br>'));
      }
      if (d.outgoing && d.outgoing.length) {
        h += row('Outgoing', d.outgoing.map(renderServer).join('<br>'));
      }
      setCard('autoconfig-body', h || badge('Empty config', 'orange'));
    }).catch(function () { setError('autoconfig-body', 'Autoconfig check failed'); });

    /* SRV records — DoH client-side.
       On teste 5 services email standards. */
    var srvQueries = [
      { label: 'submission (SMTP 587)', name: '_submission._tcp.' + domain },
      { label: 'imaps', name: '_imaps._tcp.' + domain },
      { label: 'imap', name: '_imap._tcp.' + domain },
      { label: 'pop3s', name: '_pop3s._tcp.' + domain },
      { label: 'pop3', name: '_pop3._tcp.' + domain }
    ];
    var results = await Promise.all(srvQueries.map(function (q) {
      return dohQuery(q.name, 'SRV').then(function (records) {
        return { label: q.label, records: records };
      }).catch(function () { return { label: q.label, records: [] }; });
    }));
    var srvHtml = '';
    var anyFound = false;
    results.forEach(function (r) {
      if (r.records.length) {
        anyFound = true;
        srvHtml += row(r.label, r.records.map(function (rec) {
          /* SRV format: "prio weight port target" */
          var parts = rec.data.split(/\s+/);
          var target = (parts[3] || '').replace(/\.$/, '');
          return '<code>' + esc(target + ':' + (parts[2] || '?')) + '</code>';
        }).join('<br>'));
      }
    });
    setCard('srv-body', anyFound ? srvHtml : badge('No email SRV records', 'gray') +
      '<p class="domain-hint">SRV records for email are optional (RFC 6186) but help clients auto-configure.</p>');
  }

  /* ══════════════════════════════════════════════════════════════
     MAIN
     ══════════════════════════════════════════════════════════════ */

  /* ── Scan progress bar ──────────────────────────────────── */
  var inputWrap = document.querySelector('.domain-input-wrap');
  var pendingCount = 0;

  function scanStart() {
    pendingCount++;
    if (inputWrap) inputWrap.classList.add('is-scanning');
  }
  function scanEnd() {
    pendingCount = Math.max(0, pendingCount - 1);
    if (pendingCount === 0 && inputWrap) inputWrap.classList.remove('is-scanning');
  }

  /* Wrap API calls to track scan state */
  var _origApiCall = apiCall;
  apiCall = function (endpoint, params) {
    scanStart();
    return _origApiCall(endpoint, params).finally(scanEnd);
  };

  function startAnalysis() {
    var domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!domain || domain.indexOf('.') === -1) return;

    /* Vérifier le quota client */
    if (!checkQuota()) {
      updateQuotaDisplay();
      return;
    }
    recordAnalysis();
    updateQuotaDisplay();
    input.value = domain;

    /* Show results with animation */
    results.classList.remove('domain-results-hidden');
    results.style.display = 'flex';
    results.style.flexDirection = 'column';
    results.style.gap = '2.5rem';
    /* Remove is-visible first if re-scanning, trigger reflow, then animate */
    results.classList.remove('is-visible');
    void results.offsetHeight;
    results.classList.add('is-visible');

    document.querySelectorAll('.domain-card-body, #mail-body').forEach(function (el) {
      el.innerHTML = '<div class="domain-skeleton"></div>';
    });

    /* Track DNS queries as scan items too */
    scanStart(); /* website DNS */
    scanStart(); /* mail MX */
    scanStart(); /* security TXT */
    scanStart(); /* DNS security */
    scanStart(); /* BIMI */
    scanStart(); /* MTA-STS */
    scanStart(); /* client config */

    analyzeWebsite(domain).finally(scanEnd);
    analyzeMail(domain).finally(scanEnd);
    analyzeSecurity(domain).finally(scanEnd);
    analyzeDnsSecurity(domain).finally(scanEnd);
    analyzeBimi(domain).finally(scanEnd);
    analyzeMtaSts(domain).finally(scanEnd);
    analyzeClientConfig(domain).finally(scanEnd);
  }

  analyzeBtn.addEventListener('click', startAnalysis);
  input.addEventListener('keydown', function (e) { if (e.key === 'Enter') startAnalysis(); });

})();
