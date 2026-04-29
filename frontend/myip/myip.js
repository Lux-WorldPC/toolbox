/**
 * What's My IP — affiche l'IP publique du visiteur + infos réseau.
 * @lwpc/toolbox (MIT) — frontend. Backend attend : GET /api/myip?ip=X
 *
 * Flux (2 requêtes IP en parallèle + 1 enrichissement) :
 *   1a. Cloudflare trace (cdn-cgi/trace) → IP principale (v4 ou v6 selon la connexion)
 *   1b. ipify.org (api.ipify.org) → toujours IPv4 (fallback si Cloudflare retourne v6)
 *   2. Si les deux diffèrent → IPv4 (ipify) + IPv6 (Cloudflare) affichés
 *   3. GET /api/myip?ip=X → enrichissement via IPv4 (meilleures données RIPE que IPv6)
 *      → Node.js dns.reverse() + RIPE Stat (org, ASN, CIDR, pays) + whitelisted flag
 *   4. Affichage dans 5 cartes (réutilise les classes CSS Domain Checkup)
 *
 * Pourquoi deux sources : HAProxy voit l'IP NATée interne (172.16.x.x), pas la vraie IP publique.
 * Cloudflare/ipify sont appelés directement par le navigateur → voient la vraie IP.
 * Sur mobile 4G : Cloudflare retourne souvent IPv6 (données RIPE pauvres) → ipify donne l'IPv4.
 *
 * Crédits : Cloudflare (IP detection) + ipify (IPv4 fallback) + RIPE Stat (network data).
 *
 * Whitelist : détectée automatiquement par baseof.html (GET /api/check-whitelist via Cloudflare trace).
 *   myip.js stocke aussi le flag 'lwpc_whitelisted' quand le backend retourne whitelisted:true
 *   (redondant avec baseof.html, mais utile si la page myip est la première visitée).
 *
 * Quota client : 10 requêtes / 30 min (sessionStorage 'myip_lookups').
 *   Bypass si window.lwpcWhitelisted (posé par baseof.html ou myip.js).
 *
 * Bouton "Envoyer au support" : stocke les infos IP dans sessionStorage('ticket_prefill')
 *   et redirige vers /{lang}/contact/ticket/ (la page ticket pré-remplit sujet + description).
 *
 * ⚠ Après modification, supprimer resources/ et rebuild (Hugo cache les assets).
 */
(function () {
  'use strict';

  /* API endpoint base — override via `window.LWPC_API_BASE = 'https://api.example.com'`
     before loading this script. Default: same-origin. */
  var API_BASE = (typeof window !== 'undefined' && window.LWPC_API_BASE) || '';

  var quotaMsg = document.getElementById('myip-quota-msg');
  var refreshBtn = document.getElementById('myip-refresh');
  if (!document.getElementById('myip-results')) return;

  /* ── Helpers (réutilise le design Domain Checkup) ────────── */

  function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  function badge(text, color) {
    var colors = { green: '#27ae60', yellow: '#f1c40f', red: '#e74c3c', blue: '#3d5394', gray: '#8b949e' };
    var bg = colors[color] || colors.gray;
    return '<span class="domain-badge" style="background:' + bg + '22;color:' + bg + ';border:1px solid ' + bg + '55">' + esc(text) + '</span>';
  }

  function setCard(id, html) { var el = document.getElementById(id); if (el) el.innerHTML = html; }

  /* ── Quota — 10 / 30 min ─────────────────────────────────── */

  var QM = 10, QW = 30 * 60 * 1000, QK = 'myip_lookups';
  function qGet() { try { var d = JSON.parse(sessionStorage.getItem(QK)); if (d && Array.isArray(d.ts)) return d; } catch (e) {} return { ts: [] }; }
  function qSave(d) { sessionStorage.setItem(QK, JSON.stringify(d)); }
  function qPurge() { var d = qGet(), n = Date.now(); d.ts = d.ts.filter(function (t) { return t > n - QW; }); qSave(d); return d; }
  function qCheck() { return window.lwpcWhitelisted || qPurge().ts.length < QM; }
  function qRecord() { var d = qPurge(); d.ts.push(Date.now()); qSave(d); }
  function qRemain() { return QM - qPurge().ts.length; }
  function qLbl(k, f) { return (quotaMsg && quotaMsg.dataset['lbl' + k]) || f; }
  function qUpdate() {
    if (window.lwpcWhitelisted || !quotaMsg) return;
    var r = qRemain(), b = qLbl('Limited', 'Voluntarily limited to') + ' ' + QM + ' ' + qLbl('Unit', 'analyses') + ' / 30 min';
    if (r <= 0) {
      quotaMsg.innerHTML = '⚠ ' + b + ' — <strong>0</strong> ' + qLbl('Remaining', 'remaining') + '. ' + qLbl('Blocked', 'Please try again later.');
      quotaMsg.classList.add('is-blocked');
      if (refreshBtn) refreshBtn.disabled = true;
    } else {
      quotaMsg.innerHTML = b + ' — <strong>' + r + '</strong> ' + qLbl('Remaining', 'remaining');
      quotaMsg.classList.remove('is-blocked');
      if (refreshBtn) refreshBtn.disabled = false;
    }
    quotaMsg.hidden = false;
  }

  /* ── Fetch IP ────────────────────────────────────────────── */

  var isWhitelisted = sessionStorage.getItem('lwpc_whitelisted') === '1';

  function fetchMyIp() {
    /* Si pas encore whitelisted ET quota atteint → bloquer (sauf premier appel) */
    if (!isWhitelisted && !firstCall && !qCheck()) { qUpdate(); return; }
    if (!isWhitelisted && !firstCall) { qRecord(); qUpdate(); }
    firstCall = false;

    /* Reset skeletons */
    ['myip-ip', 'myip-rdns', 'myip-org', 'myip-asn', 'myip-country'].forEach(function (id) {
      setCard(id, '<div class="domain-skeleton"></div>');
    });

    /* Étape 1 : obtenir les IPs publiques en parallèle :
       - Cloudflare trace → IP principale (v4 ou v6 selon la connexion)
       - api.ipify.org → toujours IPv4 (fallback si Cloudflare retourne v6)
       Étape 2 : enrichir via /api/myip?ip=X (RIPE + reverse DNS) en utilisant l'IPv4 (meilleures données RIPE). */
    var cfPromise = fetch('https://cloudflare.com/cdn-cgi/trace')
      .then(function (r) { return r.text(); })
      .then(function (t) { var m = t.match(/ip=([^\n]+)/); return m ? m[1].trim() : null; })
      .catch(function () { return null; });

    var v4Promise = fetch('https://api.ipify.org?format=text')
      .then(function (r) { return r.text(); })
      .then(function (t) { return t.trim(); })
      .catch(function () { return null; });

    Promise.all([cfPromise, v4Promise]).then(function (results) {
      var cfIp = results[0];
      var v4Ip = results[1];
      if (!cfIp && !v4Ip) throw new Error('No IP detected');

      /* Déterminer IPv4 et IPv6 */
      var isV6 = cfIp && cfIp.indexOf(':') !== -1;
      var ipv4 = isV6 ? v4Ip : cfIp;
      var ipv6 = isV6 ? cfIp : null;
      /* Si Cloudflare a retourné v4 et ipify aussi → pas de v6 */
      if (!isV6 && v4Ip && cfIp && v4Ip !== cfIp) ipv4 = cfIp; /* préférer Cloudflare */

      /* Enrichir via l'IPv4 (meilleures données RIPE que IPv6) */
      var enrichIp = ipv4 || cfIp;
      return fetch(API_BASE + '/api/myip?ip=' + encodeURIComponent(enrichIp)).then(function (r) { return r.json(); })
        .then(function (d) {
          d.ipv4 = ipv4;
          d.ipv6 = ipv6;
          return d;
        });
    })
      .then(function (d) {
        /* IP — affiche IPv4 + IPv6 (si disponible), copier au clic */
        var ipHtml = '<div style="font-family:\'JetBrains Mono\',monospace;font-size:1.5rem;font-weight:700;color:var(--text);letter-spacing:0.5px;cursor:pointer;" title="Click to copy" onclick="navigator.clipboard.writeText(\'' + esc(d.ipv4 || d.ip) + '\')">' +
          esc(d.ipv4 || d.ip) + '</div>';
        if (d.ipv6) {
          ipHtml += '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.82rem;color:var(--text-2);margin-top:0.4rem;cursor:pointer;word-break:break-all;" title="Click to copy IPv6" onclick="navigator.clipboard.writeText(\'' + esc(d.ipv6) + '\')">' +
            'IPv6: ' + esc(d.ipv6) + '</div>';
        }
        setCard('myip-ip', ipHtml);

        /* Reverse DNS */
        setCard('myip-rdns', d.reverse
          ? '<code style="font-size:0.85rem;">' + esc(d.reverse) + '</code>'
          : '<span class="domain-error">No reverse DNS</span>'
        );

        /* Organization */
        var orgHtml = '';
        if (d.org) orgHtml += '<strong>' + esc(d.org) + '</strong>';
        if (d.netname) orgHtml += (orgHtml ? '<br>' : '') + '<span style="color:var(--text-3);font-size:0.78rem;">' + esc(d.netname) + '</span>';
        setCard('myip-org', orgHtml || '<span class="domain-error">Unknown</span>');

        /* ASN / CIDR */
        var asnHtml = '';
        if (d.asn) asnHtml += badge('AS' + d.asn, 'blue') + ' ';
        if (d.prefix) asnHtml += '<code>' + esc(d.prefix) + '</code>';
        setCard('myip-asn', asnHtml || '—');

        /* Country */
        setCard('myip-country', d.country
          ? badge(d.country, 'gray')
          : '—'
        );

        /* Si IP whitelist → masquer le quota et mémoriser (pas de limite) */
        if (d.whitelisted) {
          isWhitelisted = true;
          sessionStorage.setItem('lwpc_whitelisted', '1');
          if (quotaMsg) quotaMsg.hidden = true;
          if (refreshBtn) refreshBtn.disabled = false;
        }

        /* Stocker les données pour le bouton "Envoyer au support" */
        lastIpData = d;
      })
      .catch(function () {
        setCard('myip-ip', '<span class="domain-error">Unable to detect IP</span>');
      });
  }

  /* ── Envoyer au support — redirige vers /contact/ticket/ avec les infos IP (2026-04-10).
     Stocke le sujet + description dans sessionStorage, la page ticket les pré-remplit. */
  var lastIpData = null;
  var sendBtn = document.getElementById('myip-send-support');
  if (sendBtn) {
    sendBtn.addEventListener('click', function () {
      if (!lastIpData) return;
      var d = lastIpData;
      var mainIp = d.ipv4 || d.ip;
      var subject = 'My IP: ' + mainIp;
      var desc = 'IPv4: ' + (d.ipv4 || d.ip) +
        (d.ipv6 ? '\nIPv6: ' + d.ipv6 : '') +
        '\nReverse DNS: ' + (d.reverse || '—') +
        '\nOrganization: ' + (d.org || '—') +
        '\nNetname: ' + (d.netname || '—') +
        '\nASN: ' + (d.asn ? 'AS' + d.asn : '—') +
        '\nCIDR: ' + (d.prefix || '—') +
        '\nCountry: ' + (d.country || '—');
      sessionStorage.setItem('ticket_prefill', JSON.stringify({ subject: subject, description: desc }));
      var lang = document.documentElement.lang || 'lb';
      location.href = '/' + lang + '/contact/ticket/';
    });
  }

  /* ── Init ────────────────────────────────────────────────── */

  var firstCall = true;
  if (!isWhitelisted) qUpdate();
  fetchMyIp();

  if (refreshBtn) {
    refreshBtn.addEventListener('click', fetchMyIp);
  }

})();
