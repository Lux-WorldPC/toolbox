/**
 * What's My IP — diagnostic réseau IT-grade.
 * @lwpc/toolbox (MIT) — frontend. Ajouté 2026-04-29.
 *
 * Activé après que myip.js a affiché les 5 cards de base et émis l'event
 * 'lwpc-myip-ready' sur document. Lance en parallèle :
 *
 *   1. WebRTC/STUN (probe Cloudflare + Google) — ICE candidates host + srflx
 *      → détecte 100.64.0.0/10 (CGNAT confirmé RFC 6598), symmetric NAT
 *        (port srflx variable entre 2 STUN servers = CGNAT very probable),
 *        IP locale (ou *.local si mDNS Chrome).
 *   2. IPv6 reachability — utilise simplement le résultat Cloudflare trace
 *      capturé par myip.js (event detail.ipv6) : si présent, IPv6 OK.
 *   3. Connection quality — 5 fetches /api/myip/ping (médiane RTT),
 *      lecture nextHopProtocol via PerformanceResourceTiming (HTTP version),
 *      TLS via Cloudflare cdn-cgi/trace champ tls=.
 *   4. Verdict scoring — combine tous les signaux en un état 🟢/🟡/🔴/⚪
 *      affiché dans la card #myip-verdict.
 *
 * Aucune dépendance, aucun framework. Toutes les sondes sont initiées côté
 * navigateur (sortantes). Aucun scan TCP entrant — les EDR/AV/SIEM ne
 * voient rien qui ressemble à un port scan.
 *
 * Toggle "Détails techniques" (#myip-verdict-toggle) plie/déplie #myip-details.
 *
 * Backend attend GET /api/myip/ping (200 "ok") pour la mesure RTT.
 */
(function () {
  'use strict';

  var grid = document.getElementById('myip-diag-grid');
  var verdict = document.getElementById('myip-verdict');
  var details = document.getElementById('myip-details');
  var toggle = document.getElementById('myip-verdict-toggle');
  if (!grid || !verdict || !details || !toggle) return;

  var API_BASE = (typeof window !== 'undefined' && window.LWPC_API_BASE) || '';
  var lbl = function (k, fb) { return grid.dataset[k] || fb || ''; };
  var vlbl = function (k, fb) { return verdict.dataset[k] || fb || ''; };

  function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
  function setCard(id, html) { var el = document.getElementById(id); if (el) el.innerHTML = html; }

  /* ── Toggle "Détails techniques" ───────────────────────────── */
  toggle.addEventListener('click', function () {
    var open = toggle.getAttribute('aria-expanded') === 'true';
    var next = !open;
    toggle.setAttribute('aria-expanded', String(next));
    details.hidden = !next;
    var span = toggle.querySelector('span:first-child');
    if (span) span.textContent = next
      ? vlbl('lblToggleHide', 'Hide details')
      : vlbl('lblToggleShow', 'Show details');
    var chev = toggle.querySelector('.myip-verdict-toggle-chevron');
    if (chev) chev.textContent = next ? '▾' : '▸';
  });

  /* ── Helpers ───────────────────────────────────────────────── */

  function isCgnat(ip) {
    /* RFC 6598 — 100.64.0.0/10 (CGNAT shared address space) */
    if (!ip || ip.indexOf(':') !== -1) return false;
    var p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some(function (n) { return isNaN(n); })) return false;
    return p[0] === 100 && p[1] >= 64 && p[1] <= 127;
  }

  function isPrivate(ip) {
    if (!ip) return false;
    if (ip.indexOf(':') !== -1) {
      var l = ip.toLowerCase();
      return l === '::1' || l.indexOf('fe80') === 0 || l.indexOf('fc') === 0 || l.indexOf('fd') === 0;
    }
    var p = ip.split('.').map(Number);
    if (p.length !== 4) return false;
    if (p[0] === 10) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 169 && p[1] === 254) return true; /* link-local */
    if (p[0] === 127) return true; /* loopback */
    return false;
  }

  /* ── 1. STUN probe (WebRTC) ─────────────────────────────────
     Récupère les ICE candidates émises pour un STUN donné.
     Renvoie { host: [...], srflx: [...], stun: url, error: string|null }.
     Timeout 4s — STUN est ~ 50-200ms en pratique mais on laisse de la marge. */
  function stunProbe(stunUrl) {
    return new Promise(function (resolve) {
      if (typeof RTCPeerConnection === 'undefined') {
        resolve({ host: [], srflx: [], stun: stunUrl, error: 'no-webrtc' });
        return;
      }
      var pc, done = false, host = [], srflx = [];
      function finish(err) {
        if (done) return; done = true;
        try { pc && pc.close(); } catch (e) {}
        resolve({ host: host, srflx: srflx, stun: stunUrl, error: err || null });
      }
      try {
        pc = new RTCPeerConnection({ iceServers: [{ urls: stunUrl }] });
      } catch (e) { finish('rtc-init-failed'); return; }
      pc.createDataChannel('lwpc-probe');
      pc.onicecandidate = function (e) {
        if (!e.candidate) { finish(null); return; } /* end-of-candidates */
        var c = e.candidate;
        /* Parser le candidate string pour extraire type, ip, port :
           "candidate:842163049 1 udp 1677729535 1.2.3.4 54321 typ srflx raddr 0.0.0.0 rport 0 ..."
           On préfère c.address/c.port quand dispos (Chrome récent). */
        var addr = c.address || null, port = c.port || null, type = null;
        var m = c.candidate.match(/typ\s+(\S+)/);
        if (m) type = m[1];
        if (!addr) { var ma = c.candidate.match(/typ\s+\S+\s+raddr|^candidate:\S+\s+\d+\s+\S+\s+\d+\s+(\S+)\s+(\d+)/); if (ma && ma[1]) { addr = ma[1]; port = parseInt(ma[2], 10); } }
        if (!addr) {
          /* Fallback parser large */
          var parts = c.candidate.split(/\s+/);
          if (parts.length >= 6) { addr = parts[4]; port = parseInt(parts[5], 10); }
        }
        if (!type || !addr) return;
        if (type === 'host') host.push({ address: addr, port: port });
        else if (type === 'srflx') srflx.push({ address: addr, port: port });
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); })
        .catch(function () { finish('offer-failed'); });
      setTimeout(function () { finish('timeout'); }, 4000);
    });
  }

  /* ── 2. RTT (5 fetches /api/myip/ping, médiane) + HTTP (nextHopProtocol)
        + TLS (Cloudflare trace champ tls=). Le TLS ne peut pas venir de
        $ssl_protocol nginx car HAProxy fait le handshake TLS en amont
        (nginx est HTTP-only en interne). On lit donc le TLS du visiteur
        vers Cloudflare, qui reflète bien la capacité TLS du client. */
  function measureRtt() {
    var samples = [];
    var url = API_BASE + '/api/myip/ping';
    function one() {
      var t0 = (performance && performance.now) ? performance.now() : Date.now();
      return fetch(url, { cache: 'no-store' })
        .then(function (r) {
          var t1 = (performance && performance.now) ? performance.now() : Date.now();
          samples.push(t1 - t0);
          return r;
        });
    }
    var tlsPromise = fetch('https://cloudflare.com/cdn-cgi/trace', { cache: 'no-store' })
      .then(function (r) { return r.text(); })
      .then(function (t) {
        var m = t.match(/tls=([^\n]+)/);
        return m ? m[1].trim() : '';
      })
      .catch(function () { return ''; });
    return Promise.all([one(), one(), one(), one(), one(), tlsPromise]).then(function (results) {
      var tls = results[5];
      samples.sort(function (a, b) { return a - b; });
      var med = samples[Math.floor(samples.length / 2)];
      var http = '';
      try {
        var entries = performance.getEntriesByType('resource');
        for (var i = entries.length - 1; i >= 0; i--) {
          if (entries[i].name && entries[i].name.indexOf('/api/myip/ping') !== -1) {
            http = entries[i].nextHopProtocol || '';
            break;
          }
        }
      } catch (e) {}
      return { rtt: Math.round(med), http: http, tls: tls };
    }).catch(function () { return null; });
  }

  /* ── Render helpers ────────────────────────────────────────── */

  function renderLocal(allCandidates) {
    /* allCandidates = liste fusionnée des host candidates des 2 STUN probes (dédupée). */
    if (!allCandidates.length) {
      return setCard('myip-local', '<span style="color:var(--text-3)">' +
        esc(lbl('lblNoWebrtc', 'WebRTC unavailable')) + '</span>');
    }
    var html = '';
    allCandidates.forEach(function (c) {
      var addr = c.address;
      var isMdns = /\.local$/i.test(addr);
      var note = '';
      if (isMdns) note = ' <span style="color:var(--text-3);font-size:0.78rem;">(' + esc(lbl('lblMdns', 'mDNS obfuscated')) + ')</span>';
      else if (isPrivate(addr)) note = ' <span class="domain-badge" style="background:#27ae6022;color:#27ae60;border:1px solid #27ae6055;">RFC1918</span>';
      else if (isCgnat(addr)) note = ' <span class="domain-badge" style="background:#e74c3c22;color:#e74c3c;border:1px solid #e74c3c55;">CGNAT 100.64/10</span>';
      else note = ' <span class="domain-badge" style="background:#f1c40f22;color:#f1c40f;border:1px solid #f1c40f55;">PUBLIC</span>';
      html += '<div style="font-family:var(--mono);font-size:0.85rem;margin:0.2rem 0;">' +
        esc(addr) + (c.port ? ':' + c.port : '') + note + '</div>';
    });
    setCard('myip-local', html);
  }

  function renderNat(natType, srflxByStun) {
    var color = '#8b949e', label = natType || 'unknown';
    if (natType === 'symmetric') {
      color = '#e74c3c';
      label = lbl('lblSymmetric', 'Symmetric NAT (CGNAT very likely)');
    } else if (natType === 'cone') {
      color = '#27ae60';
      label = lbl('lblCone', 'Cone NAT (consistent mapping)');
    } else if (natType === 'open') {
      color = '#27ae60';
      label = lbl('lblOpen', 'Open / endpoint-independent');
    } else if (natType === 'no-webrtc') {
      label = lbl('lblNoWebrtc', 'WebRTC unavailable');
    }
    var html = '<div><span class="domain-badge" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '55;font-size:0.85rem;">' + esc(label) + '</span></div>';
    setCard('myip-nat', html);
  }

  function renderStun(observations) {
    /* observations = [{ stun, srflx: [{address, port}], host: [...], error }] */
    if (!observations.length) {
      return setCard('myip-stun', '<span style="color:var(--text-3)">' +
        esc(lbl('lblNoWebrtc', 'WebRTC unavailable')) + '</span>');
    }
    var html = '<div style="display:grid;grid-template-columns:1fr;gap:0.4rem;font-family:var(--mono);font-size:0.85rem;">';
    observations.forEach(function (o) {
      var labelStun = o.stun.replace(/^stun:/, '');
      if (o.error) {
        html += '<div><span style="color:var(--text-3)">' + esc(labelStun) + ':</span> ' +
          '<span class="domain-error">' + esc(o.error) + '</span></div>';
      } else if (!o.srflx.length) {
        html += '<div><span style="color:var(--text-3)">' + esc(labelStun) + ':</span> ' +
          '<span style="color:var(--text-3)">(no srflx)</span></div>';
      } else {
        var s = o.srflx[0];
        html += '<div><span style="color:var(--text-3)">' + esc(labelStun) + ':</span> ' +
          esc(s.address) + ':' + esc(s.port) + '</div>';
      }
    });
    html += '</div>';
    setCard('myip-stun', html);
  }

  function renderIpv6(hasIpv6, ipv6, isCgnatV4) {
    if (hasIpv6) {
      var saves = isCgnatV4
        ? ' <div style="margin-top:0.4rem;color:var(--text-2);font-size:0.78rem;">' +
            esc(lbl('lblIpv6Saves', 'IPv4 is CGNATed but IPv6 is reachable — your services are exposed via IPv6.')) +
          '</div>'
        : '';
      setCard('myip-ipv6', '<span class="domain-badge" style="background:#27ae6022;color:#27ae60;border:1px solid #27ae6055;">' +
        esc(lbl('lblIpv6Yes', 'Connected')) + '</span>' +
        '<div style="font-family:var(--mono);font-size:0.78rem;color:var(--text-2);margin-top:0.4rem;word-break:break-all;">' +
        esc(ipv6 || '') + '</div>' + saves);
    } else {
      setCard('myip-ipv6', '<span class="domain-badge" style="background:#8b949e22;color:#8b949e;border:1px solid #8b949e55;">' +
        esc(lbl('lblIpv6No', 'IPv4-only (no IPv6 connectivity detected)')) + '</span>');
    }
  }

  function renderConn(c) {
    if (!c) {
      return setCard('myip-conn', '<span style="color:var(--text-3)">' +
        esc(lbl('lblPending', 'Measuring…')) + '</span>');
    }
    var rttUnit = lbl('lblRttUnit', 'ms');
    var html = '<div style="display:grid;grid-template-columns:auto 1fr;gap:0.3rem 0.8rem;font-family:var(--mono);font-size:0.85rem;">';
    html += '<span style="color:var(--text-3)">RTT:</span><span>' + esc(c.rtt) + ' ' + esc(rttUnit) + '</span>';
    html += '<span style="color:var(--text-3)">HTTP:</span><span>' + esc(c.http || '—') + '</span>';
    html += '<span style="color:var(--text-3)">TLS:</span><span>' + esc(c.tls || '—') + '</span>';
    html += '</div>';
    setCard('myip-conn', html);
  }

  function renderVerdict(state, opts) {
    /* state = 'direct' | 'uncertain' | 'cgnat' | 'unknown' */
    var icons = { direct: '🟢', uncertain: '🟡', cgnat: '🔴', unknown: '⚪' };
    verdict.dataset.state = state;
    var ico = verdict.querySelector('.myip-verdict-icon');
    var ttl = verdict.querySelector('.myip-verdict-title');
    var sub = verdict.querySelector('.myip-verdict-sub');
    if (ico) ico.textContent = icons[state] || '⚪';
    if (ttl) ttl.textContent = vlbl('lbl' + state.charAt(0).toUpperCase() + state.slice(1) + 'Title', '');
    if (sub) sub.textContent = (opts && opts.reason) || vlbl('lbl' + state.charAt(0).toUpperCase() + state.slice(1) + 'Sub', '');
  }

  /* ── Orchestration : déclenchée par lwpc-myip-ready ────────── */

  function runDiag(d) {
    /* d = données IP de base (ipv4, ipv6, asn, country, ...) */
    var hasIpv6 = !!d.ipv6;
    var ipv4 = d.ipv4 || d.ip;

    /* Render IPv6 immédiatement (basé sur les données déjà collectées) */
    renderIpv6(hasIpv6, d.ipv6, false /* isCgnatV4 — déterminé après STUN */);

    /* RTT + HTTP + TLS — en parallèle des STUN probes */
    var rttPromise = measureRtt().then(function (c) { renderConn(c); return c; });

    /* STUN probes — Cloudflare puis Google (pas en parallèle pour rester
       gentil avec les serveurs publics et permettre la comparaison de ports). */
    var stunUrls = ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'];
    var probesPromise = stunProbe(stunUrls[0]).then(function (a) {
      return stunProbe(stunUrls[1]).then(function (b) { return [a, b]; });
    });

    Promise.all([probesPromise, rttPromise]).then(function (results) {
      var probes = results[0];

      /* Fusion des host candidates (dédup par address) */
      var hostMap = {};
      probes.forEach(function (p) {
        (p.host || []).forEach(function (h) { hostMap[h.address] = h; });
      });
      var hostCands = Object.keys(hostMap).map(function (k) { return hostMap[k]; });
      renderLocal(hostCands);

      /* Render STUN observations */
      renderStun(probes);

      /* Détection CGNAT 100.64/10 dans host candidates */
      var hasCgnatHost = hostCands.some(function (c) { return isCgnat(c.address); });

      /* Comparaison srflx ports inter-STUN → symmetric NAT */
      var srflx0 = (probes[0].srflx && probes[0].srflx[0]) || null;
      var srflx1 = (probes[1].srflx && probes[1].srflx[0]) || null;
      var natType = 'unknown';
      if (probes.every(function (p) { return p.error === 'no-webrtc'; })) natType = 'no-webrtc';
      else if (srflx0 && srflx1) {
        if (srflx0.address !== srflx1.address || Math.abs(srflx0.port - srflx1.port) > 1) {
          natType = 'symmetric';
        } else {
          natType = 'cone';
        }
      } else if (!srflx0 && !srflx1) {
        natType = 'unknown';
      }
      renderNat(natType, [srflx0, srflx1]);

      /* Mise à jour IPv6 reachability avec contexte CGNAT */
      var srflxIp = (srflx0 && srflx0.address) || (srflx1 && srflx1.address) || ipv4;
      var srflxIsCgnat = isCgnat(srflxIp);
      if (hasIpv6 && (hasCgnatHost || srflxIsCgnat || natType === 'symmetric')) {
        renderIpv6(true, d.ipv6, true);
      }

      /* ── VERDICT SCORING (partiel — sera enrichi inc. 3 avec ASN cloud/Tor) ── */
      var state = 'unknown', reason = '';

      if (natType === 'no-webrtc') {
        state = 'unknown';
        reason = vlbl('lblUnknownSub', '');
      } else if (hasCgnatHost || srflxIsCgnat) {
        state = 'cgnat';
        reason = lbl('lblCgnatConfirmed', 'IP detected in 100.64.0.0/10 (RFC 6598).');
      } else if (natType === 'symmetric') {
        state = 'cgnat';
        reason = lbl('lblSymmetric', 'Symmetric NAT (CGNAT very likely).');
      } else if (natType === 'cone') {
        state = 'direct';
        reason = '';
      } else {
        state = 'uncertain';
        reason = '';
      }

      renderVerdict(state, { reason: reason });
    });
  }

  /* ── Wiring ────────────────────────────────────────────────── */
  document.addEventListener('lwpc-myip-ready', function (ev) {
    if (ev && ev.detail) runDiag(ev.detail);
  });
  document.addEventListener('lwpc-myip-failed', function () {
    renderVerdict('unknown', { reason: '' });
  });

})();
