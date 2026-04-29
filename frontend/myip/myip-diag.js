/**
 * What's My IP — diagnostic réseau IT-grade.
 * @lwpc/toolbox (MIT) — frontend. Ajouté 2026-04-29.
 *
 * Activé après que myip.js a affiché les 5 cards de base et émis l'event
 * 'lwpc-myip-ready' sur document. Lance en parallèle :
 *
 *   1. WebRTC/STUN — UNE seule RTCPeerConnection avec 2 STUN servers
 *      (Cloudflare + Google) dans iceServers. Test RFC 5780 du NAT mapping
 *      behavior, mais avec regroupement par raddr (interface locale source)
 *      pour ne pas confondre multi-homing (Wi-Fi + Ethernet, VPN, Docker)
 *      avec symmetric NAT.
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

  /* ── 1. STUN probe (WebRTC) — UNE SEULE RTCPeerConnection avec les
        N serveurs STUN dans iceServers. ICE va alors interroger chaque
        STUN avec le MÊME socket UDP local et émettre une srflx candidate
        par STUN — c'est le vrai test RFC 5780 du NAT mapping behavior :

          - mêmes (ip, port) srflx pour tous les STUN  → endpoint-independent
            (full-cone, address/port-restricted) = ✅ pas de CGNAT côté NAT
          - port (ou IP) srflx différent selon le STUN → endpoint-dependent
            (symmetric NAT) = 🔴 CGNAT très probable

        ⚠ Faire 2 PeerConnection séparées (une par STUN) ne marche PAS :
        chaque PC ouvre son propre socket UDP éphémère → ports différents
        même en cone NAT (faux positif). Il faut UNE PC, plusieurs STUN.

        Renvoie { host: [...], srflx: [...by stun], error: string|null }
        avec srflx = [{ stun, address, port, raddr, rport }, ...]. */
  function stunProbe(stunUrls) {
    return new Promise(function (resolve) {
      if (typeof RTCPeerConnection === 'undefined') {
        resolve({ host: [], srflx: [], error: 'no-webrtc' });
        return;
      }
      var pc, done = false, host = [], srflx = [];
      function finish(err) {
        if (done) return; done = true;
        try { pc && pc.close(); } catch (e) {}
        resolve({ host: host, srflx: srflx, error: err || null });
      }
      try {
        pc = new RTCPeerConnection({
          iceServers: stunUrls.map(function (u) { return { urls: u }; }),
          iceCandidatePoolSize: 0
        });
      } catch (e) { finish('rtc-init-failed'); return; }
      pc.createDataChannel('lwpc-probe');
      pc.onicecandidate = function (e) {
        if (!e.candidate) { finish(null); return; } /* end-of-candidates */
        var c = e.candidate;
        var raw = c.candidate || '';
        var addr = c.address || null, port = c.port || null, type = null;
        var raddr = c.relatedAddress || null, rport = c.relatedPort || null;
        var m = raw.match(/typ\s+(\S+)/);
        if (m) type = m[1];
        if (!addr) {
          var parts = raw.split(/\s+/);
          if (parts.length >= 6) { addr = parts[4]; port = parseInt(parts[5], 10); }
        }
        if (!raddr) {
          var rm = raw.match(/raddr\s+(\S+)\s+rport\s+(\d+)/);
          if (rm) { raddr = rm[1]; rport = parseInt(rm[2], 10); }
        }
        if (!type || !addr) return;
        if (type === 'host') host.push({ address: addr, port: port });
        else if (type === 'srflx') srflx.push({
          address: addr, port: port, raddr: raddr, rport: rport, raw: raw
        });
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); })
        .catch(function () { finish('offer-failed'); });
      /* Timeout généreux : ICE peut tarder à émettre tous les candidates
         srflx (un par STUN), surtout si l'un des STUN est lent. */
      setTimeout(function () { finish('timeout'); }, 5000);
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

  function renderNat(natType) {
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

  function renderStun(srflxList, stunUrls) {
    /* Affiche chaque srflx (ip publique:port) avec sa raddr (interface locale
       source). Plusieurs interfaces (Wi-Fi + Ethernet, VPN, Docker) → autant
       de srflx avec raddr différents. Comparer leur (ip, port) entre raddr
       n'a pas de sens (sockets différents) — d'où le regroupement visible. */
    if (!srflxList || !srflxList.length) {
      return setCard('myip-stun', '<span style="color:var(--text-3)">' +
        esc(lbl('lblNoWebrtc', 'WebRTC unavailable / no srflx')) + '</span>');
    }
    var stunsLabel = (stunUrls || []).map(function (u) { return u.replace(/^stun:/, ''); }).join(' + ');
    var html = '<div style="display:grid;grid-template-columns:1fr;gap:0.4rem;font-family:var(--mono);font-size:0.85rem;">';
    html += '<div style="color:var(--text-3);font-size:0.75rem;">via ' + esc(stunsLabel) + '</div>';
    srflxList.forEach(function (s, i) {
      var line = esc(s.address) + ':' + esc(s.port);
      var note = s.raddr
        ? ' <span style="color:var(--text-3);font-size:0.75rem;">(from ' + esc(s.raddr) + ')</span>'
        : '';
      html += '<div>#' + (i + 1) + ' &nbsp; ' + line + note + '</div>';
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

    /* RTT + HTTP + TLS — en parallèle de la STUN probe */
    var rttPromise = measureRtt().then(function (c) { renderConn(c); return c; });

    /* STUN probe — UNE seule RTCPeerConnection avec 2 STUN servers dans
       iceServers (cf. commentaire stunProbe). C'est le vrai test RFC 5780. */
    var stunUrls = ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'];
    var probePromise = stunProbe(stunUrls);

    Promise.all([probePromise, rttPromise]).then(function (results) {
      var probe = results[0];

      /* Host candidates — affichage Local Network */
      renderLocal(probe.host || []);

      /* Détection CGNAT 100.64/10 sur host candidates ET srflx */
      var hasCgnatHost = (probe.host || []).some(function (c) { return isCgnat(c.address); });
      var hasCgnatSrflx = (probe.srflx || []).some(function (c) { return isCgnat(c.address); });

      /* Affichage STUN — on liste les srflx par "STUN n°i" puisqu'on ne sait
         plus de quel STUN vient chaque candidate (single PC, ICE multiplexe).
         C'est OK : ce qui compte est qu'on en voit ≥ 1, et qu'ils soient
         tous identiques (cone) ou divergents (symmetric). */
      renderStun(probe.srflx || [], stunUrls);

      /* Analyse symmetric vs cone — IMPORTANT : il faut comparer SEULEMENT
         des srflx qui sortent du MÊME chemin réseau (même raddr = même
         interface locale + socket). Un client multi-homed (Wi-Fi + Ethernet,
         VPN, Docker, adaptateurs virtuels) émet une host candidate par
         interface → chaque interface ouvre son propre socket UDP éphémère
         → ports srflx différents même en cone NAT, ce qui n'est PAS un
         signal symmetric (juste du multi-homing).

         On groupe donc les srflx par raddr et on cherche l'INCONSISTANCE
         INTRA-RADDR : si deux srflx sortant de la même interface ont des
         (ip, port) différents → symmetric NAT vraiment. Sinon → cone. */
      var natType = 'unknown';
      if (probe.error === 'no-webrtc') natType = 'no-webrtc';
      else if (!probe.srflx || !probe.srflx.length) natType = 'unknown';
      else {
        var byRaddr = {};
        probe.srflx.forEach(function (s) {
          var k = s.raddr || '_unknown';
          if (!byRaddr[k]) byRaddr[k] = {};
          byRaddr[k][s.address + ':' + s.port] = true;
        });
        var symmetricEvidence = false;
        var coneEvidence = false;
        Object.keys(byRaddr).forEach(function (raddr) {
          var n = Object.keys(byRaddr[raddr]).length;
          if (n > 1) symmetricEvidence = true;
          else if (n === 1) coneEvidence = true;
        });
        /* Si on n'a aucune comparaison intra-raddr possible (1 seul srflx
           par interface, ou aucun raddr fiable), on retient "cone" par
           défaut — c'est le cas standard et l'absence de preuve d'inconsis-
           tance ne justifie pas un verdict 🔴 alarmiste. */
        if (symmetricEvidence) natType = 'symmetric';
        else if (coneEvidence) natType = 'cone';
        else natType = 'unknown';
      }
      renderNat(natType);

      /* Mise à jour IPv6 reachability avec contexte CGNAT */
      var srflxIp = (probe.srflx && probe.srflx[0] && probe.srflx[0].address) || ipv4;
      var srflxIsCgnat = isCgnat(srflxIp);
      if (hasIpv6 && (hasCgnatHost || hasCgnatSrflx || natType === 'symmetric')) {
        renderIpv6(true, d.ipv6, true);
      }

      /* ── VERDICT SCORING (partiel — sera enrichi inc. 3 avec ASN cloud/Tor) ── */
      var state = 'unknown', reason = '';

      if (natType === 'no-webrtc') {
        state = 'unknown';
        reason = vlbl('lblUnknownSub', '');
      } else if (hasCgnatHost || hasCgnatSrflx) {
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
