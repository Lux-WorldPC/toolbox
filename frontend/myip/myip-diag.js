/**
 * What's My IP — diagnostic réseau IT-grade.
 * @lwpc/toolbox (MIT) — frontend. Ajouté 2026-04-29.
 *
 * Activé après que myip.js a affiché les 5 cards de base et émis l'event
 * 'lwpc-myip-ready' sur document. Lance en parallèle :
 *
 *   1. WebRTC/STUN — UNE seule RTCPeerConnection avec 2 STUN servers
 *      (Cloudflare + Google) dans iceServers. Verdict CGNAT basé sur
 *      la STABILITÉ DE L'IP PUBLIQUE entre srflx (pas le port).
 *   2. IPv6 reachability — résultat Cloudflare trace de myip.js.
 *   3. Connection quality — 5 fetches /api/myip/ping (médiane RTT),
 *      nextHopProtocol via PerformanceResourceTiming (HTTP version),
 *      TLS via Cloudflare cdn-cgi/trace champ tls=.
 *   4. ASN matching — petite liste de FAI luxembourgeois CGNAT par
 *      défaut (POST 6661, Orange 56601, Tango 5605) car STUN seul ne
 *      détecte pas un CGNAT bien comporté (1 IP publique stable). Pour
 *      d'autres pays, étendre cette liste ou la passer en paramètre.
 *   5. Verdict scoring — combine STUN + ASN en un état 🟢/🟡/🔴/⚪.
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

  function renderNat(natType, portVariation) {
    var color = '#8b949e', label = natType || 'unknown';
    if (natType === 'symmetric') {
      color = '#e74c3c';
      label = lbl('lblSymmetric', 'Symmetric NAT (CGNAT very likely)');
    } else if (natType === 'cone') {
      color = '#27ae60';
      label = lbl('lblCone', 'Cone NAT (consistent address)');
    } else if (natType === 'open') {
      color = '#27ae60';
      label = lbl('lblOpen', 'Open / endpoint-independent');
    } else if (natType === 'no-webrtc') {
      label = lbl('lblNoWebrtc', 'WebRTC unavailable');
    }
    var html = '<div><span class="domain-badge" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '55;font-size:0.85rem;">' + esc(label) + '</span></div>';
    /* Port-variation note — informative, pas un signal CGNAT à elle seule
       (commun en multi-homing ou port-dependent mapping). */
    if (portVariation && natType === 'cone') {
      html += '<div style="margin-top:0.4rem;color:var(--text-3);font-size:0.75rem;">' +
        esc(lbl('lblPortVariation', 'Port mapping varies by destination — common with multi-homing (Wi-Fi+Ethernet, VPN, Docker) or port-dependent NAT.')) + '</div>';
    }
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

    /* RTT + HTTP + TLS — en parallèle de la STUN probe et du fetch DB-IP */
    var rttPromise = measureRtt().then(function (c) { renderConn(c); return c; });

    /* STUN probe — UNE seule RTCPeerConnection avec 2 STUN servers dans
       iceServers (cf. commentaire stunProbe). C'est le vrai test RFC 5780. */
    var stunUrls = ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'];
    var probePromise = stunProbe(stunUrls);

    /* DB-IP enrichi — vient désormais du backend (handleMyIp /api/myip
       inclut un sous-objet `dbip` quand DBIP_API_KEY est posée côté serveur).
       La clé privée n'est pas restreinte par origin (contrairement à la
       publique trial limitée à 1 origin), et le backend fait du cache 1h.
       Si DB-IP est absent (pas de clé, plan expiré, panne), d.dbip est
       undefined → scoring retombe sur la logique ASN hardcodée. */
    var dbip = (d && d.dbip) || null;

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

      /* Classification NAT — basée sur l'IP publique, pas sur le port.
         Le port mapping (cone full / address-restricted / port-restricted /
         symmetric) n'est PAS un proxy fiable pour CGNAT depuis 2 STUN seuls :
           - Multi-homing (Wi-Fi + Eth, VPN, Docker) → ports différents
             par interface, pas un signal symmetric.
           - Chrome avec mDNS masque les raddr en 0.0.0.0 → impossible de
             grouper par interface.
           - Port-dependent mapping (cone NAT cohérent par adresse mais
             port variable selon dest) ≠ CGNAT.
         Le vrai signal CGNAT côté client est :
           - une IP publique en 100.64.0.0/10 (RFC 6598) — déjà géré ailleurs
           - une IP publique qui CHANGE entre 2 STUN servers (= pool CGNAT)
         Si l'IP publique est stable, on retient "cone" même si les ports
         varient (et on rend ça lisible dans la card). */
      var natType = 'unknown';
      var portVariation = false;
      if (probe.error === 'no-webrtc') natType = 'no-webrtc';
      else if (!probe.srflx || !probe.srflx.length) natType = 'unknown';
      else {
        var publicIps = {};
        var pairs = {};
        probe.srflx.forEach(function (s) {
          publicIps[s.address] = true;
          pairs[s.address + ':' + s.port] = true;
        });
        var nIps = Object.keys(publicIps).length;
        portVariation = Object.keys(pairs).length > nIps;
        if (nIps === 1) natType = 'cone';
        else natType = 'symmetric';
      }
      renderNat(natType, portVariation);

      /* Mise à jour IPv6 reachability avec contexte CGNAT */
      var srflxIp = (probe.srflx && probe.srflx[0] && probe.srflx[0].address) || ipv4;
      var srflxIsCgnat = isCgnat(srflxIp);
      if (hasIpv6 && (hasCgnatHost || hasCgnatSrflx || natType === 'symmetric')) {
        renderIpv6(true, d.ipv6, true);
      }

      /* ── DB-IP — Network Owner enrichi avec linkType + usageType ── */
      if (dbip) renderOwnerEnriched(dbip);

      /* ── Threat / proxy banner si signal fort DB-IP ── */
      if (dbip) renderThreatBanner(dbip);

      /* ── ASN matching luxembourgeois (fallback si DB-IP absent) ──
            Si DB-IP n'a pas répondu (clé absente, trial expiré, panne),
            on retombe sur le mini-mapping inline qui couvre les 3 FAI lux.
            Sinon la logique DB-IP qui suit prend la priorité. */
      var asn = d.asn != null ? String(d.asn) : '';
      var asnCgnatHint = null;
      if (!dbip) {
        if (asn === '6661') {
          asnCgnatHint = lbl('lblAsnPost', 'AS6661 (POST Luxembourg) — CGNAT by default on fixed POP Internet AND mobile. A public-IP option is available.');
        } else if (asn === '56601') {
          asnCgnatHint = lbl('lblAsnOrange', 'AS56601 (Orange Luxembourg) — mobile data is systematically CGNATed.');
        } else if (asn === '5605') {
          asnCgnatHint = lbl('lblAsnTango', 'AS5605 (Tango / Proximus LU) — CGNAT on mobile data. Fixed depends on plan.');
        }
      }

      /* ── VERDICT SCORING ──
         Ordre de priorité (du plus fiable au moins fiable) :
           1. 100.64/10 confirmé STUN  → 🔴 CGNAT (RFC 6598, signal direct)
           2. STUN symmetric (IP varie) → 🔴 CGNAT (vrai pool CGNAT visible)
           3. DB-IP linkType=cellular   → 🔴 CGNAT mobile (mondial)
           4. DB-IP usageType=hosting/cdn → 🟡 VPN/cloud probable
           5. DB-IP isProxy=true        → 🟡/🔴 selon proxyType
           6. DB-IP usageType=business/corporate → 🟢 IP fixe pro (override
              le hint ASN POST/Tango pour les clients business avec IP fixe)
           7. ASN hardcodé lux (fallback si DB-IP absent) → 🔴 CGNAT
           8. STUN cone               → 🟢 direct
           9. Sinon                   → 🟡 uncertain */
      var state = 'unknown', reason = '';

      if (natType === 'no-webrtc') {
        state = 'unknown';
        reason = vlbl('lblUnknownSub', '');
      } else if (hasCgnatHost || hasCgnatSrflx) {
        state = 'cgnat';
        reason = lbl('lblCgnatConfirmed', 'IP detected in 100.64.0.0/10 (RFC 6598).');
      } else if (natType === 'symmetric') {
        state = 'cgnat';
        reason = lbl('lblSymmetric', 'Symmetric NAT — public IP varies between STUN servers (CGNAT pool).');
      } else if (dbip && (
            dbip.linkType === 'cellular' ||
            dbip.linkType === 'wireless' ||
            dbip.usageType === 'cellular'
          )) {
        /* DB-IP utilise tantôt 'cellular' tantôt 'wireless' pour la 4G/5G
           selon les régions/opérateurs. Les deux valeurs signalent du
           mobile, qui est CGNATé chez quasi tous les opérateurs mondiaux. */
        state = 'cgnat';
        reason = lbl('lblCellular', 'Cellular network detected — mobile data is almost always CGNATed.');
      } else if (dbip && dbip.isProxy && dbip.proxyType === 'tor') {
        state = 'cgnat';
        reason = lbl('lblTor', 'Tor exit node detected — your apparent IP is shared and not yours.');
      } else if (dbip && dbip.isProxy && dbip.proxyType === 'vpn') {
        state = 'uncertain';
        reason = lbl('lblVpn', 'VPN detected — your apparent IP belongs to a VPN provider, not your home/office network.');
      } else if (dbip && (dbip.usageType === 'hosting' || dbip.usageType === 'cdn')) {
        state = 'uncertain';
        reason = lbl('lblHosting', 'Hosting/CDN IP — likely a VPN, cloud server or proxy, not a residential connection.');
      } else if (dbip && (dbip.usageType === 'business' || dbip.usageType === 'corporate')) {
        /* Override du fallback ASN : un client business sur AS6661 avec
           usageType=corporate a probablement l'option IP publique fixe. */
        state = 'direct';
        reason = '';
      } else if (asnCgnatHint) {
        state = 'cgnat';
        reason = asnCgnatHint;
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

  /* ── Render helpers DB-IP ─────────────────────────────────── */

  function renderOwnerEnriched(dbip) {
    /* Étend la card "Network Owner" déjà alimentée par myip.js (RIPE)
       avec linkType + usageType (badge), sans tout réécrire — on append
       une ligne en bas. Sans casser le rendu si l'élément a été manipulé. */
    var el = document.getElementById('myip-org');
    if (!el) return;
    var badges = '';
    if (dbip.linkType) {
      badges += '<span class="domain-badge" style="background:#3d539422;color:#3d5394;border:1px solid #3d539455;">' +
        esc(String(dbip.linkType).toUpperCase()) + '</span>';
    }
    if (dbip.usageType) {
      var color = '#8b949e';
      var ut = String(dbip.usageType).toLowerCase();
      if (ut === 'consumer') color = '#27ae60';
      else if (ut === 'business' || ut === 'corporate') color = '#3d5394';
      else if (ut === 'hosting' || ut === 'cdn') color = '#f1c40f';
      else if (ut === 'cellular') color = '#e74c3c';
      badges += ' <span class="domain-badge" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '55;">' +
        esc(String(dbip.usageType).toUpperCase()) + '</span>';
    }
    if (badges) {
      el.innerHTML += '<div style="margin-top:0.4rem;">' + badges + '</div>';
    }
  }

  function renderThreatBanner(dbip) {
    /* Si DB-IP signale un threat élevé ou un proxy abusif, on ajoute
       un bandeau au-dessus du verdict. Affiché uniquement si signal fort. */
    if (!dbip) return;
    var msgs = [];
    if (dbip.threatLevel === 'high') {
      msgs.push(lbl('lblThreatHigh', 'High threat level reported for this IP (attack source, abuse, etc.).'));
    }
    if (dbip.isProxy && dbip.proxyType === 'tor') {
      msgs.push(lbl('lblProxyTor', 'IP listed as a Tor exit node.'));
    }
    if (Array.isArray(dbip.threatDetails) && dbip.threatDetails.length) {
      msgs.push(esc(dbip.threatDetails.join(', ')));
    }
    if (!msgs.length) return;
    var el = document.getElementById('myip-verdict');
    if (!el) return;
    /* Insertion après le verdict, avant les détails — on évite de casser
       le data-state du verdict en ajoutant un sibling. */
    var existing = document.getElementById('myip-threat-banner');
    if (existing) existing.parentNode.removeChild(existing);
    var banner = document.createElement('div');
    banner.id = 'myip-threat-banner';
    banner.setAttribute('role', 'alert');
    banner.style.cssText = 'background:#e74c3c11;border:1px solid #e74c3c55;border-left:4px solid #e74c3c;border-radius:var(--radius);padding:0.7rem 1rem;font-size:0.85rem;color:var(--text);';
    banner.innerHTML = '<strong>⚠ ' + esc(lbl('lblThreatTitle', 'Threat signals')) + '</strong><br>' +
      msgs.map(function (m) { return esc(m); }).join('<br>');
    el.parentNode.insertBefore(banner, el.nextSibling);
  }

  /* ── Wiring ────────────────────────────────────────────────── */
  document.addEventListener('lwpc-myip-ready', function (ev) {
    if (ev && ev.detail) runDiag(ev.detail);
  });
  document.addEventListener('lwpc-myip-failed', function () {
    renderVerdict('unknown', { reason: '' });
  });

})();
