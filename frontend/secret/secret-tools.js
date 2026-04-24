/**
 * Secret Tools — Chiffrement E2E + formulaire + page reveal
 * @lwpc/toolbox (MIT) — frontend. Autonome : le serveur stocke des blobs
 * chiffrés qu'il ne peut PAS déchiffrer. Backend : POST /secret/api/{create,reveal}.
 *
 * 100% autonome : le serveur stocke des blobs chiffrés qu'il ne peut PAS déchiffrer.
 * Le masterKey reste dans le fragment URL (#) — jamais envoyé au serveur.
 *
 * Crypto (Web Crypto API) :
 *   - AES-256-GCM pour le chiffrement du contenu
 *   - PBKDF2 (100 000 itérations, SHA-256) pour dériver la clé AES
 *   - Le masterKey (32 chars URL-safe aléatoires) sert de mot de passe pour PBKDF2
 *   - Double chiffrement si mot de passe utilisateur (password puis masterKey)
 *
 * Deux modes de fonctionnement (même fichier JS, détection par ID DOM) :
 *   1. Page CREATE (/toolbox/secret/)      — #secret-form détecté
 *      Formulaire → chiffre → POST /secret/api/create → affiche lien
 *   2. Page REVEAL (/toolbox/secret/view/) — #secret-reveal détecté
 *      Lit le fragment → POST /secret/api/reveal → déchiffre → affiche
 *
 * Format du lien : https://<host>/#{id}:{masterKey}
 *   - <host> = origine du site qui héberge la page reveal (configurable via
 *     data-secret-host sur .secret-container ; défaut = location.host)
 *   - id       = identifiant du fichier sur le serveur (22 chars, crypto.randomBytes)
 *   - masterKey = clé de déchiffrement (32 chars, jamais envoyée au serveur)
 *
 * Pièce jointe (ajouté 2026-04-09) :
 *   - Fichier optionnel (max 1 Mo) : image, PDF, txt, json, csv
 *   - Le fichier est lu via FileReader.readAsDataURL → base64
 *   - Payload JSON chiffré : {type:'file', name, mime, data, text} ou {type:'text', content}
 *   - Page reveal : preview image + bouton download (toujours)
 *   - Rétrocompatibilité : si le JSON ne parse pas, affiche en texte brut (anciens secrets)
 *
 * Fonctionnalités additionnelles :
 *   - Bouton Partager (Web Share API) sur les pages create ET reveal
 *   - Fix lang switcher sur la page reveal : intercepte les clics pour préserver le #hash
 *   - Conversion base64 via Blob+FileReader (évite les limites de btoa sur gros buffers Safari)
 *
 * Quota client (ajouté 2026-04-10) :
 *   - 10 créations / 30 min (sessionStorage, même logique que Domain Checkup)
 *   - Compteur toujours visible, bouton désactivé si quota atteint
 *   - Labels i18n via data-lbl-* sur #secret-quota-msg (4 langues)
 *   - Backend applique aussi un quota (12/jour via isDailyLimitReached + whitelist IPs)
 *   - Bypass client : window.lwpcWhitelisted → skip quota + message "Whitelisted"
 *
 * Notification email créateur (ajouté 2026-04-10) :
 *   - Champ email optionnel #secret-notify-email sur la page create
 *   - Envoyé dans le payload comme `notifyEmail` → stocké en clair dans le JSON serveur
 *   - À la révélation : Node.js envoie un email au créateur (template corporate)
 *
 * Pré-remplissage depuis Password Generator (ajouté 2026-04-10) :
 *   - Lit sessionStorage('secret_prefill') au chargement de la page create
 *   - Si présent → pré-remplit le textarea #secret-content + supprime la clé
 *   - Posé par le bouton "Envoyer en secret" de /toolbox/password/ (password-generator.js)
 *
 * Page reveal — confirmation (ajouté 2026-04-10) :
 *   - Checkbox #reveal-confirm "Je suis prêt(e) à révéler" (i18n 4 langues)
 *   - Bouton Révéler disabled par défaut, activé quand la case est cochée
 *   - Empêche une révélation accidentelle (le secret est détruit après lecture)
 *
 * Dernière mise à jour : 2026-04-10.
 * ⚠ Après modification, supprimer resources/ et rebuild (Hugo cache les assets).
 */
(function () {
  'use strict';

  /* API endpoint base — override via `window.LWPC_API_BASE = 'https://api.example.com'`
     before loading this script. Default: same-origin. */
  var API_BASE = (typeof window !== 'undefined' && window.LWPC_API_BASE) || '';

  /* ══════════════════════════════════════════════════════════════
     CRYPTO — chiffrement E2E côté navigateur
     AES-256-GCM via PBKDF2 (100k itérations). Même pattern que l'ancien code.
     ══════════════════════════════════════════════════════════════ */

  var URL_SAFE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  function generateMasterKey() {
    var arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    var result = '';
    for (var i = 0; i < 32; i++) result += URL_SAFE_CHARS[arr[i] % URL_SAFE_CHARS.length];
    return result;
  }

  async function deriveKey(password, salt) {
    var encoded = new TextEncoder().encode(password);
    var keyMaterial = await crypto.subtle.importKey('raw', encoded, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  /* Convertit un Uint8Array en base64.
     Utilise Blob + FileReader pour éviter les limites de btoa/String.fromCharCode
     (dépassement de stack sur gros buffers, erreur Safari "pattern" sur certains octets). */
  function uint8ToBase64(arr) {
    return new Promise(function (resolve) {
      var blob = new Blob([arr]);
      var reader = new FileReader();
      reader.onload = function () {
        /* result = "data:application/octet-stream;base64,XXXXX" */
        resolve(reader.result.split(',')[1]);
      };
      reader.readAsDataURL(blob);
    });
  }

  /* Convertit une string base64 en Uint8Array */
  function base64ToUint8(b64) {
    var bin = atob(b64);
    var arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  /* Chiffre un texte → base64(salt16 + iv12 + ciphertext) */
  async function encrypt(text, password) {
    var salt = new Uint8Array(16); crypto.getRandomValues(salt);
    var iv   = new Uint8Array(12); crypto.getRandomValues(iv);
    var key  = await deriveKey(password, salt);
    var data = new TextEncoder().encode(text);
    var enc  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, data);
    var buf  = new Uint8Array(salt.length + iv.length + enc.byteLength);
    buf.set(salt, 0);
    buf.set(iv, salt.length);
    buf.set(new Uint8Array(enc), salt.length + iv.length);
    return await uint8ToBase64(buf);
  }

  /* Déchiffre base64(salt16 + iv12 + ciphertext) → texte */
  async function decrypt(b64, password) {
    var raw = base64ToUint8(b64);
    var salt = raw.slice(0, 16);
    var iv   = raw.slice(16, 28);
    var data = raw.slice(28);
    var key  = await deriveKey(password, salt);
    var dec  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
    return new TextDecoder().decode(dec);
  }

  /* ══════════════════════════════════════════════════════════════
     MODE 1 — PAGE CREATE (/toolbox/secret/)
     ══════════════════════════════════════════════════════════════ */

  /* ══════════════════════════════════════════════════════════════
     QUOTA CLIENT — 10 créations / 30 min (même logique que Domain Checkup)
     ══════════════════════════════════════════════════════════════ */

  var QUOTA_MAX = 10;
  var QUOTA_WINDOW = 30 * 60 * 1000;
  var QUOTA_KEY = 'secret_creates';
  var quotaMsg = document.getElementById('secret-quota-msg');
  var submitBtnGlobal = document.getElementById('secret-submit');

  function getQuotaData() {
    try { var d = JSON.parse(sessionStorage.getItem(QUOTA_KEY)); if (d && Array.isArray(d.ts)) return d; } catch (e) {}
    return { ts: [] };
  }
  function saveQuotaData(d) { sessionStorage.setItem(QUOTA_KEY, JSON.stringify(d)); }
  function purgeQuota() {
    var d = getQuotaData(); var now = Date.now();
    d.ts = d.ts.filter(function (t) { return t > now - QUOTA_WINDOW; });
    saveQuotaData(d); return d;
  }
  function checkQuota() { return window.lwpcWhitelisted || purgeQuota().ts.length < QUOTA_MAX; }
  function recordCreate() { var d = purgeQuota(); d.ts.push(Date.now()); saveQuotaData(d); }
  function getQuotaRemaining() { return QUOTA_MAX - purgeQuota().ts.length; }

  function quotaLabel(key, fallback) {
    return (quotaMsg && quotaMsg.dataset['lbl' + key]) || fallback;
  }
  function updateQuotaDisplay() {
    if (window.lwpcWhitelisted || !quotaMsg) return;
    var remaining = getQuotaRemaining();
    var base = quotaLabel('Limited', 'Voluntarily limited to') + ' ' + QUOTA_MAX + ' ' +
               quotaLabel('Unit', 'messages') + ' / 30 min';
    if (remaining <= 0) {
      quotaMsg.innerHTML = '⚠ ' + base + ' — <strong>0</strong> ' +
        quotaLabel('Remaining', 'remaining') + '. ' + quotaLabel('Blocked', 'Please try again later.');
      quotaMsg.classList.add('is-blocked');
      if (submitBtnGlobal) submitBtnGlobal.disabled = true;
    } else {
      quotaMsg.innerHTML = base + ' — <strong>' + remaining + '</strong> ' +
        quotaLabel('Remaining', 'remaining');
      quotaMsg.classList.remove('is-blocked');
      if (submitBtnGlobal) submitBtnGlobal.disabled = false;
    }
    quotaMsg.hidden = false;
  }
  updateQuotaDisplay();

  var form = document.getElementById('secret-form');
  if (form) initCreateMode();

  function initCreateMode() {
    var contentInput  = document.getElementById('secret-content');
    var fileInput     = document.getElementById('secret-file');
    var fileNameEl    = document.getElementById('secret-file-name');
    var passwordInput = document.getElementById('secret-password');
    var expirationSel = document.getElementById('secret-expiration');

    /* Pré-remplissage depuis le Password Generator (sessionStorage, ajouté 2026-04-10).
       Le bouton "Envoyer en secret" sur /toolbox/password/ stocke le mdp dans secret_prefill.
       On le lit, pré-remplit le textarea, et le supprime immédiatement. */
    var prefill = sessionStorage.getItem('secret_prefill');
    if (prefill && contentInput) {
      contentInput.value = prefill;
      sessionStorage.removeItem('secret_prefill');
    }
    var submitBtn     = document.getElementById('secret-submit');
    var resultSection = document.getElementById('secret-result');
    var resultLink    = document.getElementById('secret-link');
    var resultExpires = document.getElementById('secret-expires');
    var copyBtn       = document.getElementById('secret-copy');
    var newBtn        = document.getElementById('secret-new');
    var formMessage   = document.getElementById('secret-form-message');
    var formSection   = document.getElementById('secret-form-section');
    var container     = document.querySelector('.secret-container');

    var MAX_FILE_SIZE = 1 * 1024 * 1024; // 1 Mo

    /* Afficher le nom du fichier + vérifier la taille immédiatement */
    if (fileInput && fileNameEl) {
      fileInput.addEventListener('change', function () {
        hideMsg();
        if (!fileInput.files.length) { fileNameEl.textContent = ''; return; }
        var file = fileInput.files[0];
        var sizeMB = (file.size / (1024 * 1024)).toFixed(2);
        if (file.size > MAX_FILE_SIZE) {
          fileNameEl.textContent = file.name + ' (' + sizeMB + ' Mo)';
          fileNameEl.classList.add('secret-file-error');
          showMsg('error', lbl('ErrorFileSize', 'File too large (max 1 MB)'));
          fileInput.value = ''; /* reset le champ */
        } else {
          fileNameEl.textContent = file.name + ' (' + sizeMB + ' Mo)';
          fileNameEl.classList.remove('secret-file-error');
        }
      });
    }

    function lbl(key, fallback) {
      return (container && container.dataset['lbl' + key]) || fallback;
    }
    function showMsg(type, text) {
      if (!formMessage) return;
      formMessage.textContent = text;
      formMessage.className = 'secret-form-message secret-msg-' + type;
      formMessage.style.display = 'block';
    }
    function hideMsg() { if (formMessage) formMessage.style.display = 'none'; }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      hideMsg();

      /* Vérifier le quota client */
      if (!checkQuota()) { updateQuotaDisplay(); return; }

      var content = contentInput.value.trim();
      var hasFile = fileInput && fileInput.files.length > 0;
      if (!content && !hasFile) { showMsg('error', lbl('ErrorEmpty', 'Please enter a secret')); return; }

      /* Vérifier taille fichier (max 2 Mo) */
      if (hasFile && fileInput.files[0].size > MAX_FILE_SIZE) {
        showMsg('error', lbl('ErrorFileSize', 'File too large (max 1 MB)'));
        return;
      }

      /* Token Turnstile */
      var tsWidget = form.querySelector('[name="cf-turnstile-response"]');
      var turnstileToken = tsWidget ? tsWidget.value : '';
      if (!turnstileToken) { showMsg('error', lbl('ErrorTurnstile', 'Security check failed')); return; }

      var originalText = submitBtn.textContent;
      submitBtn.disabled = true;
      submitBtn.textContent = lbl('BtnCreating', 'Encrypting…');
      submitBtn.classList.add('is-loading');

      try {
        /* 1. Générer le masterKey */
        var masterKey = generateMasterKey();

        /* 2. Construire le payload à chiffrer (JSON texte ou fichier) */
        var payload;
        if (hasFile) {
          /* Lire le fichier en base64 */
          var file = fileInput.files[0];
          var fileData = await new Promise(function (resolve) {
            var reader = new FileReader();
            reader.onload = function () { resolve(reader.result.split(',')[1]); }; /* base64 après data:...;base64, */
            reader.readAsDataURL(file);
          });
          payload = JSON.stringify({
            type: 'file',
            name: file.name,
            mime: file.type || 'application/octet-stream',
            data: fileData,
            text: content || '' /* texte optionnel accompagnant le fichier */
          });
        } else {
          payload = JSON.stringify({ type: 'text', content: content });
        }

        /* 3. Chiffrer le payload */
        var toEncrypt = payload;
        var userPassword = passwordInput ? passwordInput.value : '';
        if (userPassword) {
          toEncrypt = await encrypt(toEncrypt, userPassword);
        }
        var encrypted = await encrypt(toEncrypt, masterKey);

        /* 4. Envoyer au serveur (notifyEmail optionnel pour notification à la lecture) */
        var notifyEl = document.getElementById('secret-notify-email');
        var notifyEmail = notifyEl ? notifyEl.value.trim() : '';
        var resp = await fetch(API_BASE + '/secret/api/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            encrypted: encrypted,
            expiresIn: parseInt(expirationSel.value, 10),
            hasPassword: !!userPassword,
            notifyEmail: notifyEmail || undefined,
            turnstileToken: turnstileToken
          })
        });
        var data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Erreur API');

        /* 4. Construire le lien : https://<host>/#{id}:{masterKey}
              Le host est lu depuis data-secret-host sur .secret-container
              (défaut = location.host, utilise l'origine courante du site). */
        var secretHost = (container && container.dataset.secretHost) || window.location.host;
        var link = 'https://' + secretHost + '/#' + data.id + ':' + masterKey;

        recordCreate();
        updateQuotaDisplay();

        resultLink.value = link;
        if (data.expiresAt) {
          var d = new Date(data.expiresAt);
          resultExpires.textContent = lbl('ResultExpires', 'Expires:') + ' ' +
            d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
        }
        formSection.style.display = 'none';
        resultSection.style.display = 'block';

      } catch (err) {
        console.error('[secret] Erreur création:', err);
        var msg = err.message || '';
        if (msg.indexOf('429') !== -1 || msg.indexOf('Trop') !== -1) {
          showMsg('error', lbl('ErrorRate', 'Too many requests'));
        } else if (msg.indexOf('Turnstile') !== -1 || msg.indexOf('403') !== -1) {
          showMsg('error', lbl('ErrorTurnstile', 'Security check failed'));
        } else {
          showMsg('error', lbl('ErrorApi', 'Error creating secret') + ' [' + msg + ']');
        }
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
        submitBtn.classList.remove('is-loading');
        if (window.turnstile) window.turnstile.reset();
      }
    });

    /* Bouton Copier */
    if (copyBtn && resultLink) {
      copyBtn.addEventListener('click', function () {
        resultLink.select();
        navigator.clipboard.writeText(resultLink.value).then(function () {
          var original = copyBtn.textContent;
          copyBtn.textContent = lbl('ResultCopied', 'Copied!');
          setTimeout(function () { copyBtn.textContent = original; }, 1500);
        });
      });
    }

    /* Bouton Partager — Web Share API (même pattern que password generator) */
    var shareBtn = document.getElementById('secret-share');
    if (shareBtn && navigator.share) {
      shareBtn.style.display = '';
      shareBtn.addEventListener('click', function () {
        if (!resultLink || !resultLink.value) return;
        navigator.share({ text: resultLink.value }).catch(function () {});
      });
    }

    /* Bouton Nouveau */
    if (newBtn) {
      newBtn.addEventListener('click', function () {
        formSection.style.display = 'block';
        resultSection.style.display = 'none';
        contentInput.value = '';
        if (passwordInput) passwordInput.value = '';
        if (fileInput) { fileInput.value = ''; }
        if (fileNameEl) fileNameEl.textContent = '';
        hideMsg();
        updateQuotaDisplay();
      });
    }
  }

  /* ══════════════════════════════════════════════════════════════
     MODE 2 — PAGE REVEAL (/toolbox/secret/view/)
     Lit le fragment #{id}:{masterKey}, appelle /secret/api/reveal,
     déchiffre et affiche le secret. Le secret est détruit sur le serveur.
     ══════════════════════════════════════════════════════════════ */

  var revealContainer = document.getElementById('secret-reveal');
  if (revealContainer) initRevealMode();

  function initRevealMode() {
    /* Fix lang switcher : préserver le hash fragment lors du changement de langue.
       Sans ce fix, cliquer FR/EN/DE/LB dans la nav perd le #{id}:{masterKey}. */
    document.querySelectorAll('.lang-btn').forEach(function (btn) {
      if (btn.tagName === 'A' && btn.href) {
        btn.addEventListener('click', function (e) {
          e.preventDefault();
          /* Construire l'URL de la page reveal dans la nouvelle langue + hash actuel */
          var href = btn.getAttribute('href');
          var lang = btn.getAttribute('hreflang') || 'lb';
          var revealPath = '/' + lang + '/toolbox/secret/view/';
          window.location = revealPath + window.location.hash;
        });
      }
    });

    var revealBtn     = document.getElementById('reveal-btn');
    var confirmBox    = document.getElementById('reveal-confirm');
    var passwordWrap  = document.getElementById('reveal-password-wrap');
    var passwordInput = document.getElementById('reveal-password');
    var contentEl     = document.getElementById('reveal-content');
    var statusEl      = document.getElementById('reveal-status');
    var container     = document.querySelector('.secret-reveal-container');

    /* Checkbox de confirmation — le bouton Révéler est disabled tant que non cochée (2026-04-10) */
    if (confirmBox && revealBtn) {
      confirmBox.addEventListener('change', function () {
        revealBtn.disabled = !confirmBox.checked;
      });
    }

    function lbl(key, fallback) {
      return (container && container.dataset['lbl' + key]) || fallback;
    }

    /* Parser le fragment : #{id}:{masterKey} */
    var hash = window.location.hash.substring(1);
    var colonIdx = hash.indexOf(':');
    if (!hash || colonIdx === -1) {
      statusEl.textContent = lbl('RevealInvalid', 'Invalid or missing secret link');
      statusEl.className = 'reveal-status reveal-error';
      if (revealBtn) revealBtn.style.display = 'none';
      return;
    }
    var secretId  = hash.substring(0, colonIdx);
    var masterKey = hash.substring(colonIdx + 1);

    /* Bouton "Révéler le secret" */
    if (revealBtn) {
      revealBtn.addEventListener('click', async function () {
        revealBtn.disabled = true;
        revealBtn.textContent = lbl('RevealLoading', 'Decrypting…');
        revealBtn.classList.add('is-loading');
        statusEl.textContent = '';

        try {
          /* 1. Appeler le serveur pour récupérer le blob chiffré */
          var resp = await fetch(API_BASE + '/secret/api/reveal', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: secretId })
          });
          var data = await resp.json();

          if (resp.status === 404) {
            statusEl.textContent = lbl('RevealNotFound', 'This secret has already been read or does not exist.');
            statusEl.className = 'reveal-status reveal-error';
            revealBtn.style.display = 'none';
            return;
          }
          if (resp.status === 410) {
            statusEl.textContent = lbl('RevealExpired', 'This secret has expired.');
            statusEl.className = 'reveal-status reveal-error';
            revealBtn.style.display = 'none';
            return;
          }
          if (!resp.ok) throw new Error(data.error || 'Erreur');

          /* 2. Déchiffrer avec le masterKey */
          var decrypted = await decrypt(data.encrypted, masterKey);

          /* 3. Si double chiffrement (mot de passe), demander le mot de passe */
          if (data.hasPassword) {
            if (passwordWrap) passwordWrap.style.display = 'block';
            revealBtn.textContent = lbl('RevealUnlock', 'Unlock');
            revealBtn.disabled = false;
            revealBtn.classList.remove('is-loading');

            /* Remplacer le handler pour le 2e déchiffrement */
            revealBtn.onclick = async function () {
              var pwd = passwordInput ? passwordInput.value : '';
              if (!pwd) return;
              revealBtn.disabled = true;
              revealBtn.classList.add('is-loading');
              try {
                var final = await decrypt(decrypted, pwd);
                showSecret(final);
              } catch (e) {
                statusEl.textContent = lbl('RevealWrongPwd', 'Wrong password');
                statusEl.className = 'reveal-status reveal-error';
                revealBtn.disabled = false;
                revealBtn.classList.remove('is-loading');
              }
            };
            return;
          }

          /* Pas de mot de passe → afficher directement */
          showSecret(decrypted);

        } catch (e) {
          statusEl.textContent = lbl('RevealError', 'Error retrieving secret');
          statusEl.className = 'reveal-status reveal-error';
        } finally {
          revealBtn.classList.remove('is-loading');
        }
      });
    }

    /* Affiche le secret déchiffré — gère texte et fichier.
       Le payload déchiffré est un JSON : {type:'text', content:'...'} ou {type:'file', name, mime, data, text}.
       Pour la rétrocompatibilité, si le JSON ne parse pas, on affiche en texte brut. */
    function showSecret(decrypted) {
      if (revealBtn) revealBtn.style.display = 'none';
      if (passwordWrap) passwordWrap.style.display = 'none';
      statusEl.textContent = lbl('RevealDestroyed', 'This secret has been destroyed on the server.');
      statusEl.className = 'reveal-status reveal-success';

      var payload;
      try { payload = JSON.parse(decrypted); } catch (e) {
        /* Rétrocompatibilité : texte brut (anciens secrets) */
        contentEl.textContent = decrypted;
        contentEl.style.display = 'block';
        return;
      }

      /* Bouton Partager — Web Share API (texte uniquement, pas les fichiers) */
      var revealShareBtn = document.getElementById('reveal-share');
      if (revealShareBtn && navigator.share && payload.type !== 'file') {
        revealShareBtn.style.display = '';
        revealShareBtn.onclick = function () {
          navigator.share({ text: payload.content || decrypted }).catch(function () {});
        };
      }

      if (payload.type === 'file') {
        /* Fichier : preview si image + bouton download toujours */
        var fileWrap = document.getElementById('reveal-file');
        if (!fileWrap) { fileWrap = document.createElement('div'); fileWrap.id = 'reveal-file'; fileWrap.className = 'reveal-file'; contentEl.parentNode.insertBefore(fileWrap, contentEl); }
        var html = '';

        /* Texte accompagnant le fichier */
        if (payload.text) {
          html += '<pre class="reveal-content" style="display:block;margin-bottom:1rem">' +
            payload.text.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</pre>';
        }

        /* Preview image */
        var isImage = payload.mime && payload.mime.startsWith('image/');
        if (isImage) {
          html += '<img src="data:' + payload.mime + ';base64,' + payload.data +
            '" alt="' + (payload.name || 'image') + '" class="reveal-image">';
        }

        /* Bouton download (toujours) */
        html += '<a href="data:' + payload.mime + ';base64,' + payload.data +
          '" download="' + (payload.name || 'secret-file') +
          '" class="btn btn-primary reveal-download">' +
          lbl('RevealDownload', 'Download') + ' — ' + (payload.name || 'file') + '</a>';

        fileWrap.innerHTML = html;
        fileWrap.style.display = 'block';

      } else {
        /* Texte */
        contentEl.textContent = payload.content || decrypted;
        contentEl.style.display = 'block';
      }
    }
  }

})();
