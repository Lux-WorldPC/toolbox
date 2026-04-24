/**
 * Password Generator — @lwpc/toolbox (MIT)
 * Ajouté 2026-04-08. Dernière mise à jour : 2026-04-10.
 *
 * 100% client-side : aucun appel réseau, aucun cookie.
 * Seul stockage : sessionStorage (3 clés) pour persister l'état entre rechargements
 * de page (ex: changement de langue du site via la nav) :
 *   - 'pwgen-mode' : mode classique/passphrase
 *   - 'pwgen-tab'  : onglet actif (generate/test)
 *   - 'secret_prefill' : transitoire — mdp envoyé vers /toolbox/secret/ (lu + supprimé par secret-tools.js)
 * Crypto-safe : utilise exclusivement crypto.getRandomValues() (jamais Math.random()).
 *
 * Ce fichier est chargé via Hugo resources pipeline (minifié + fingerprinted).
 * ⚠ Après modification, supprimer resources/ et rebuild (Hugo cache les assets).
 *
 * Étape 1 : squelette UI (onglets, switch mode).
 * Étape 2 : générateur classique (crypto, slider, toggles, copier, coloration).
 * Étape 3 : indicateur de force (entropie, barre, temps de crack).
 * Étape 4 : mode passphrase + wordlists (4 langues, 2048 mots chacune).
 * Étape 5 : testeur de mot de passe (calcTestEntropy, conseils, common-passwords).
 * Étape 6 : QR code — ANNULÉE (iOS Safari envoie le texte dans la recherche Google).
 * Étape 7 : polish (responsive ≤600px, accessibilité WAI-ARIA, animations, focus-visible).
 *
 * Ajouts 2026-04-09 :
 *   - sessionStorage('pwgen-mode') : persiste le mode classique/passphrase
 *   - sessionStorage('pwgen-tab') : persiste l'onglet actif (generate/test)
 *   - syncModeUI() : synchronise boutons + sections avec classList.add/remove + style.display
 *   - Option "Toutes les langues" (value="all") : concatène les 4 wordlists (8192 mots)
 *   - Langue par défaut = langue du site (data-site-lang sur .pwgen-container)
 *   - Détails de crack dans <details> dépliable (masqués par défaut)
 *   - Testeur : calcTestEntropy(), updateTestAdvice(), debounce 150ms, common-passwords.js
 *   - Bouton Partager : Web Share API (navigator.share), masqué si non supporté
 *   - Onglets WAI-ARIA : tabindex dynamique, navigation clavier flèches/Home/End
 *   - Barres de force : role="progressbar" (dans le template HTML)
 *   - CSS : focus-visible, transitions, scale au clic, responsive ≤600px
 *
 * Ajouts 2026-04-10 :
 *   - Bouton "Envoyer en secret" (#pwgen-send-secret) : stocke le mdp dans
 *     sessionStorage('secret_prefill') et redirige vers /{lang}/toolbox/secret/.
 *     La page secret lit secret_prefill, pré-remplit le textarea, supprime la clé.
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════════
     CHARSETS — jeux de caractères pour le mode classique.
     Ambiguous : caractères visuellement confusibles (0/O, l/1/I, etc.).
     Quand "exclure ambigus" est coché, ces caractères sont retirés des pools.
     ══════════════════════════════════════════════════════════════ */
  var UPPER       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var LOWER       = 'abcdefghijklmnopqrstuvwxyz';
  var DIGITS      = '0123456789';
  var SYMBOLS     = '!@#$%^&*()-_=+[]{}|;:,.<>?/~';
  var AMBIGUOUS   = '0OolI1|';

  /* ══════════════════════════════════════════════════════════════
     CRYPTO — génération aléatoire sécurisée.
     cryptoRandom(max) : retourne un entier dans [0, max) uniformément distribué.
     Utilise crypto.getRandomValues() avec rejection sampling pour éviter le biais modulo.
     ══════════════════════════════════════════════════════════════ */
  function cryptoRandom(max) {
    if (max <= 0) return 0;
    var arr = new Uint32Array(1);
    /* Rejection sampling : on rejette les valeurs >= limit pour garantir
       une distribution uniforme. limit = plus grand multiple de max ≤ 2^32. */
    var limit = Math.floor(0x100000000 / max) * max;
    do {
      crypto.getRandomValues(arr);
    } while (arr[0] >= limit);
    return arr[0] % max;
  }

  /* ══════════════════════════════════════════════════════════════
     GENERATE — génère un mot de passe classique.
     Construit le pool de caractères selon les toggles actifs.
     Garantit qu'au moins un caractère de chaque catégorie activée est présent
     (Fisher-Yates shuffle après injection d'un caractère obligatoire par catégorie).
     ══════════════════════════════════════════════════════════════ */
  function generateClassic() {
    var length     = parseInt(lengthSlider.value, 10);
    var useUpper   = upperCb.checked;
    var useLower   = lowerCb.checked;
    var useDigits  = digitsCb.checked;
    var useSymbols = symbolsCb.checked;
    var excludeAmb = excludeAmbCb.checked;

    /* Construire le pool */
    var pool = '';
    var required = []; // un caractère obligatoire par catégorie activée
    if (useUpper)   pool += UPPER;
    if (useLower)   pool += LOWER;
    if (useDigits)  pool += DIGITS;
    if (useSymbols) pool += SYMBOLS;

    /* Rien de coché → fallback lowercase */
    if (pool === '') {
      pool = LOWER;
      lowerCb.checked = true;
    }

    /* Retirer les caractères ambigus si demandé */
    if (excludeAmb) {
      pool = pool.split('').filter(function (c) { return AMBIGUOUS.indexOf(c) === -1; }).join('');
    }

    if (pool.length === 0) return '';

    /* Garantir au moins un caractère par catégorie activée.
       On pioche un caractère obligatoire dans chaque sous-pool activé.
       Ces caractères seront placés aux premières positions puis mélangés. */
    function pickFrom(charset) {
      var filtered = excludeAmb
        ? charset.split('').filter(function (c) { return AMBIGUOUS.indexOf(c) === -1; }).join('')
        : charset;
      if (filtered.length === 0) return null;
      return filtered[cryptoRandom(filtered.length)];
    }
    if (useUpper)   { var c = pickFrom(UPPER);   if (c) required.push(c); }
    if (useLower)   { var c = pickFrom(LOWER);   if (c) required.push(c); }
    if (useDigits)  { var c = pickFrom(DIGITS);  if (c) required.push(c); }
    if (useSymbols) { var c = pickFrom(SYMBOLS); if (c) required.push(c); }

    /* Générer le reste du mot de passe */
    var result = [];
    for (var i = 0; i < required.length && i < length; i++) {
      result.push(required[i]);
    }
    for (var i = result.length; i < length; i++) {
      result.push(pool[cryptoRandom(pool.length)]);
    }

    /* Shuffle Fisher-Yates pour mélanger les caractères obligatoires */
    for (var i = result.length - 1; i > 0; i--) {
      var j = cryptoRandom(i + 1);
      var tmp = result[i];
      result[i] = result[j];
      result[j] = tmp;
    }

    return result.join('');
  }

  /* ══════════════════════════════════════════════════════════════
     PASSPHRASE — génère une passphrase à partir d'une wordlist.

     Wordlists chargées en global par les fichiers wordlist-{lang}.js :
       window.WORDLIST_FR, window.WORDLIST_EN, window.WORDLIST_DE, window.WORDLIST_LB
     Chaque liste contient 2048 mots (11 bits d'entropie par mot).

     Paramètres (lus depuis les éléments DOM) :
       - Nombre de mots : slider 3-10 (défaut 4)
       - Séparateur : -, espace, ., _, ou chiffre aléatoire
       - Capitaliser : première lettre de chaque mot en majuscule
       - Ajouter chiffre : un chiffre 0-9 aléatoire à la fin

     L'affichage alterne les couleurs des mots pour les distinguer visuellement
     (classes .pw-word-a / .pw-word-b).
     ══════════════════════════════════════════════════════════════ */

  /* Récupère la wordlist pour la langue sélectionnée.
     "all" = concaténation des 4 listes (8192 mots, 13 bits d'entropie par mot).
     Les doublons inter-langues sont conservés (impact négligeable sur l'entropie). */
  function getWordlist() {
    var langSelect = document.getElementById('pwgen-lang');
    var lang = langSelect ? langSelect.value : 'en';
    var lists = {
      fr: window.WORDLIST_FR,
      en: window.WORDLIST_EN,
      de: window.WORDLIST_DE,
      lb: window.WORDLIST_LB
    };
    if (lang === 'all') {
      return [].concat(lists.fr || [], lists.en || [], lists.de || [], lists.lb || []);
    }
    return lists[lang] || lists['en'] || [];
  }

  function generatePassphrase() {
    var wordlist = getWordlist();
    if (wordlist.length === 0) return '';

    var numWords    = parseInt(wordsSlider.value, 10);
    var sepSelect   = document.getElementById('pwgen-separator');
    var sepValue    = sepSelect ? sepSelect.value : '-';
    var capitalize  = document.getElementById('pwgen-capitalize');
    var addDigit    = document.getElementById('pwgen-add-digit');
    var doCap       = capitalize && capitalize.checked;
    var doDigit     = addDigit && addDigit.checked;

    /* Piocher numWords mots aléatoires dans la wordlist */
    var words = [];
    for (var i = 0; i < numWords; i++) {
      var word = wordlist[cryptoRandom(wordlist.length)];
      if (doCap) word = word.charAt(0).toUpperCase() + word.slice(1);
      words.push(word);
    }

    /* Construire le séparateur */
    var sep = sepValue;
    if (sepValue === 'random') {
      /* Chiffre aléatoire différent entre chaque mot */
      var result = words[0];
      for (var i = 1; i < words.length; i++) {
        result += String(cryptoRandom(10)) + words[i];
      }
      if (doDigit) result += String(cryptoRandom(10));
      return result;
    }

    var result = words.join(sep);
    if (doDigit) result += String(cryptoRandom(10));
    return result;
  }

  /* Variables pour le calcul d'entropie passphrase (utilisées par calcEntropy) */
  var passphraseEntropy = 0;

  /* Calcul d'entropie passphrase — appelé juste avant generate pour stocker le résultat.
     E = words × log2(wordlistSize)
     Bonus séparateur "random" : + (words-1) × log2(10) (un chiffre entre chaque mot)
     Bonus chiffre final : + log2(10) ≈ 3.32 bits */
  function calcPassphraseEntropy() {
    var wordlist = getWordlist();
    if (wordlist.length === 0) return 0;
    var numWords   = parseInt(wordsSlider.value, 10);
    var sepSelect  = document.getElementById('pwgen-separator');
    var sepValue   = sepSelect ? sepSelect.value : '-';
    var addDigit   = document.getElementById('pwgen-add-digit');
    var doDigit    = addDigit && addDigit.checked;

    var entropy = numWords * Math.log2(wordlist.length);
    if (sepValue === 'random') entropy += (numWords - 1) * Math.log2(10);
    if (doDigit) entropy += Math.log2(10);
    return entropy;
  }

  /* ══════════════════════════════════════════════════════════════
     DISPLAY — affichage avec coloration syntaxique.
     Mode classique — chaque caractère enveloppé dans un <span> :
       .pw-letter : lettres majuscules et minuscules (couleur texte standard)
       .pw-digit  : chiffres (bleu en light, jaune en dark)
       .pw-symbol : symboles (orange #e67e22 en light, #f39c12 en dark)
     Mode passphrase — couleurs alternées par mot (ajouté étape 4) :
       .pw-word-a : mots pairs (bleu / blue-xl en dark)
       .pw-word-b : mots impairs (couleur texte standard)
       Séparateurs : .pw-digit (chiffres) ou .pw-symbol (ponctuation)
     escapeHtml() protège contre l'injection HTML (ex: < > &).
     ══════════════════════════════════════════════════════════════ */
  function displayPassword(pw) {
    if (!pw) {
      displayEl.innerHTML = '';
      return;
    }

    /* Mode passphrase : alterner les couleurs des mots (.pw-word-a / .pw-word-b)
       pour les distinguer visuellement. Les séparateurs gardent la couleur symbol. */
    if (currentMode === 'passphrase') {
      var sepSelect = document.getElementById('pwgen-separator');
      var sepValue  = sepSelect ? sepSelect.value : '-';
      /* Déterminer le séparateur réel pour le split (random = chiffre → on split par chiffre) */
      var html = '';
      var wordIdx = 0;
      var inWord = true;
      for (var i = 0; i < pw.length; i++) {
        var c = pw[i];
        var isLetter = /[a-zA-ZÀ-ÿ]/.test(c);
        if (isLetter) {
          var cls = (wordIdx % 2 === 0) ? 'pw-word-a' : 'pw-word-b';
          html += '<span class="' + cls + '">' + escapeHtml(c) + '</span>';
          inWord = true;
        } else {
          if (inWord) wordIdx++;
          inWord = false;
          var cls = /[0-9]/.test(c) ? 'pw-digit' : 'pw-symbol';
          html += '<span class="' + cls + '">' + escapeHtml(c) + '</span>';
        }
      }
      displayEl.innerHTML = html;
      return;
    }

    /* Mode classique : coloration par type de caractère */
    var html = '';
    for (var i = 0; i < pw.length; i++) {
      var c = pw[i];
      var cls = 'pw-letter';
      if (/[0-9]/.test(c))          cls = 'pw-digit';
      else if (/[^a-zA-Z0-9]/.test(c)) cls = 'pw-symbol';
      html += '<span class="' + cls + '">' + escapeHtml(c) + '</span>';
    }
    displayEl.innerHTML = html;
  }

  /* Échapper les caractères HTML pour éviter l'injection */
  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  /* ══════════════════════════════════════════════════════════════
     COPY — copie dans le presse-papier avec feedback visuel.
     Utilise navigator.clipboard.writeText() (API moderne).
     Feedback : le texte du bouton change brièvement en "Copié !" / "Copied!".
     ══════════════════════════════════════════════════════════════ */
  function copyToClipboard() {
    if (!currentPassword) return;
    navigator.clipboard.writeText(currentPassword).then(function () {
      var original = copyBtn.textContent;
      copyBtn.textContent = copyBtn.dataset.copied;
      copyBtn.classList.add('pwgen-btn-copied');
      setTimeout(function () {
        copyBtn.textContent = original;
        copyBtn.classList.remove('pwgen-btn-copied');
      }, 1500);
    });
  }

  /* ══════════════════════════════════════════════════════════════
     STRENGTH — calcul d'entropie et estimation du temps de crack.

     Entropie (mode classique) :
       E = length × log2(poolSize)
       poolSize = taille du jeu de caractères effectif (après exclusion ambigus).

     Entropie (mode passphrase — étape 4) :
       E = words × log2(wordlistSize)
       Bonus : +log2(separatorOptions) si séparateur aléatoire,
               +log2(10) si chiffre final ajouté.

     Temps de crack :
       T = 2^E / (2 × vitesse)  (facteur 2 = moyenne brute-force, moitié de l'espace)
       Trois niveaux de vitesse documentés :
         - Online       :          1 000 essais/s (serveur limité)
         - GPU puissant : 10 000 000 000 essais/s (10 Mrd, ex: hashcat sur RTX 4090)
         - Supercomputer: 1 000 000 000 000 essais/s (1 000 Mrd, cluster national)
     ══════════════════════════════════════════════════════════════ */

  /* Calcul taille du pool effectif pour le mode classique */
  function getPoolSize() {
    var size = 0;
    var excludeAmb = excludeAmbCb && excludeAmbCb.checked;
    if (upperCb && upperCb.checked)   size += excludeAmb ? UPPER.split('').filter(function(c){ return AMBIGUOUS.indexOf(c)===-1; }).length : UPPER.length;
    if (lowerCb && lowerCb.checked)   size += excludeAmb ? LOWER.split('').filter(function(c){ return AMBIGUOUS.indexOf(c)===-1; }).length : LOWER.length;
    if (digitsCb && digitsCb.checked) size += excludeAmb ? DIGITS.split('').filter(function(c){ return AMBIGUOUS.indexOf(c)===-1; }).length : DIGITS.length;
    if (symbolsCb && symbolsCb.checked) size += excludeAmb ? SYMBOLS.split('').filter(function(c){ return AMBIGUOUS.indexOf(c)===-1; }).length : SYMBOLS.length;
    return size || LOWER.length; // fallback lowercase
  }

  /* Calcul entropie en bits — pour les mots de passe GÉNÉRÉS.
     Utilise le pool effectif (mode classique) ou l'entropie pré-calculée (mode passphrase). */
  function calcEntropy(password) {
    if (!password || password.length === 0) return 0;
    if (currentMode === 'classic') {
      var poolSize = getPoolSize();
      return password.length * Math.log2(poolSize);
    }
    /* Mode passphrase : entropie pré-calculée par calcPassphraseEntropy() */
    return passphraseEntropy;
  }

  /* Calcul entropie en bits — pour les mots de passe TESTÉS (étape 5, ajouté 2026-04-09).
     Contrairement à calcEntropy(), on détecte les classes de caractères PRÉSENTES
     dans le mot de passe au lieu de lire l'état des toggles du générateur.
     Pool : minuscules (26) + majuscules (26) + chiffres (10) + symboles (32). */
  function calcTestEntropy(password) {
    if (!password || password.length === 0) return 0;
    var poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;
    if (poolSize === 0) return 0;
    return password.length * Math.log2(poolSize);
  }

  /* Formatage du temps de crack de façon lisible.
     Reçoit un nombre de secondes, retourne une chaîne humaine.
     Échelle : secondes → minutes → heures → jours → années → millions → milliards d'années. */
  function formatTime(seconds) {
    if (seconds < 0.001)       return '< 1 ms';
    if (seconds < 1)           return '< 1 s';
    if (seconds < 60)          return Math.round(seconds) + ' s';
    if (seconds < 3600)        return Math.round(seconds / 60) + ' min';
    if (seconds < 86400)       return Math.round(seconds / 3600) + ' h';
    if (seconds < 31536000)    return Math.round(seconds / 86400) + ' j';
    var years = seconds / 31536000;
    if (years < 1000)          return Math.round(years) + ' ans';
    if (years < 1e6)           return Math.round(years / 1000) + ' milliers d\'ans';
    if (years < 1e9)           return Math.round(years / 1e6) + ' millions d\'ans';
    if (years < 1e12)          return Math.round(years / 1e9) + ' milliards d\'ans';
    return '> 1 000 milliards d\'ans';
  }

  /* Niveaux de force — correspondance entropie → pourcentage barre + couleur.
     Labels lus depuis data-lbl-* sur .pwgen-container (i18n, injectés par Hugo). */
  function getStrengthLevel(entropy) {
    var c = document.querySelector('.pwgen-container');
    var lbl = function(key, fallback) { return (c && c.dataset['lbl' + key]) || fallback; };
    /* Seuils : <28 très faible, 28-35 faible, 36-59 moyen, 60-127 fort, 128+ très fort */
    if (entropy < 28)  return { pct: 10,  color: '#e74c3c', label: lbl('VeryWeak', 'Very weak') };
    if (entropy < 36)  return { pct: 25,  color: '#e67e22', label: lbl('Weak', 'Weak') };
    if (entropy < 60)  return { pct: 50,  color: '#f1c40f', label: lbl('Medium', 'Medium') };
    if (entropy < 128) return { pct: 75,  color: '#27ae60', label: lbl('Strong', 'Strong') };
    return              { pct: 100, color: '#2ecc71', label: lbl('VeryStrong', 'Very strong') };
  }

  /* Met à jour l'indicateur de force (barre + détails textuels).
     fillEl  : la div .pwgen-strength-fill à animer (width + background).
     detailsEl : la div .pwgen-strength-details pour le texte.
     entropyOverride : si fourni (nombre), utilise cette valeur au lieu de calcEntropy().
       → Utilisé par le testeur (étape 5) qui calcule l'entropie via calcTestEntropy().
     Appelé à chaque génération et à chaque frappe dans le testeur. */
  function updateStrength(password, fillEl, detailsEl, entropyOverride) {
    if (!fillEl || !detailsEl) return;

    var entropy = (typeof entropyOverride === 'number') ? entropyOverride : calcEntropy(password);
    var level = getStrengthLevel(entropy);

    /* Animer la barre */
    fillEl.style.width = level.pct + '%';
    fillEl.style.background = level.color;

    if (!password || password.length === 0) {
      fillEl.style.width = '0%';
      detailsEl.innerHTML = '';
      return;
    }

    /* Temps de crack sur 3 niveaux.
       Hypothèses de vitesse de brute-force :
         ONLINE_SPEED  =          1 000 essais/s — serveur web avec rate limiting
         GPU_SPEED     = 10 000 000 000 essais/s — GPU haut de gamme (hashcat, bcrypt rapide)
         SUPER_SPEED   = 1 000 000 000 000 essais/s — cluster de supercalculateurs */
    var ONLINE_SPEED = 1e3;
    var GPU_SPEED    = 1e10;
    var SUPER_SPEED  = 1e12;

    /* Espace de recherche = 2^entropy. Moyenne brute-force = espace / 2. */
    var space = Math.pow(2, entropy);
    var tOnline = space / (2 * ONLINE_SPEED);
    var tGpu    = space / (2 * GPU_SPEED);
    var tSuper  = space / (2 * SUPER_SPEED);

    /* Récupérer les labels i18n depuis les data-attributes du conteneur */
    var container = document.querySelector('.pwgen-container');
    var lblEntropy      = (container && container.dataset.lblEntropy)      || 'bits of entropy';
    var lblOnline       = (container && container.dataset.lblOnline)       || 'Online attack (1,000/s)';
    var lblGpu          = (container && container.dataset.lblGpu)          || 'Powerful GPU (10 Bn/s)';
    var lblSuper        = (container && container.dataset.lblSuper)        || 'Supercomputers (1,000 Bn/s)';
    var lblCrackDetails = (container && container.dataset.lblCrackDetails) || 'Crack time details';

    /* Ligne principale : niveau + entropie (toujours visible).
       Détails du crack : dans un <details> dépliable, masqué par défaut (ajouté 2026-04-09). */
    detailsEl.innerHTML =
      '<strong>' + level.label + '</strong> — ' + Math.round(entropy) + ' ' + lblEntropy +
      '<details class="pwgen-crack-details"><summary>' + lblCrackDetails + '</summary>' +
      lblOnline + ' : ' + formatTime(tOnline) + '<br>' +
      lblGpu + ' : ' + formatTime(tGpu) + '<br>' +
      lblSuper + ' : ' + formatTime(tSuper) +
      '</details>';
  }

  /* ══════════════════════════════════════════════════════════════
     MAIN — initialisation et événements.
     ══════════════════════════════════════════════════════════════ */
  var currentPassword = '';
  /* Mode classique/passphrase — persisté dans sessionStorage (ajouté 2026-04-09).
     Quand l'utilisateur change la langue du site (LB/FR/EN/DE dans la nav),
     le navigateur charge une nouvelle page (/fr/toolbox/password/ → /de/toolbox/password/).
     Sans persistance, le mode revient toujours à 'classic' au rechargement.
     sessionStorage conserve la valeur pendant la session du navigateur. */
  var currentMode = sessionStorage.getItem('pwgen-mode') || 'classic';

  /* Éléments DOM */
  var displayEl    = document.getElementById('pwgen-display');
  var copyBtn      = document.getElementById('pwgen-copy');
  var regenBtn     = document.getElementById('pwgen-regenerate');
  var lengthSlider = document.getElementById('pwgen-length');
  var lengthVal    = document.getElementById('pwgen-length-val');
  var wordsSlider  = document.getElementById('pwgen-words');
  var wordsVal     = document.getElementById('pwgen-words-val');
  var upperCb      = document.getElementById('pwgen-upper');
  var lowerCb      = document.getElementById('pwgen-lower');
  var digitsCb     = document.getElementById('pwgen-digits');
  var symbolsCb    = document.getElementById('pwgen-symbols');
  var excludeAmbCb = document.getElementById('pwgen-exclude-ambiguous');

  var strengthFill    = document.getElementById('pwgen-strength-fill');
  var strengthDetails = document.getElementById('pwgen-strength-details');

  if (!displayEl) return; // page sans générateur

  /* Stocker le texte "Copié !" depuis l'attribut data pour i18n */
  if (copyBtn) {
    copyBtn.dataset.copied = copyBtn.dataset.copied || 'Copied!';
  }

  /* ── Fonction principale : génère, affiche, évalue la force, et synchronise le mode UI ── */
  function generate() {
    if (currentMode === 'classic') {
      currentPassword = generateClassic();
    } else if (currentMode === 'passphrase') {
      passphraseEntropy = calcPassphraseEntropy();
      currentPassword = generatePassphrase();
    }
    displayPassword(currentPassword);
    updateStrength(currentPassword, strengthFill, strengthDetails);
    syncModeUI();
  }

  /* ── Onglets Générer / Tester ───────────────────────────── */
  /* Onglet actif persisté dans sessionStorage('pwgen-tab') (ajouté 2026-04-09).
     Même mécanisme que sessionStorage('pwgen-mode') pour le mode classique/passphrase :
     quand l'utilisateur change la langue du site, la page recharge et l'onglet est restauré. */
  var tabs = document.querySelectorAll('.pwgen-tab');
  var panels = document.querySelectorAll('.pwgen-panel');

  /* switchTab : bascule l'onglet actif + gère tabindex pour la navigation clavier.
     L'onglet actif a tabindex=0, les inactifs tabindex=-1 (pattern WAI-ARIA tabs). */
  function switchTab(target) {
    tabs.forEach(function (t) {
      var isActive = t.dataset.tab === target;
      t.classList.toggle('active', isActive);
      t.setAttribute('aria-selected', isActive ? 'true' : 'false');
      t.setAttribute('tabindex', isActive ? '0' : '-1');
    });
    panels.forEach(function (p) {
      p.classList.toggle('active', p.dataset.panel === target);
    });
  }

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      var target = tab.dataset.tab;
      switchTab(target);
      try { sessionStorage.setItem('pwgen-tab', target); } catch (e) {}
    });
  });

  /* Navigation clavier sur les onglets — flèches gauche/droite (WAI-ARIA tabs pattern, étape 7).
     La touche Home va au premier onglet, End au dernier. */
  document.querySelector('.pwgen-tabs').addEventListener('keydown', function (e) {
    var tabArray = Array.prototype.slice.call(tabs);
    var idx = tabArray.indexOf(document.activeElement);
    if (idx === -1) return;
    var newIdx = -1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') newIdx = (idx + 1) % tabArray.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') newIdx = (idx - 1 + tabArray.length) % tabArray.length;
    else if (e.key === 'Home') newIdx = 0;
    else if (e.key === 'End') newIdx = tabArray.length - 1;
    if (newIdx !== -1) {
      e.preventDefault();
      var target = tabArray[newIdx].dataset.tab;
      switchTab(target);
      tabArray[newIdx].focus();
      try { sessionStorage.setItem('pwgen-tab', target); } catch (ex) {}
    }
  });

  /* Restaurer l'onglet actif depuis sessionStorage */
  var savedTab = sessionStorage.getItem('pwgen-tab');
  if (savedTab) switchTab(savedTab);

  /* ── Switch Classique / Passphrase ──────────────────────── */
  var modeBtns = document.querySelectorAll('.pwgen-mode-btn');
  var controlSections = document.querySelectorAll('.pwgen-controls');

  /* Synchronise l'UI (boutons mode + sections contrôles) avec currentMode.
     Utilise classList.add/remove + style.display direct (belt-and-suspenders)
     pour contourner un bug Safari où classList.toggle + CSS .active
     peut se désynchroniser après interaction avec un <select>.
     Intégré dans generate() pour garantie systématique. */
  function syncModeUI() {
    modeBtns.forEach(function (b) {
      if (b.dataset.mode === currentMode) {
        b.classList.add('active');
      } else {
        b.classList.remove('active');
      }
    });
    controlSections.forEach(function (s) {
      if (s.dataset.controls === currentMode) {
        s.classList.add('active');
        s.style.display = 'flex';
      } else {
        s.classList.remove('active');
        s.style.display = 'none';
      }
    });
  }

  modeBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      currentMode = btn.dataset.mode;
      try { sessionStorage.setItem('pwgen-mode', currentMode); } catch (e) {}
      syncModeUI();
      generate();
    });
  });

  /* ── Slider longueur — valeur affichée + regénération ──── */
  if (lengthSlider && lengthVal) {
    lengthSlider.addEventListener('input', function () {
      lengthVal.textContent = lengthSlider.value;
      generate();
    });
  }

  /* ── Slider mots (passphrase) — valeur affichée ─────────── */
  if (wordsSlider && wordsVal) {
    wordsSlider.addEventListener('input', function () {
      wordsVal.textContent = wordsSlider.value;
      generate();
    });
  }

  /* ── Toggles classique — regénération à chaque changement ── */
  [upperCb, lowerCb, digitsCb, symbolsCb, excludeAmbCb].forEach(function (cb) {
    if (cb) cb.addEventListener('change', generate);
  });

  /* ── Contrôles passphrase — regénération à chaque changement ── */
  ['pwgen-separator', 'pwgen-lang'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', generate);
  });
  ['pwgen-capitalize', 'pwgen-add-digit'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', generate);
  });

  /* ── Boutons Copier / Générer / Partager ─────────────────── */
  if (copyBtn)  copyBtn.addEventListener('click', copyToClipboard);
  if (regenBtn) regenBtn.addEventListener('click', generate);

  /* ── Bouton Partager — Web Share API (ajouté 2026-04-09) ── */
  /* Utilise navigator.share() pour ouvrir le menu de partage natif (iOS/Android/macOS).
     Le mot de passe est envoyé en texte brut via le champ `text` — il ne passe pas
     par une URL et n'apparaît pas dans l'historique du navigateur.
     Le bouton est masqué par défaut (style="display:none" dans le HTML) et affiché
     uniquement si navigator.share est disponible (détection feature). */
  var shareBtn = document.getElementById('pwgen-share');
  if (shareBtn && navigator.share) {
    shareBtn.style.display = '';
    shareBtn.addEventListener('click', function () {
      if (!currentPassword) return;
      navigator.share({ text: currentPassword }).catch(function () {});
    });
  }

  /* ── Envoyer en secret — redirige vers /toolbox/secret/ avec le mdp en sessionStorage (2026-04-10).
     Le mot de passe est stocké dans sessionStorage('secret_prefill') que la page secret lit au chargement.
     sessionStorage = même onglet, même origine, pas persisté entre sessions. */
  var sendSecretBtn = document.getElementById('pwgen-send-secret');
  if (sendSecretBtn) {
    sendSecretBtn.addEventListener('click', function () {
      if (!currentPassword) return;
      sessionStorage.setItem('secret_prefill', currentPassword);
      /* Naviguer vers la page secret dans la langue courante */
      var c = document.querySelector('.pwgen-container');
      var lang = (c && c.dataset.siteLang) || 'lb';
      location.href = '/' + lang + '/toolbox/secret/';
    });
  }

  /* ── Étape 6 (QR Code) — ANNULÉE (2026-04-09).
     Raison : iOS Safari interprète le texte brut du QR comme une recherche Google,
     ce qui envoie le mot de passe dans l'historique de recherche — risque de sécurité.
     Le bouton QR, le modal, la librairie qrcode.min.js et le CSS associé ont été retirés. ── */

  /* ── Eye toggle (testeur) ───────────────────────────────── */
  var eyeBtn = document.getElementById('pwgen-eye');
  var testInput = document.getElementById('pwgen-test-input');
  if (eyeBtn && testInput) {
    eyeBtn.addEventListener('click', function () {
      var isPassword = testInput.type === 'password';
      testInput.type = isPassword ? 'text' : 'password';
      eyeBtn.querySelector('.pwgen-eye-icon').textContent = isPassword ? '🙈' : '👁';
    });
  }

  /* ══════════════════════════════════════════════════════════════
     TESTEUR — analyse d'un mot de passe existant (étape 5, ajouté 2026-04-09).

     Fonctionnement :
       - L'utilisateur tape ou colle un mot de passe dans #pwgen-test-input
       - À chaque frappe (debounce 150ms), on calcule l'entropie via calcTestEntropy()
       - La barre de force est mise à jour via updateStrength() avec entropyOverride
       - Des conseils contextuels sont affichés si le mot de passe est faible
       - Vérification contre window.COMMON_PASSWORDS (top 200, chargé par common-passwords.js)

     i18n : les labels des conseils sont lus depuis data-lbl-advice-* sur .pwgen-container
     (injectés par Hugo depuis les clés pwgen_advice_* des fichiers i18n).
     ══════════════════════════════════════════════════════════════ */

  /* Affiche des conseils contextuels sous la barre de force du testeur */
  function updateTestAdvice(password) {
    var adviceEl = document.getElementById('pwgen-test-advice');
    if (!adviceEl) return;
    if (!password || password.length === 0) { adviceEl.innerHTML = ''; return; }

    var container = document.querySelector('.pwgen-container');
    var lbl = function (key, fallback) {
      return (container && container.dataset['lblAdvice' + key]) || fallback;
    };

    var tips = [];
    /* Mot de passe courant — priorité critique */
    if (window.COMMON_PASSWORDS && window.COMMON_PASSWORDS.indexOf(password.toLowerCase()) !== -1) {
      tips.push('<div class="pwgen-advice-item pwgen-advice-critical">' + lbl('Common', 'Very common password — change it immediately') + '</div>');
    }
    if (password.length < 16) {
      tips.push('<div class="pwgen-advice-item">' + lbl('Short', 'Too short — aim for at least 16 characters') + '</div>');
    }
    if (!/[^a-zA-Z0-9]/.test(password)) {
      tips.push('<div class="pwgen-advice-item">' + lbl('Symbols', 'Add symbols for extra strength') + '</div>');
    }
    if (!/[0-9]/.test(password)) {
      tips.push('<div class="pwgen-advice-item">' + lbl('Digits', 'No digits detected') + '</div>');
    }
    adviceEl.innerHTML = tips.join('');
  }

  /* Éléments DOM du testeur + listener debounced */
  var testFillEl    = document.getElementById('pwgen-test-strength-fill');
  var testDetailsEl = document.getElementById('pwgen-test-strength-details');
  var testDebounce  = null;

  if (testInput) {
    testInput.addEventListener('input', function () {
      clearTimeout(testDebounce);
      testDebounce = setTimeout(function () {
        var pw = testInput.value;
        var entropy = calcTestEntropy(pw);
        updateStrength(pw, testFillEl, testDetailsEl, entropy);
        updateTestAdvice(pw);
      }, 150);
    });
  }

  /* ── Langue par défaut du sélecteur wordlist (ajouté 2026-04-09) ──── */
  /* data-site-lang sur .pwgen-container = langue Hugo courante (lb, fr, en, de),
     injecté par le template single.html via {{ .Site.Language.Lang }}.
     On pré-sélectionne cette langue dans le select #pwgen-lang au chargement.
     Exemple : sur /lb/toolbox/password/ → data-site-lang="lb" → Lëtzebuergesch sélectionné.
     Note : .value = ... ne déclenche PAS l'événement 'change' (pas de regénération). */
  (function initLangDefault() {
    var container = document.querySelector('.pwgen-container');
    var langSelect = document.getElementById('pwgen-lang');
    if (!container || !langSelect) return;
    var siteLang = container.dataset.siteLang;
    if (siteLang) {
      var opt = langSelect.querySelector('option[value="' + siteLang + '"]');
      if (opt) langSelect.value = siteLang;
    }
  })();

  /* ── Restauration du mode + génération initiale (mis à jour 2026-04-09) ── */
  /* syncModeUI() applique le mode restauré depuis sessionStorage :
     - Boutons mode (.pwgen-mode-btn) : .active sur le bon bouton
     - Sections contrôles (.pwgen-controls) : .active + style.display sur la bonne section
     generate() produit un mot de passe initial et appelle aussi syncModeUI() en sortie. */
  syncModeUI();
  generate();

})();
