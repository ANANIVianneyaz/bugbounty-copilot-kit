(function () {
  var form    = document.getElementById('report-form');
  var success = document.getElementById('report-success');
  if (!form || !success) return;

  var isEn = document.documentElement.lang === 'en';

  // Hidden until the account check confirms this visitor may submit. The check
  // is asynchronous, so leaving it visible would briefly present a usable form
  // to someone with no account.
  form.style.display = 'none';

  // ── Programme pause check ─────────────────────────────────────────────────
  fetch('/api/aarme/stats')
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.paused) {
        var banner = document.getElementById('pause-banner');
        var btn    = form.querySelector('button[type="submit"]');
        if (banner) banner.style.display = 'block';
        if (btn)    btn.disabled = true;
      }
    })
    .catch(function () {});

  // ── Account gate ──────────────────────────────────────────────────────────
  // Submitting requires a signed-in, identity-verified account, so the gate is
  // the session rather than whatever address someone types into the form.
  var ACCT_URL = isEn ? '/en/account/' : '/compte/';
  var KYC_MSGS = {
    not_signed_in: {
      title: isEn ? 'Account required' : 'Compte requis',
      body:  isEn
        ? 'Submitting a report requires an AarMe account. Create one or sign in, then come back here.'
        : "Soumettre un rapport nécessite un compte AarMe. Créez-en un ou connectez-vous, puis revenez ici.",
    },
    kyc_required: {
      title: isEn ? 'Identity verification pending' : "Vérification d'identité en attente",
      body:  isEn
        ? 'Your account exists but your identity is not verified yet. Upload your documents from your account: they are encrypted on arrival and destroyed once a decision is recorded. Verification within 24-48 business hours.'
        : "Votre compte existe mais votre identité n'est pas encore vérifiée. Déposez vos documents depuis votre compte : ils sont chiffrés dès leur arrivée et détruits dès qu'une décision est prise. Vérification sous 24 à 48 heures ouvrées.",
    },
    // Reponse UNIQUE du serveur, qu'il n'existe aucun compte pour cette adresse
    // ou qu'il en existe un non valide. Les deux cas partagent ce message : en
    // distinguer deux ferait de l'endpoint de soumission un oracle d'existence
    // de comptes, alors que les pseudonymes sont deja publics. Le texte doit
    // donc rester vrai dans les deux situations, et ne rien affirmer sur
    // l'existence du compte.
    identity_required: {
      title: isEn ? 'Validated identity required' : "Identité validée requise",
      body:  isEn
        ? 'Reports are accepted only from researchers whose identity has been validated. Create an account if you do not have one, then upload your documents: they are encrypted on arrival and destroyed once a decision is recorded. Verification within 24-48 business hours.'
        : "Les rapports ne sont acceptés que de chercheurs dont l'identité a été validée. Créez un compte si vous n'en avez pas, puis déposez vos documents : ils sont chiffrés dès leur arrivée et détruits dès qu'une décision est prise. Vérification sous 24 à 48 heures ouvrées.",
    },
  };

  function _showKycBanner(type) {
    var banner = document.getElementById('kyc-banner');
    var title  = document.getElementById('kyc-banner-title');
    var body   = document.getElementById('kyc-banner-body');
    var msg    = KYC_MSGS[type];
    if (!banner || !msg) return;
    if (title) title.textContent = msg.title;
    if (body) {
      body.textContent = msg.body + ' ';
      var a = document.createElement('a');
      a.href = ACCT_URL;
      a.textContent = (type === 'not_signed_in')
        ? (isEn ? 'Create an account or sign in \u2192' : 'Cr\u00e9er un compte ou se connecter \u2192')
        : (isEn ? 'Go to my account \u2192' : 'Aller \u00e0 mon compte \u2192');
      a.style.cssText = 'display:inline-block;margin-top:.75rem;padding:.6rem 1.25rem;'
        + 'background:var(--accent);color:#080d1a;font-weight:700;border-radius:8px;'
        + 'font-size:.9375rem;text-decoration:none;';
      body.appendChild(document.createElement('br'));
      body.appendChild(a);
    }
    banner.style.display = 'block';
    // Hide the form outright rather than only disabling the button: filling in a
    // long vulnerability report and only then being told an account is required
    // wastes the researcher's work.
    form.style.display = 'none';
  }

  function _hideKycBanner() {
    var banner = document.getElementById('kyc-banner');
    if (banner) banner.style.display = 'none';
    form.style.display = 'flex';
    var btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = false;
  }

  function _checkAccount() {
    fetch('/api/aarme/account/session', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (me) { return me && me.authenticated ? me : null; })
      .then(function (me) {
        if (!me) { _showKycBanner('not_signed_in'); return; }
        if (!(me.kyc && me.kyc.outcome === 'approved')) { _showKycBanner('kyc_required'); return; }
        // Verified: the address is the account's, not something to be typed.
        var emailEl = document.getElementById('email');
        if (emailEl && me.email) {
          emailEl.value = me.email;
          emailEl.readOnly = true;
          emailEl.style.opacity = '.7';
        }
        var nameEl = document.getElementById('name');
        if (nameEl && !nameEl.value && me.display_name) nameEl.value = me.display_name;
        _hideKycBanner();
      })
      .catch(function () { /* API unreachable: leave the form as rendered */ });
  }

  _checkAccount();

  // ── Severity visual picker ────────────────────────────────────────────────
  var sevOpts = document.querySelectorAll('.sev-opt');
  var sevInput = document.getElementById('severity');

  sevOpts.forEach(function (btn) {
    btn.addEventListener('click', function () {
      sevOpts.forEach(function (b) { b.removeAttribute('data-selected'); });
      btn.setAttribute('data-selected', 'true');
      if (sevInput) sevInput.value = btn.getAttribute('data-sev') || '';
      clearErr('severity');
    });
  });

  // ── File upload display ───────────────────────────────────────────────────
  var attachEl    = document.getElementById('attachment');
  var attachLabel = document.getElementById('attach-label');
  var defaultAttachText = isEn ? 'Drag a file here or click to browse' : 'Glisser un fichier ici ou cliquer pour parcourir';
  if (attachEl && attachLabel) {
    attachEl.addEventListener('change', function () {
      attachLabel.textContent = (this.files && this.files[0])
        ? this.files[0].name
        : defaultAttachText;
    });
  }

  // ── Error helpers ─────────────────────────────────────────────────────────
  var MSGS = {
    name:        isEn ? 'Name is required'                 : 'Nom obligatoire',
    email:       isEn ? 'Email is required'                : 'Email obligatoire',
    emailBad:    isEn ? 'Invalid email address'            : 'Adresse email invalide',
    target:      isEn ? 'Target URL or endpoint is required' : 'URL ou endpoint concerné obligatoire',
    asset:       isEn ? 'Choose the programme and asset your report concerns' : 'Choisissez le programme et l\'actif concernés par votre rapport',
    assetLoad:   isEn ? 'The programme list could not be loaded: reload the page.' : 'La liste des programmes n\'a pas pu être chargée : rechargez la page.',
    category:    isEn ? 'Category is required'             : 'Catégorie obligatoire',
    severity:    isEn ? 'Please select a severity level'   : 'Veuillez sélectionner une sévérité',
    title:       isEn ? 'Title is required'                : 'Titre obligatoire',
    description: isEn ? 'Description is required'         : 'Description obligatoire',
    steps:       isEn ? 'Steps to reproduce are required'  : 'Étapes de reproduction obligatoires',
    attachBig:   isEn ? 'File must be under 5 MB'          : 'Le fichier doit faire moins de 5 Mo',
    attachType:  isEn ? 'The report must be a PDF' : 'Le rapport doit être un PDF',
    attachReq:   isEn ? 'A PDF report is required (reproduction steps and screenshots)' : 'Un rapport PDF est obligatoire (étapes de reproduction et captures d\'écran)',
    fail: isEn
      ? 'An error occurred. Please try again or email security@cyberaar.io'
      : 'Une erreur est survenue. Réessayez ou écrivez-nous à security@cyberaar.io',
  };

  function g(id) { var el = document.getElementById(id); return el ? el.value.trim() : ''; }

  // ── Programme and asset (2026-10-07) ──────────────────────────────────────
  // The list comes from the server's programme registry, so a new programme
  // appears here without a site change. ?programme= and ?asset= preselect; a
  // target naming an asset preselects it while the choice is still empty.
  var ASSETS = [];
  (function loadAssets() {
    var sel = document.getElementById('asset');
    if (!sel) return;
    var qs = new URLSearchParams(location.search);
    fetch('/api/aarme/programmes', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
      .then(function (d) {
        var progs = (d && d.programmes) || [];
        sel.innerHTML = '';
        var ph = document.createElement('option');
        ph.value = ''; ph.textContent = isEn ? 'Choose...' : 'Choisir...';
        sel.appendChild(ph);
        progs.forEach(function (p) {
          var og = document.createElement('optgroup');
          og.label = (isEn ? 'Programme ' : 'Programme ') + p.name;
          (p.assets || []).forEach(function (a) {
            var o = document.createElement('option');
            o.value = a.key;
            o.textContent = a.name + ' (' + (a.match && a.match[0] || '') + ')';
            og.appendChild(o);
            ASSETS.push({ key: a.key, programme: p.key, match: a.match || [] });
          });
          sel.appendChild(og);
        });
        var want = qs.get('asset');
        if (!want && qs.get('programme')) {
          var ofProg = ASSETS.filter(function (a) { return a.programme === qs.get('programme'); });
          if (ofProg.length === 1) want = ofProg[0].key;
        }
        if (want && ASSETS.some(function (a) { return a.key === want; })) sel.value = want;
        guessAsset();
      })
      .catch(function () {
        sel.innerHTML = '';
        var o = document.createElement('option');
        o.value = ''; o.textContent = MSGS.assetLoad;
        sel.appendChild(o);
      });
  })();
  var assetTouched = false;
  function guessAsset() {
    var sel = document.getElementById('asset');
    if (!sel || assetTouched || sel.value) return;
    var t = (g('target') || '').toLowerCase(), best = null;
    var re = /(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(\/[^\s,;"'<>)]*)?/g, m;
    while (!best && (m = re.exec(t))) {
      if (m.index && t.charAt(m.index - 1) === '@') continue;
      var cand = (m[1] + (m[2] || '')).replace(/\/+$/, '');
      ASSETS.forEach(function (a) {
        a.match.forEach(function (mt) {
          if ((cand === mt || cand.indexOf(mt + '/') === 0 || cand.indexOf(mt + '?') === 0)
              && (!best || mt.length > best.len)) best = { key: a.key, len: mt.length };
        });
      });
    }
    if (best) sel.value = best.key;
  }
  document.addEventListener('input', function (ev) {
    if (ev.target && ev.target.id === 'target') guessAsset();
  });
  document.addEventListener('change', function (ev) {
    if (ev.target && ev.target.id === 'asset') assetTouched = true;
  });

  function setErr(id, msg) {
    var el = document.getElementById(id);
    if (el) el.style.borderColor = '#ff6b6b';
    var errEl = document.getElementById(id + '-err');
    if (!errEl) {
      errEl = document.createElement('p');
      errEl.id = id + '-err';
      errEl.style.cssText = 'color:#ff6b6b;font-size:.875rem;margin-top:.25rem;margin-bottom:0;';
      if (el) el.parentNode.appendChild(errEl);
    }
    if (errEl) errEl.textContent = msg;
  }

  function clearErr(id) {
    var el = document.getElementById(id);
    if (el) el.style.borderColor = '';
    var errEl = document.getElementById(id + '-err');
    if (errEl) errEl.textContent = '';
  }

  ['name','email','target','asset','category','title','description','steps','impact','proof','attachment','collaborators'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) {
      el.addEventListener('change', function () { clearErr(id); });
      el.addEventListener('input',  function () { clearErr(id); });
    }
  });

  // A PDF report is required since 2026-10-05: reviewers replay from it.
  var ALLOWED_TYPES = ['application/pdf'];
  var MAX_BYTES = 5 * 1024 * 1024;

  form.addEventListener('submit', function (e) {
    e.preventDefault();

    ['name','email','target','asset','category','severity','title','description','steps','attachment'].forEach(function(id) { clearErr(id); });

    var valid = true;
    if (!g('name')) { setErr('name', MSGS.name); valid = false; }
    var email = g('email');
    if (!email) {
      setErr('email', MSGS.email); valid = false;
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setErr('email', MSGS.emailBad); valid = false;
    }
    if (!g('target'))      { setErr('target',      MSGS.target);      valid = false; }
    if (!g('asset'))       { setErr('asset',       MSGS.asset);       valid = false; }
    if (!g('category'))    { setErr('category',    MSGS.category);    valid = false; }
    if (!g('severity'))    { setErr('severity',    MSGS.severity);    valid = false; }
    if (!g('title'))       { setErr('title',       MSGS.title);       valid = false; }
    if (!g('description')) { setErr('description', MSGS.description); valid = false; }
    if (!g('steps'))       { setErr('steps',       MSGS.steps);       valid = false; }

    var attachFile = attachEl && attachEl.files && attachEl.files[0];
    if (!attachFile) { setErr('attachment', MSGS.attachReq); valid = false; }
    if (attachFile) {
      if (attachFile.size > MAX_BYTES)                      { setErr('attachment', MSGS.attachBig);  valid = false; }
      else if (ALLOWED_TYPES.indexOf(attachFile.type) < 0)  { setErr('attachment', MSGS.attachType); valid = false; }
    }

    if (!valid) return;

    var btn = form.querySelector('button[type="submit"]');
    var originalTxt = btn.textContent;
    btn.disabled    = true;
    btn.textContent = isEn ? 'Sending...' : 'Envoi...';

    function submit(attachmentRef) {
      fetch('/api/aarme/report', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name:           g('name'),
          email:          email,
          target:         g('target'),
          asset:          g('asset'),
          category:       g('category'),
          severity:       g('severity'),
          title:          g('title'),
          description:    g('description'),
          steps:          g('steps'),
          impact:         g('impact'),
          proof:          g('proof'),
          attachment_ref: attachmentRef || '',
          collaborators:  g('collaborators'),
          lang:           isEn ? 'en' : 'fr',
          hp:             g('hp'),
        }),
      })
        .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
        .then(function (res) {
          if (res.status === 200) {
            form.style.display    = 'none';
            success.style.display = 'block';
            // Show tracking ref if returned
            var refEl = document.getElementById('success-ref');
            if (refEl && res.body && res.body.ref) {
              refEl.textContent = res.body.ref;
            }
            success.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          } else if (res.body && (res.body.error === 'asset_required' || res.body.error === 'invalid_asset')) {
            btn.disabled    = false;
            btn.textContent = originalTxt;
            setErr('asset', MSGS.asset);
          } else if (res.body && res.body.error === 'programme_paused') {
            btn.disabled    = false;
            btn.textContent = originalTxt;
            var banner = document.getElementById('pause-banner');
            if (banner) banner.style.display = 'block';
          } else if (res.status === 401) {
            // The submitter is the signed-in account; the server ignores the
            // address in the form. Signed out means nothing to submit as.
            _showKycBanner('not_signed_in');
          } else if (res.body && (res.body.error === 'identity_required'
                              || res.body.error === 'kyc_required'
                              || res.body.error === 'not_registered')) {
            btn.disabled    = false;
            btn.textContent = originalTxt;
            _showKycBanner(res.body.error);
          } else if (res.body && res.body.error === 'invalid_collaborators') {
            // Name the handles that were refused, but never the reason: the
            // server deliberately does not distinguish "no such handle" from
            // "identity not validated", so neither can the UI.
            btn.disabled    = false;
            btn.textContent = originalTxt;
            var bad = (res.body.handles || []).join(', ');
            setErr('collaborators', isEn
              ? (bad ? 'Cannot be used as co-researchers: ' + bad
                     + '. Each one needs an AarMe account with a validated identity.'
                     : 'Check the co-researcher nicknames.')
              : (bad ? 'Inutilisables comme co-chercheurs : ' + bad
                     + '. Chacun doit avoir un compte AarMe avec une identite validee.'
                     : 'Verifiez les pseudonymes des co-chercheurs.'));
          } else if (res.body && res.body.error === 'too_many_collaborators') {
            btn.disabled    = false;
            btn.textContent = originalTxt;
            setErr('collaborators', isEn
              ? 'At most ' + (res.body.maximum || 3) + ' co-researchers.'
              : 'Au maximum ' + (res.body.maximum || 3) + ' co-chercheurs.');
          } else if (res.body && res.body.error === 'sanctioned') {
            // A measure in force on the account (or on this programme). The
            // decision and its dates are on the account page, with the appeal.
            var until = res.body.until ? new Date(res.body.until).toLocaleDateString(isEn ? 'en-GB' : 'fr-FR') : '';
            _showErr(btn, originalTxt, isEn
              ? 'A measure in force on your account prevents submissions' + (until ? ' until ' + until : '')
                + '. The decision and how to appeal it are on your account page.'
              : 'Une mesure en vigueur sur votre compte empêche les soumissions' + (until ? ' jusqu\u2019au ' + until : '')
                + '. La décision et le moyen d\u2019en faire appel sont sur la page de votre compte.');
          } else if (res.body && res.body.error === 'totp_required') {
            _showErr(btn, originalTxt, isEn
              ? 'Turn on two-factor authentication in your account before submitting a report.'
              : "Activez la double authentification dans votre compte avant de soumettre un rapport.");
          } else if (res.body && res.body.error === 'pdf_required') {
            btn.disabled    = false;
            btn.textContent = originalTxt;
            setErr('attachment', MSGS.attachReq);
          } else if (res.body && res.body.error === 'rate_limited') {
            btn.disabled    = false;
            btn.textContent = originalTxt;
            _showErr(btn, originalTxt, isEn
              ? 'Too many reports submitted today. Please try again tomorrow.'
              : "Trop de rapports soumis aujourd'hui. Réessayez demain.");
          } else {
            _showErr(btn, originalTxt, null);
          }
        })
        .catch(function () { _showErr(btn, originalTxt, null); });
    }

    if (attachFile) {
      btn.textContent = isEn ? 'Uploading file...' : 'Envoi du fichier...';
      var fd = new FormData();
      fd.append('file', attachFile);
      fetch('/api/aarme/attachment', { method: 'POST', body: fd })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, data: j }; }); })
        .then(function (r) {
          btn.textContent = isEn ? 'Sending...' : 'Envoi...';
          if (r.ok && r.data.ref) { submit(r.data.ref); }
          else { _showErr(btn, originalTxt, null); }
        })
        .catch(function () { _showErr(btn, originalTxt, null); });
    } else {
      submit(null);
    }
  });

  function _showErr(btn, originalTxt, customMsg) {
    btn.disabled    = false;
    btn.textContent = originalTxt;
    var errEl = document.getElementById('report-error');
    if (errEl) { errEl.textContent = customMsg || MSGS.fail; errEl.style.display = 'block'; }
  }
}());
