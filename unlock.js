'use strict';

(() => {
  const form = document.getElementById('unlock-form');
  const passwordInput = document.getElementById('portfolio-password');
  const toggle = document.getElementById('toggle-password');
  const submit = document.getElementById('unlock-button');
  const buttonLabel = document.getElementById('button-label');
  const status = document.getElementById('access-status');
  const capsWarning = document.getElementById('caps-warning');
  let pending = false;

  const fromBase64 = value => Uint8Array.from(atob(value), character => character.charCodeAt(0));
  const normalizePath = value => value.replace(/^\.\//, '').replace(/^\//, '');
  const escapeRegExp = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  toggle.addEventListener('click', () => {
    const showing = passwordInput.type === 'password';
    passwordInput.type = showing ? 'text' : 'password';
    toggle.textContent = showing ? 'Hide' : 'Show';
    toggle.setAttribute('aria-label', showing ? 'Hide password' : 'Show password');
    toggle.setAttribute('aria-pressed', String(showing));
    passwordInput.focus();
  });

  for (const eventName of ['keyup', 'keydown']) {
    passwordInput.addEventListener(eventName, event => {
      capsWarning.hidden = !event.getModifierState('CapsLock');
    });
  }
  passwordInput.addEventListener('blur', () => { capsWarning.hidden = true; });
  passwordInput.addEventListener('input', () => {
    passwordInput.removeAttribute('aria-invalid');
    status.textContent = '';
  });

  async function decrypt(envelope, password) {
    if (envelope.version !== 1 || envelope.kdf !== 'PBKDF2' || envelope.hash !== 'SHA-256' ||
        envelope.cipher !== 'AES-256-GCM' || envelope.iterations !== 600000) {
      throw new Error('Unsupported encrypted portfolio.');
    }
    const salt = fromBase64(envelope.salt);
    const iv = fromBase64(envelope.iv);
    if (salt.byteLength !== 16 || iv.byteLength !== 12) throw new Error('Invalid encrypted portfolio.');
    const encoder = new TextEncoder();
    const encodedPassword = encoder.encode(password);
    let material;
    try {
      material = await crypto.subtle.importKey('raw', encodedPassword, 'PBKDF2', false, ['deriveKey']);
    } finally {
      encodedPassword.fill(0);
    }
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: envelope.iterations, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: encoder.encode('private-portfolio:v1'), tagLength: 128 },
      key, fromBase64(envelope.ciphertext)
    );
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    } finally {
      new Uint8Array(plaintext).fill(0);
    }
  }

  function mountPortfolio(payload) {
    if (payload.version !== 1 || typeof payload.html !== 'string' ||
        !Array.isArray(payload.styles) || !Array.isArray(payload.scripts) || !Array.isArray(payload.assets)) {
      throw new Error('Invalid portfolio data.');
    }
    const documentTree = new DOMParser().parseFromString(payload.html, 'text/html');
    const assetUrls = new Map();
    for (const asset of payload.assets) {
      const bytes = fromBase64(asset.base64);
      const url = URL.createObjectURL(new Blob([bytes], { type: asset.mime }));
      bytes.fill(0);
      assetUrls.set(asset.path, url);
    }
    const replaceAssetPaths = value => {
      let updated = value;
      for (const [path, url] of assetUrls) {
        // Only replace a whole local path; never a substring of an external URL.
        const escaped = escapeRegExp(path);
        updated = updated.replace(new RegExp(`(^|[\\s"'\x60(=:])(?:\\./|/)?${escaped}(?=$|[\\s"'\x60)<>?#])`, 'g'), (_, prefix) => prefix + url);
      }
      return updated;
    };
    for (const element of documentTree.querySelectorAll('[src],[href],[poster],[data-src]')) {
      for (const attribute of ['src', 'href', 'poster', 'data-src']) {
        const value = element.getAttribute(attribute);
        if (!value) continue;
        const [path, suffix = ''] = value.split(/(?=[?#])/);
        const blobUrl = assetUrls.get(normalizePath(path));
        if (blobUrl) {
          element.setAttribute(attribute, blobUrl + suffix);
          if (attribute === 'href' && element.hasAttribute('download') && !element.getAttribute('download')) {
            element.setAttribute('download', normalizePath(path).split('/').pop());
          }
        }
      }
    }
    for (const element of documentTree.querySelectorAll('[style]')) {
      element.setAttribute('style', replaceAssetPaths(element.getAttribute('style')));
    }
    for (const entry of payload.styles) {
      const matchingLink = Array.from(documentTree.querySelectorAll('link[rel="stylesheet"]'))
        .find(element => normalizePath(element.getAttribute('href') || '') === entry.path);
      const style = documentTree.createElement('style');
      style.textContent = replaceAssetPaths(entry.content).replace(/<\/style/gi, '<\\/style');
      if (matchingLink) matchingLink.replaceWith(style);
      else documentTree.head.append(style);
    }
    for (const style of documentTree.querySelectorAll('style')) {
      style.textContent = replaceAssetPaths(style.textContent).replace(/<\/style/gi, '<\\/style');
    }
    const scriptEntries = new Map(payload.scripts.map(entry => [entry.path, entry]));
    for (const matchingScript of Array.from(documentTree.querySelectorAll('script[src]'))) {
      const entry = scriptEntries.get(normalizePath(matchingScript.getAttribute('src') || ''));
      if (!entry) continue;
      const script = documentTree.createElement('script');
      if (matchingScript.type) script.type = matchingScript.type;
      script.textContent = replaceAssetPaths(entry.content).replace(/<\/script/gi, '<\\/script');
      matchingScript.remove();
      // Run local scripts in document order once all body elements exist.
      documentTree.body.append(script);
    }
    for (const metaName of ['referrer', 'robots']) {
      documentTree.querySelector(`meta[name="${metaName}"]`)?.remove();
    }
    const referrer = documentTree.createElement('meta');
    referrer.name = 'referrer';
    referrer.content = 'no-referrer';
    documentTree.head.append(referrer);
    const robots = documentTree.createElement('meta');
    robots.name = 'robots';
    robots.content = 'noindex,nofollow,noarchive';
    documentTree.head.append(robots);
    // No password, key, decrypted markup, or document is written to storage.
    // The next refresh requests the encrypted entry page and locks the portfolio.
    const html = '<!doctype html>\n' + documentTree.documentElement.outerHTML;
    document.open();
    document.write(html);
    document.close();
    window.scrollTo(0, 0);
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (pending) return;
    if (!passwordInput.value) {
      status.textContent = 'Enter your access password to continue.';
      passwordInput.setAttribute('aria-invalid', 'true');
      passwordInput.focus();
      return;
    }
    if (!window.isSecureContext || !window.crypto?.subtle) {
      status.textContent = 'Open this portfolio over HTTPS to unlock it securely.';
      return;
    }
    pending = true;
    submit.disabled = true;
    toggle.disabled = true;
    passwordInput.readOnly = true;
    form.setAttribute('aria-busy', 'true');
    status.textContent = '';
    buttonLabel.textContent = 'Opening portfolio…';
    let password = passwordInput.value;
    passwordInput.value = '';
    passwordInput.type = 'password';
    toggle.textContent = 'Show';
    toggle.setAttribute('aria-label', 'Show password');
    toggle.setAttribute('aria-pressed', 'false');
    try {
      let envelope;
      try {
        const response = await fetch(new URL('payload.enc', document.baseURI), { cache: 'no-store', credentials: 'omit' });
        if (!response.ok) throw new Error('Fetch failed');
        envelope = await response.json();
      } catch {
        status.textContent = 'The portfolio could not be loaded. Check your connection and try again.';
        return;
      }
      let payload;
      try {
        payload = await decrypt(envelope, password);
      } catch {
        status.textContent = 'That password did not unlock the portfolio. Please try again.';
        passwordInput.setAttribute('aria-invalid', 'true');
        return;
      }
      password = '';
      mountPortfolio(payload);
    } catch {
      status.textContent = 'The portfolio could not be opened. Refresh the page and try again.';
    } finally {
      password = '';
      passwordInput.value = '';
      pending = false;
      submit.disabled = false;
      toggle.disabled = false;
      passwordInput.readOnly = false;
      form.removeAttribute('aria-busy');
      buttonLabel.textContent = 'Enter portfolio';
      if (document.contains(passwordInput)) passwordInput.focus();
    }
  });
})();
