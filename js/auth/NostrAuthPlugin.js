// js/auth/NostrAuthPlugin.js
// Nostr authentication plugin using NIP-07, manual keys, or NIP-46

import { AuthPluginInterface } from './AuthPluginInterface.js';
import { client as nostrClient } from '../nostr.js';

export class NostrAuthPlugin extends AuthPluginInterface {
  constructor(config = {}) {
    super(config);
    this.name = 'nostr';
    this.displayName = 'Nostr';
    this.client = nostrClient;
    this.currentMethod = null; // 'nip07', 'manual', 'nip46'
  }

  async initialize() {
    console.log('[NostrAuth] Initializing Nostr auth plugin');
    // Auto-reconnect NIP-46 if previously connected
    try {
      const wasConnected = localStorage.getItem('nip46_connected');
      const savedPubkey = localStorage.getItem('nip46_connected_pubkey');
      if (wasConnected && savedPubkey) {
        // Auto-reconnect will be handled by bunker auto-reconnect logic
        this.currentMethod = 'nip46';
      }
    } catch (e) {
      console.debug('[NostrAuth] No previous NIP-46 session');
    }
  }

  async isLoggedIn() {
    return this.client.signer !== null && this.client.pubkey !== null;
  }

  async getIdentity() {
    if (!await this.isLoggedIn()) {
      return null;
    }

    return {
      pubkey: this.client.pubkey,
      method: this.currentMethod,
      displayName: this.getDisplayNameForPubkey(this.client.pubkey),
      provider: 'nostr',
      supports: {
        signing: true,
        eventCreation: true,
        directPublishing: true
      }
    };
  }

  async login(credentials = {}) {
    const { method = 'auto', nsec = null, bunkerURI = null } = credentials;

    try {
      let result;
      
      if (method === 'nip07' || (method === 'auto' && window.nostr)) {
        result = await this.client.login();
        this.currentMethod = 'nip07';
      } else if (method === 'manual' && nsec) {
        result = await this.client.loginWithNsec(nsec);
        this.currentMethod = 'manual';
      } else if (method === 'nip46' && bunkerURI) {
        result = await this.client.connectBunker(bunkerURI);
        this.currentMethod = 'nip46';
      } else if (method === 'auto') {
        // Fallback to generated key
        result = await this.client.login();
        this.currentMethod = 'local';
      } else {
        throw new Error('Invalid login method or missing credentials');
      }

      console.log(`[NostrAuth] Logged in via ${this.currentMethod}:`, result.pubkey);
      return {
        success: true,
        method: this.currentMethod,
        pubkey: result.pubkey,
        provider: 'nostr'
      };
    } catch (error) {
      console.error('[NostrAuth] Login failed:', error);
      throw error;
    }
  }

  async logout() {
    console.log('[NostrAuth] Logging out');
    
    // Clear bunker connection
    if (this.currentMethod === 'nip46' && this.client.signer?.close) {
      try {
        await this.client.signer.close();
      } catch (e) {
        console.warn('[NostrAuth] Error closing bunker connection:', e);
      }
    }

    await this.client.logout();
    this.currentMethod = null;
    
    // Clear all stored authentication data (matching auth.js logout function)
    try {
      localStorage.removeItem('nostr_sk_hex');
      localStorage.removeItem('nip46_connect_uri');
      localStorage.removeItem('nip46_client_sk_hex');
      localStorage.removeItem('nip46_connected');
      localStorage.removeItem('nip46_connected_pubkey');
      
      // Clear cookies (helper function from auth.js)
      this.deleteCookie('nostr_manual_nsec');
      
      // Clear session storage
      sessionStorage.removeItem('nostr_manual_nsec_plain');
    } catch (e) {
      console.warn('[NostrAuth] Error clearing stored data:', e);
    }
  }

  // Helper function for deleting cookies (from auth.js)
  deleteCookie(name) {
    try {
      document.cookie = name + '=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax';
    } catch (e) { /* ignore */ }
    try { localStorage.removeItem(name); } catch (e) { /* ignore */ }
  }

  async createEvent(eventData) {
    if (!await this.isLoggedIn()) {
      throw new Error('Not logged in to Nostr');
    }

    console.log('[NostrAuth] Creating event via Nostr client');
    
    // If eventData is already a formatted event (has kind, tags, etc.), use it directly
    // Otherwise, use the client.publish method which will format it
    if (eventData && eventData.kind && eventData.tags) {
      // Already formatted event, just sign and publish
      await this.client.initPool();
      const signed = await this.client.signer.signEvent(eventData);
      
      // Publish to relays
      const { Config } = await import('../config.js');
      const pubs = this.client.pool.publish(Config.relays, signed);
      
      if (Array.isArray(pubs)) {
        const timeout = 3000;
        const promises = pubs.map(pub => {
          if (!pub || typeof pub.on !== 'function') return Promise.resolve();
          return new Promise(resolve => {
            const timer = setTimeout(() => resolve(), timeout);
            const onOk = () => { clearTimeout(timer); resolve(true); };
            const onFailed = () => { clearTimeout(timer); resolve(false); };
            try {
              pub.on('ok', onOk);
              pub.on('failed', onFailed);
            } catch (e) {
              clearTimeout(timer);
              resolve();
            }
          });
        });
        await Promise.race(promises);
        await Promise.allSettled(promises);
      }
      
      return { signed };
    } else {
      // Raw event data, let client.publish handle formatting
      return await this.client.publish(eventData);
    }
  }

  async deleteEvent(eventId) {
    if (!await this.isLoggedIn()) {
      throw new Error('Not logged in to Nostr');
    }

    console.log('[NostrAuth] Deleting event via Nostr client:', eventId);
    
    const deleteEventData = {
      kind: 5,
      content: '',
      tags: [['e', eventId]],
      created_at: Math.floor(Date.now() / 1000)
    };

    if (!this.client.signer) {
      throw new Error('No signer available');
    }

    await this.client.initPool();
    const signed = await this.client.signer.signEvent(deleteEventData);

    // Publish delete event to relays
    const { Config } = await import('../config.js');
    const pubs = this.client.pool.publish(Config.relays, signed);
    
    if (Array.isArray(pubs)) {
      const timeout = 3000;
      const promises = pubs.map(pub => {
        if (!pub || typeof pub.on !== 'function') return Promise.resolve();
        return new Promise(resolve => {
          const timer = setTimeout(() => resolve(), timeout);
          const onOk = () => { clearTimeout(timer); resolve(true); };
          const onFailed = () => { clearTimeout(timer); resolve(false); };
          try {
            pub.on('ok', onOk);
            pub.on('failed', onFailed);
          } catch (e) {
            clearTimeout(timer);
            resolve();
          }
        });
      });
      await Promise.race(promises);
      await Promise.allSettled(promises);
    }

    return { signed };
  }

  updateAuthUI(elements) {
    const { whoami, btnLogin, btnLogout, btnNew, btnLoginMenu } = elements;
    
    if (this.isLoggedIn()) {
      // Show user info
      if (whoami && this.client.pubkey) {
        const shortPubkey = this.client.pubkey.slice(0, 32) + '...';
        const methodLabel = this.getMethodLabel(this.currentMethod);
        whoami.innerHTML = `
          <div>
            <div><strong>🔑 Nostr Identity (${methodLabel})</strong></div>
            <div>${this.getDisplayNameForPubkey(this.client.pubkey)}</div>
            <div>${shortPubkey}</div>
          </div>
        `;
      }
      
      // Hide login elements, show logout
      if (btnLoginMenu) btnLoginMenu.style.display = 'none';
      if (btnLogin) btnLogin.style.display = 'none';
      if (btnLogout) {
        btnLogout.style.display = 'inline-block';
        btnLogout.classList.remove('hidden');
      }
      if (btnNew) {
        btnNew.style.display = 'inline-block';
        btnNew.disabled = false;
        btnNew.title = 'Neuen Termin anlegen';
      }
    } else {
      // Show login elements, hide logout
      if (btnLoginMenu) btnLoginMenu.style.display = 'inline-block';
      if (btnLogout) btnLogout.style.display = 'none';
      if (whoami) whoami.textContent = '';
      if (btnNew) {
        btnNew.disabled = true;
        btnNew.title = 'Bitte zuerst einloggen';
      }
    }
  }

  setupUI(elements, onChange) {
    const { btnManual, btnNip07, btnBunker } = elements;

    // NIP-07 login
    if (btnNip07) {
      btnNip07.onclick = async () => {
        try {
          await this.login({ method: 'nip07' });
          if (onChange) onChange();
        } catch (error) {
          alert('NIP-07 Login fehlgeschlagen: ' + error.message);
        }
      };
    }

    // Manual nsec login
    if (btnManual) {
      btnManual.onclick = async () => {
        const nsec = prompt('Bitte nsec1... Key eingeben:');
        if (!nsec) return;
        
        try {
          await this.login({ method: 'manual', nsec });
          if (onChange) onChange();
        } catch (error) {
          alert('Manual Login fehlgeschlagen: ' + error.message);
        }
      };
    }

    // NIP-46 Bunker login - handled by bunker.js setupBunkerUI()
    // Removed onclick handler to avoid conflicts with bunker.js
  }

  async getPublicKey() {
    return this.client.pubkey;
  }

  async getDisplayName() {
    return this.getDisplayNameForPubkey(this.client.pubkey);
  }

  supports(feature) {
    switch (feature) {
      case 'signing':
      case 'event_creation':
      case 'direct_publishing':
        return true;
      case 'server_side_publishing':
        return false;
      default:
        return false;
    }
  }

  getPriority() {
    return 10; // Standard priority for Nostr auth
  }

  // Helper methods
  getMethodLabel(method) {
    switch (method) {
      case 'nip07': return 'Extension';
      case 'manual': return 'Manual Key';
      case 'nip46': return 'Bunker';
      case 'local': return 'Generated';
      default: return 'Unknown';
    }
  }

  getDisplayNameForPubkey(pubkey) {
    if (!pubkey) return 'Unknown';
    
    // Check cache first for performance
    try {
      const cached = localStorage.getItem(`author_name:${pubkey}`);
      if (cached && cached !== 'null') {
        return cached;
      }
    } catch (e) {
      // ignore cache errors
    }
    
    // convert to bech32 npub for better readability  
    const npub = this.hexToNpub(pubkey);
    if (npub) return npub.slice(0, 32) + '...';
    return `nostr:${pubkey.slice(0, 8)}...`;
  }

  // Helper function to convert hex to npub
  hexToNpub(hex) {
    if (!hex || !/^[0-9a-f]{64}$/i.test(hex)) return null;
    try {
      const bytes = hex.match(/.{1,2}/g).map(h => parseInt(h, 16));
      const words = this.toWords(bytes);
      return this.bech32Encode('npub', words);
    } catch {
      return null;
    }
  }

  // Minimal bech32 helpers
  toWords(bytes) {
    let acc = 0, bits = 0;
    const words = [];
    for (let i = 0; i < bytes.length; i++) {
      acc = (acc << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        words.push((acc >> bits) & 31);
      }
    }
    if (bits > 0) words.push((acc << (5 - bits)) & 31);
    return words;
  }

  bech32Encode(hrp, data) {
    const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    const combined = data.concat(this.createChecksum(hrp, data));
    let out = hrp + '1';
    for (let i = 0; i < combined.length; i++) out += CHARSET.charAt(combined[i]);
    return out;
  }

  createChecksum(hrp, data) {
    const values = this.hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const polymod = this.polymod(values) ^ 1;
    const res = [];
    for (let p = 0; p < 6; ++p) res.push((polymod >> (5 * (5 - p))) & 31);
    return res;
  }

  hrpExpand(hrp) {
    const out = [];
    for (let i = 0; i < hrp.length; ++i) out.push(hrp.charCodeAt(i) >> 5);
    out.push(0);
    for (let i = 0; i < hrp.length; ++i) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }

  polymod(values) {
    const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (let p = 0; p < values.length; ++p) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ values[p];
      for (let i = 0; i < 5; ++i) if ((top >> i) & 1) chk ^= G[i];
    }
    return chk;
  }

  async destroy() {
    await this.logout();
  }
}