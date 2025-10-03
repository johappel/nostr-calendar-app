// js/nostr.js

// Nostr helpers: auth, fetch, publish (NIP-52: kind 31923)
import { Config } from './config.js';
import { uid, b64 } from './utils.js';
import { hexToBytes, bytesToHex, npubToHex, nsecToHex, pickFastestRelay, diagSign } from './nostr-utils.js';
import { BunkerManager } from './bunker.js';
import { clearUploadCache } from './blossom.js';


let tools = null;
let poolMod = null;



// ---- dyn. load
async function loadTools() {
  // Try primary CDN (esm.sh). If it fails (network/CORS), fall back to alternative CDN URLs.
  const cdnAlternatives = {
    pure: [
      'https://esm.sh/nostr-tools@2.8.1/pure',
      'https://cdn.jsdelivr.net/npm/nostr-tools@2.8.1/esm/pure.js',
      'https://unpkg.com/nostr-tools@2.8.1/esm/pure.js'

      
    ],
    pool: [
      'https://esm.sh/nostr-tools@2.8.1/pool',
      'https://cdn.jsdelivr.net/npm/nostr-tools@2.8.1/esm/pool.js',
      'https://unpkg.com/nostr-tools@2.8.1/esm/pool.js'
    ]
  };

  async function tryImport(list, validate) {
    let lastErr = null;
    for (const url of list) {
      try {
        const mod = await import(url);
        try { mod.__srcURL = url; } catch {}
        if (validate) {
          const ok = validate(mod);
          if (!ok) {
            console.warn('[loadTools] imported module missing expected shape for', url);
            lastErr = new Error('module missing expected exports');
            continue;
          }
        }
        console.info('[loadTools] loaded module from', url);
        return mod;
      } catch (e) {
        lastErr = e;
        console.debug('[loadTools] import failed for', url, e && (e.message || e));
        // try next
      }
    }
    // throw the last error for visibility
    throw lastErr || new Error('dynamic import failed for all candidates');
  }

  if (!tools) {
    try {
      tools = await tryImport(cdnAlternatives.pure);
    } catch (e) {
      console.error('[loadTools] failed to load nostr-tools pure module:', e);
      throw e;
    }
  }

  if (!poolMod) {
    try {
      poolMod = await tryImport(cdnAlternatives.pool);
    } catch (e) {
      console.error('[loadTools] failed to load nostr-tools pool module:', e);
      throw e;
    }
  }

  return { tools, poolMod };
}

export class NostrClient {
  constructor() {
    this.pool = null;
    this.signer = null; // { type: 'nip07' | 'local' | 'nip46', getPublicKey, signEvent }
    this.pubkey = null;

    // Speed helpers (memo)
    this.fastRelay = null;         // gemessener schnellster Relay
    this.fastProbeAt = 0;          // timestamp der letzten Messung
    this.fastProbeTTL = 5 * 60e3;  // 5 Minuten Cache

    // Bunker-Manager für Bunker-spezifische Funktionalität
    this.bunker = new BunkerManager(this);
  }

  // Methode für Bunker-Zugriff
  async _loadTools() {
    return loadTools();
  }

  // ---- Pool init (versch. Export-Namen unterstützen)
  async initPool() {
    if (!this.pool) {
      await loadTools();
      const PoolCls = poolMod.SimplePool || poolMod.default || poolMod.SimplePoolClass || poolMod.Simplepool || poolMod.Pool;
      if (!PoolCls) throw new Error('SimplePool class not found in nostr-tools/pool');
      this.pool = new PoolCls();
    }
  }

  

  // ---- Listen über Pool (robust, mit Timeout + API-Varianten)
  async listFromPool(relays, filter, timeoutMs = 3500) {
    const f = Array.isArray(filter) ? filter : [filter];
    const p = this.pool;
    if (!p) throw new Error('Pool not initialized');
    const timeout = new Promise((resolve) => setTimeout(() => resolve('__TIMEOUT__'), timeoutMs));

    // A) SimplePool#list(relays, filters[])
    if (typeof p.list === 'function') {
      try {
        const res = await Promise.race([p.list(relays, f), timeout]);
        if (res === '__TIMEOUT__') throw new Error('pool.list timeout');
        return res || [];
      } catch (e) { console.warn('pool.list failed', e); }
    }

    // B) SimplePool#query(relays, filter) → async iterator
    if (typeof p.query === 'function') {
      try {
        const out = [];
        const it = p.query(relays, f.length === 1 ? f[0] : f);
        const gather = (async () => { if (it && typeof it[Symbol.asyncIterator] === 'function') { for await (const ev of it) { out.push(ev); } } return out; })();
        const res = await Promise.race([gather, timeout]);
        try { it?.close?.(); } catch { }
        return Array.isArray(res) ? res : out;
      } catch (e) { console.warn('pool.query failed', e); }
    }

    // C) subscribeMany-Fallback
    if (typeof p.subscribeMany === 'function') {
      return await new Promise((resolve) => {
        const out = []; const seen = new Set(); let eoseCount = 0; const target = relays.length; let resolved = false;
        const sub = p.subscribeMany(relays, f, {
          onevent: (ev) => { if (ev?.id && !seen.has(ev.id)) { seen.add(ev.id); out.push(ev); } },
          oneose: () => { eoseCount++; if (!resolved && eoseCount >= target) { resolved = true; try { sub.close(); } catch { } resolve(out); } }
        });
        setTimeout(() => { if (!resolved) { resolved = true; try { sub.close(); } catch { } resolve(out); } }, timeoutMs);
      });
    }

    throw new Error('Unsupported pool API: no list/query/subscribeMany');
  }

  // ---- RAW-WebSocket: sammelt Events aus N Relays, löst erst wenn alle zu sind
  async listByWebSocket(relays, filter, timeoutMs = 4000) {
    return await new Promise((resolve) => {
      const subId = 'sub-' + Math.random().toString(36).slice(2, 10);
      const byId = new Map(); let openCount = 0; let done = false;
      const timer = setTimeout(() => finish(), timeoutMs);
      function finish() { if (done) return; done = true; clearTimeout(timer); resolve([...byId.values()]); }
      (relays || []).forEach((url) => {
        try {
          const ws = new WebSocket(url);
          ws.addEventListener('open', () => { openCount++; ws.send(JSON.stringify(['REQ', subId, filter])); });
          ws.addEventListener('message', (ev) => {
            let msg; try { msg = JSON.parse(ev.data); } catch { return; }
            if (msg[0] === 'EVENT' && msg[1] === subId) { const e = msg[2]; if (e && e.id && !byId.has(e.id)) byId.set(e.id, e); }
            else if (msg[0] === 'EOSE' && msg[1] === subId) { try { ws.close(); } catch { } }
          });
          const closeLike = () => { openCount = Math.max(0, openCount - 1); if (openCount === 0) finish(); };
          ws.addEventListener('close', closeLike);
          ws.addEventListener('error', closeLike);
        } catch (e) { /* ignore bad relay url */ }
      });
    });
  }

  // ---- RAW-WebSocket: „first-EOSE“-Variante (nur 1 Relay → super schnell)
  async listByWebSocketOne(relay, filter, timeoutMs = 3000) {
    return await new Promise((resolve) => {
      let done = false;
      const subId = 'sub-' + Math.random().toString(36).slice(2, 10);
      let ws = null; const byId = new Map();
      const finish = () => { if (done) return; done = true; try { ws?.close(); } catch { } resolve([...byId.values()]); };
      const timer = setTimeout(finish, timeoutMs);
      try {
        ws = new WebSocket(relay);
        ws.addEventListener('open', () => ws.send(JSON.stringify(['REQ', subId, filter])));
        ws.addEventListener('message', (ev) => {
          let msg; try { msg = JSON.parse(ev.data); } catch { return; }
          if (msg[0] === 'EVENT' && msg[1] === subId) { const e = msg[2]; if (e && e.id && !byId.has(e.id)) byId.set(e.id, e); }
          else if (msg[0] === 'EOSE' && msg[1] === subId) { clearTimeout(timer); finish(); }
        });
        ws.addEventListener('error', finish);
        ws.addEventListener('close', finish);
      } catch { finish(); }
    });
  }

  // ---- Auth: NIP-07/NOS2X, sonst Local Key (Demo)
  async login() {
      await this.initPool();
      if (window.nostr && window.nostr.getPublicKey) {
        this.pubkey = await window.nostr.getPublicKey();
        this.signer = {
          type: 'nip07',
          getPublicKey: async () => this.pubkey,
          signEvent: async (evt) => window.nostr.signEvent(evt)
        };
        return { method: 'nip07', pubkey: this.pubkey };
      }
      await loadTools();
      let sk = localStorage.getItem('nostr_sk_hex');
      if (!sk) {
        const s = tools.generateSecretKey();
        sk = bytesToHex(s);
        localStorage.setItem('nostr_sk_hex', sk);
      }
      const skBytes = hexToBytes(sk);
      this.pubkey = tools.getPublicKey(skBytes);
      this.signer = {
        type: 'local',
        getPublicKey: async () => this.pubkey,
        signEvent: async (evt) => tools.finalizeEvent(evt, skBytes)
      };
      return { method: 'local', pubkey: this.pubkey };
    }
  
    async loginWithNsec(nsec) {
      await this.initPool();
      await loadTools();
      const skHex = nsecToHex(nsec);
      if (!skHex) {
        throw new Error('Ungültiger nsec-Key: Muss gültiges Bech32-Format (nsec1...) oder 64-stelliger Hex sein.');
      }
      const skBytes = hexToBytes(skHex);
      if (skBytes.length !== 32) {
        throw new Error('Ungültiger Secret Key: Muss genau 32 Bytes lang sein.');
      }
      this.pubkey = tools.getPublicKey(skBytes);
      this.signer = {
        type: 'manual',
        getPublicKey: async () => this.pubkey,
        signEvent: async (evt) => tools.finalizeEvent(evt, skBytes)
      };
      this.manualSkBytes = skBytes; // Im Speicher halten für Logout
      return { method: 'manual', pubkey: this.pubkey };
    }

  async logout() {
      this.signer = null;
      this.pubkey = null;
      if (this.manualSkBytes) {
        this.manualSkBytes = null; // Manuellen Key aus Speicher löschen
      }
      
      // Subscriptions zurücksetzen
      try {
        if (window.Subscriptions && typeof window.Subscriptions.reset === 'function') {
          window.Subscriptions.reset();
          console.info('[NostrClient] Subscriptions zurückgesetzt');
        }
      } catch (e) {
        console.warn('[NostrClient] Fehler beim Zurücksetzen der Subscriptions:', e);
      }
      
      // Blossom-Uploads aus Local Storage löschen
      try {
        clearUploadCache();
        console.info('[NostrClient] Blossom-Uploads aus Local Storage gelöscht');
      } catch (e) {
        console.warn('[NostrClient] Fehler beim Löschen der Blossom-Uploads:', e);
      }
      
      try { window.dispatchEvent(new CustomEvent('nip46-disconnected')); } catch { }
    }

  // ---- Bunker-Delegation für Abwärtskompatibilität ----
  async connectBunker(connectURI, { openAuth = true } = {}) {
    return this.bunker.connectBunker(connectURI, { openAuth });
  }



  // ---- Diagnostics: probe signing capabilities for current signer
  async _diagSign(kind) {
    return diagSign(kind, (evt, timeout) => this.signEventWithTimeout(evt, timeout));
  }

  // ---- Publish
  async publish(data) {
    if (!this.signer) await this.login();
    await this.initPool();
    await loadTools();
    
    // Import AuthManager to use the centralized toEventTemplate
    const { authManager } = await import('./auth/AuthManager.js');
    const { evt } = authManager.toEventTemplate(data);
    const signed = await this.signer.signEvent(evt);
  
    // publish zu allen Relays; robust gegenüber verschiedenen pool-APIs und
    // verhindert unhandled promise rejections, indem wir alle relevanten
    // Events (ok/failed/seen/error) abonnieren und Promise niemals ablehnen.
    let pubs = [];
    try {
      console.debug('[publish] pool.publish', Config.relays, signed);
      pubs = this.pool.publish ? this.pool.publish(Config.relays, signed) : [];
    } catch (e) { console.warn('pool.publish sync error', e); pubs = []; }
  
    const makePubPromise = (p, timeout = 1200) => {
      if (!p) return new Promise(res => setTimeout(() => res({ ok: null }), timeout));
      // Wenn p ein thenable ist (Promise)
      if (typeof p.then === 'function') {
        return Promise.race([
          p.then(() => ({ ok: true })).catch(err => ({ ok: false, err })),
          new Promise(res => setTimeout(() => res({ ok: null }), timeout))
        ]);
      }
      // Wenn p ein Event-Emitter-ähnliches Publish-Objekt ist
      if (typeof p.on === 'function') {
        return new Promise(res => {
          let settled = false;
          const cleanup = () => {
            settled = true;
            try { p.off && p.off('ok', onOk); } catch {}
            try { p.off && p.off('failed', onFailed); } catch {}
            try { p.off && p.off('seen', onSeen); } catch {}
            try { p.off && p.off('error', onFailed); } catch {}
            clearTimeout(timer);
          };
          const onOk = () => { if (!settled) { cleanup(); res({ ok: true }); } };
          const onFailed = (msg) => { if (!settled) { cleanup(); res({ ok: false, msg }); } };
          const onSeen = () => { if (!settled) { cleanup(); res({ ok: true, seen: true }); } };
          const timer = setTimeout(() => { if (!settled) { cleanup(); res({ ok: null }); } }, timeout);
          try {
            p.on('ok', onOk);
            p.on('failed', onFailed);
            p.on('seen', onSeen);
            p.on('error', onFailed);
          } catch (e) {
            // defensiv: falls on()/off() nicht verfügbar oder Fehler werfen
            if (!settled) { cleanup(); res({ ok: null }); }
          }
        });
      }
      // Fallback: warte kurz
      return new Promise(res => setTimeout(() => res({ ok: null }), timeout));
    };
  
    try {
      if (Array.isArray(pubs) && pubs.length) {
        const pPromises = pubs.map(p => makePubPromise(p, 800));
        // Wartet darauf, dass mindestens eine Relay-Antwort kommt (oder Timeout)
        await Promise.race(pPromises);
        // kleine Grace-Periode: alle Promises sauber auflösen/ablehnen (ohne throw)
        await Promise.allSettled(pPromises);
      } else {
        await new Promise(res => setTimeout(res, 200));
      }
    } catch (e) {
      console.warn('publish wait error', e);
    }
  
    return { signed };
  }
  // ---- Events holen (FAST-PATH → 1 Relay, kleines limit) + Fallback
  async fetchEvents({ sinceDays = 365, authors = Config.allowedAuthors }) {
    try {
      const since = Math.floor(Date.now() / 1000) - (sinceDays * 86400);
      const baseLimit = 1000;

      await this.initPool();

      // Autoren normalisieren (npub→hex, hex passt durch)
      let authorsHex = Array.isArray(authors) ? authors.map(a => npubToHex(a) || a).filter(Boolean) : [];
      const filter = { kinds: [31923], since, limit: baseLimit };
      if (authorsHex && authorsHex.length) filter.authors = authorsHex;

      // -------- FAST PATH --------
      // 1) schnellsten Relay messen
      const fastRelay = await this.pickFastestRelay(Config.relays, { capMs: 1200, fastRelay: this.fastRelay, fastProbeAt: this.fastProbeAt, fastProbeTTL: this.fastProbeTTL });
      this.fastRelay = fastRelay;
      this.fastProbeAt = Date.now();

      // console.debug('[fetchEvents] fastRelay:', fastRelay);
      // 2) kleines Limit für schnellen „first paint“
      const fastFilter = { ...filter, limit: Math.min(250, filter.limit || 250) };
      // console.debug('[fetchEvents] fastFilter:', fastFilter);
      // 3) Single-relay REQ (EOSE) → in der Praxis ~wie dein Test
      let fast = [];
      try { fast = await this.listByWebSocketOne(fastRelay, fastFilter, 2500); } catch { fast = []; }
      // console.debug('[fetchEvents] fast path got', (fast || []));
      if (fast.length) {
        // dedupe + sorten und direkt zurückgeben (spürbar schneller)
        const latest = new Map();
        for (const e of fast) {
          const d = e.tags?.find(t => t[0] === 'd')?.[1] || e.id;
          const prev = latest.get(d);
          if (!prev || e.created_at > prev.created_at) latest.set(d, e);
        }
        return [...latest.values()].sort((a, b) => a.created_at - b.created_at);
      }

      // -------- Fallback (robust) --------
      const TIMEOUT = 6000;
      const poolP = this.listFromPool(Config.relays, filter, TIMEOUT).catch(() => []);
      const wsP = this.listByWebSocket(Config.relays, filter, TIMEOUT).catch(() => []);
      const both = await Promise.race([
        Promise.allSettled([poolP, wsP]),
        new Promise(res => setTimeout(() => res([
          { status: 'fulfilled', value: [] },
          { status: 'fulfilled', value: [] }
        ]), TIMEOUT + 200))
      ]);

      let events = [];
      if (Array.isArray(both)) {
        const [pRes, wRes] = both;
        const pOk = pRes?.status === 'fulfilled' ? (pRes.value || []) : [];
        const wOk = wRes?.status === 'fulfilled' ? (wRes.value || []) : [];
        events = pOk.length ? pOk : wOk;
        if (!events.length) events = pOk.concat(wOk);
      }

      const latest = new Map();
      for (const e of (events || [])) {
        const d = e.tags?.find(t => t[0] === 'd')?.[1] || e.id;
        const prev = latest.get(d);
        if (!prev || e.created_at > prev.created_at) latest.set(d, e);
      }
      return [...latest.values()].sort((a, b) => a.created_at - b.created_at);
    } catch (err) {
      console.error('fetchEvents failed:', err);
      return [];
    }
  }

  // ---- Robustes Publish eines bereits signierten Events zu mehreren Relays
  async publishToRelays(relays, signedEvent, timeoutMs = 1500) {
    await this.initPool();
  try { console.info('[publishToRelays] relays=', relays, 'kind=', signedEvent?.kind, 'created_at=', signedEvent?.created_at); } catch {}
    let pubs = [];
    try {
      if (this.pool && typeof this.pool.publish === 'function') {
        pubs = this.pool.publish(relays, signedEvent) || [];
      }
    } catch (e) {
      console.warn('[publishToRelays] pool.publish failed:', e);
      pubs = [];
    }

    const makePubPromise = (p, timeout = 1200) => {
      if (!p) return new Promise(res => setTimeout(() => res({ ok: null }), timeout));
      if (typeof p.then === 'function') {
        return Promise.race([
          p.then(() => ({ ok: true })).catch(err => ({ ok: false, err })),
          new Promise(res => setTimeout(() => res({ ok: null }), timeout))
        ]);
      }
      if (typeof p.on === 'function') {
        return new Promise(res => {
          let settled = false;
          const cleanup = () => {
            settled = true; try { p.off && p.off('ok', onOk); } catch {}
            try { p.off && p.off('failed', onFailed); } catch {}
            try { p.off && p.off('seen', onSeen); } catch {}
            try { p.off && p.off('error', onFailed); } catch {}
            clearTimeout(timer);
          };
          const onOk = () => { if (!settled) { cleanup(); res({ ok: true }); } };
          const onFailed = (msg) => { if (!settled) { cleanup(); res({ ok: false, msg }); } };
          const onSeen = () => { if (!settled) { cleanup(); res({ ok: true, seen: true }); } };
          const timer = setTimeout(() => { if (!settled) { cleanup(); res({ ok: null }); } }, timeout);
          try { p.on('ok', onOk); p.on('failed', onFailed); p.on('seen', onSeen); p.on('error', onFailed); } catch (e) { if (!settled) { cleanup(); res({ ok: null }); } }
        });
      }
      return new Promise(res => setTimeout(() => res({ ok: null }), timeout));
    };

    if (Array.isArray(pubs) && pubs.length) {
      const pPromises = pubs.map(p => makePubPromise(p, Math.min(1200, timeoutMs)));
      await Promise.race(pPromises);
      await Promise.allSettled(pPromises);
      return true;
    }

    // Fallback: RAW-WebSocket EVENT senden
    try {
      await new Promise((resolve) => {
        let remaining = (relays || []).length;
        if (!remaining) return resolve(false);
        const payload = JSON.stringify(['EVENT', signedEvent]);
        (relays || []).forEach(url => {
          let done = false; let ws;
          const finish = () => { if (done) return; done = true; remaining--; if (remaining <= 0) resolve(true); };
          const to = setTimeout(() => { finish(); try { ws && ws.close(); } catch {} }, timeoutMs);
          try {
            ws = new WebSocket(url);
            ws.addEventListener('open', () => { try { console.info('[publishToRelays][raw] send EVENT to', url); ws.send(payload); } catch {} setTimeout(finish, 100); });
            ws.addEventListener('error', finish);
            ws.addEventListener('close', finish);
          } catch { finish(); }
        });
      });
      return true;
    } catch (e) {
      console.warn('[publishToRelays] raw publish failed:', e);
      return false;
    }
  }

  // ---- Signatur mit Timeout (sichtbares Logging, um NIP‑46 Hänger zu erkennen)
  async signEventWithTimeout(evt, timeoutMs = 8000) {
    if (!this.signer) await this.login();
    const signer = this.signer;

    // Event vorbereiten: viele Remote-Signer (NIP-46/Bunker) erwarten pubkey & created_at bereits gesetzt
    const prepared = { ...(evt || {}) };
    if (!prepared.kind && evt?.kind == null) {
      throw new Error('signEvent: missing kind');
    }
    if (!Array.isArray(prepared.tags)) prepared.tags = Array.isArray(evt?.tags) ? [...evt.tags] : [];
    if (!prepared.created_at) prepared.created_at = Math.floor(Date.now() / 1000);
    if (typeof prepared.content !== 'string') prepared.content = prepared.content ? String(prepared.content) : '';
    // id/sig niemals mitsenden – das macht der Signer
    if ('id' in prepared) try { delete prepared.id; } catch {}
    if ('sig' in prepared) try { delete prepared.sig; } catch {}

    try {
      const pkLocal = this.pubkey || (typeof signer.getPublicKey === 'function' ? await signer.getPublicKey() : null);
      if (signer?.type === 'nip46') {
        // Für NIP-46: pubkey sowohl im Event als auch temporär speichern
        // Wir probieren später mit und ohne pubkey
        const pk = pkLocal || this.pubkey;
        if (pk) {
          prepared.pubkey = pk;
          prepared._nip46_pubkey = pk;
        }
      } else if (signer?.type === 'wordpress') {
        // Für WordPress: pubkey setzen (wird vom Backend benötigt)
        const pk = pkLocal || this.pubkey;
        if (pk && !prepared.pubkey) {
          prepared.pubkey = pk;
        }
      } else {
        if (pkLocal && !prepared.pubkey) prepared.pubkey = pkLocal;
        if (prepared.pubkey && this.pubkey && prepared.pubkey !== this.pubkey) {
          console.warn('[signEventWithTimeout] pubkey mismatch: prepared.pubkey != this.pubkey');
        }
      }
    } catch (e) {
      // Wenn getPublicKey fehlschlägt, trotzdem versuchen zu signieren
      console.debug('[signEventWithTimeout] getPublicKey failed (non-fatal):', e && (e.message || e));
    }

    // Delegation an Bunker-spezifische Methode für NIP-46
    if (signer?.type === 'nip46') {
      return this.bunker.signEventWithTimeoutBunker(prepared, timeoutMs);
    }
    
    // WordPress SSO nutzt die Standard-Signatur-Logik (signer.signEvent)
    // Die WordPress-spezifische Implementierung in WordPressAuthPlugin.wordpressSigner.signEvent
    // ruft window.WP_NostrTools.nostr_sign() auf

    // Allgemeine Signatur-Logik für NIP-07 und Local Key
    const effectiveTimeout = timeoutMs;
    try {
      console.info('[signEventWithTimeout] start kind=', prepared?.kind, 'timeoutMs=', effectiveTimeout, 'hasPubkey=', !!prepared?.pubkey, 'signerType=', signer?.type);
    } catch {}

    const attemptSign = async (toMs, evObj) => {
      const exec = () => signer.signEvent(evObj);
      return await Promise.race([
        exec(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('signEvent timeout after ' + toMs + 'ms')), toMs))
      ]);
    };

    try {
      const res = await attemptSign(effectiveTimeout, prepared);
      try { console.info('[signEventWithTimeout] done kind=', prepared?.kind); } catch {}
      return res;
    } catch (err) {
      const msg = err && (err.message || String(err));
      console.warn('[signEventWithTimeout] failed:', msg);
      throw err;
    }
  }

  // ---- Fastest Relay Auswahl (als Methode des Clients)
  async pickFastestRelay(relays, { capMs = 1200, fastRelay, fastProbeAt, fastProbeTTL }) {
    const now = Date.now();
    if (fastRelay && (now - fastProbeAt) < fastProbeTTL) return fastRelay || relays[0];

    const candidates = (relays || []).slice(0, 4); // nicht zu viele
    if (!candidates.length) return 'wss://relay.damus.io';

    const aborts = [];
    const winner = await new Promise((resolve) => {
      let settled = false;
      const timer = setTimeout(() => { if (!settled) { settled = true; resolve(candidates[0]); } }, capMs);

      candidates.forEach(url => {
        try {
          const ws = new WebSocket(url);
          aborts.push(() => { try { ws.close(); } catch { } });
          ws.addEventListener('open', () => {
            if (!settled) { settled = true; clearTimeout(timer); resolve(url); }
            try { ws.close(); } catch { }
          });
          ws.addEventListener('error', () => { /* ignore */ });
        } catch { /* ignore */ }
      });
    }).catch(() => candidates[0]);

    aborts.forEach(fn => fn());
    return winner || candidates[0];
  }
}

export const client = new NostrClient();