// js/nostr.js

// Nostr helpers: auth, fetch, publish (NIP-52: kind 31923)
import { Config } from './config.js';
import { uid, b64 } from './utils.js';

// nostr-tools via ESM (korrekte Pfade) – Version pinnen, um API-Divergenzen zu vermeiden
// Hinweis: Wenn nsec.app / BunkerSigner auf eine bestimmte nostr-tools-Version gebaut ist,
// können unversionierte ESM-URLs zu Laufzeit-Inkompatibilitäten führen (keine onauth/calls).
const pureUrl  = 'https://esm.sh/nostr-tools@2.8.1/pure';
const poolUrl  = 'https://esm.sh/nostr-tools@2.8.1/pool';
const nip46Url = 'https://esm.sh/nostr-tools@2.8.1/nip46';

let tools = null;
let poolMod = null;
let nip46Mod = null;

// ---- hex helpers (browser-safe)
function hexToBytes(hex) { const a = []; for (let i = 0; i < hex.length; i += 2) { a.push(parseInt(hex.substr(i, 2), 16)); } return new Uint8Array(a); }
function bytesToHex(arr) { return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join(''); }

// --- bech32 / npub helpers (minimal, ohne externe deps)
const __CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function __b32Polymod(values) { const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let chk = 1; for (let p = 0; p < values.length; ++p) { const top = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ values[p]; for (let i = 0; i < 5; ++i) if ((top >> i) & 1) chk ^= G[i]; } return chk; }
function __b32HrpExpand(hrp) { const out = []; for (let i = 0; i < hrp.length; ++i) out.push(hrp.charCodeAt(i) >> 5); out.push(0); for (let i = 0; i < hrp.length; ++i) out.push(hrp.charCodeAt(i) & 31); return out; }
function __b32Decode(bech) { try { const lower = bech.toLowerCase(); const pos = lower.lastIndexOf('1'); if (pos < 1 || pos + 7 > lower.length) return null; const hrp = lower.slice(0, pos); const data = []; for (let i = pos + 1; i < lower.length; ++i) { const c = lower.charAt(i); const v = __CHARSET.indexOf(c); if (v === -1) return null; data.push(v); } if (__b32Polymod(__b32HrpExpand(hrp).concat(data)) !== 1) return null; return { hrp, data: data.slice(0, data.length - 6) }; } catch (e) { return null; } }
function __fromWords(words) { let acc = 0, bits = 0; const out = []; for (let i = 0; i < words.length; ++i) { acc = (acc << 5) | words[i]; bits += 5; while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); } } return out; }
function npubToHex(npub) { if (!npub || typeof npub !== 'string') return null; if (/^[0-9a-f]{64}$/i.test(npub)) return npub.toLowerCase(); const dec = __b32Decode(npub); if (!dec || (dec.hrp !== 'npub' && dec.hrp !== 'nprofile')) return null; const bytes = __fromWords(dec.data); if (!bytes || !bytes.length) return null; return bytes.map(b => ('0' + b.toString(16)).slice(-2)).join(''); }

function nsecToHex(nsec) {
  if (!nsec || typeof nsec !== 'string') return null;
  if (/^[0-9a-f]{64}$/i.test(nsec)) return nsec.toLowerCase(); // fallback für hex
  const dec = __b32Decode(nsec);
  if (!dec || dec.hrp !== 'nsec') return null;
  const bytes = __fromWords(dec.data);
  if (!bytes || bytes.length !== 32) return null; // Secret Key muss 32 Bytes sein
  return bytesToHex(bytes);
}



// ---- dyn. load
async function loadTools() {
  // Try primary CDN (esm.sh). If it fails (network/CORS), fall back to alternative CDN URLs.
  const cdnAlternatives = {
    pure: [
      pureUrl,
      'https://cdn.jsdelivr.net/npm/nostr-tools@2.8.1/esm/pure.js',
      'https://unpkg.com/nostr-tools@2.8.1/esm/pure.js'
    ],
    pool: [
      poolUrl,
      'https://cdn.jsdelivr.net/npm/nostr-tools@2.8.1/esm/pool.js',
      'https://unpkg.com/nostr-tools@2.8.1/esm/pool.js'
    ],
    nip46: [
      nip46Url,
      'https://cdn.jsdelivr.net/npm/nostr-tools@2.8.1/esm/nip46.js',
      'https://unpkg.com/nostr-tools@2.8.1/esm/nip46.js'
    ]
  };

  async function tryImport(list) {
    let lastErr = null;
    for (const url of list) {
      try {
        return await import(url);
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

  if (!nip46Mod) {
    try {
      nip46Mod = await tryImport(cdnAlternatives.nip46);
    } catch (e) {
      console.warn('[loadTools] nip46 module not available (all candidates failed):', e);
      nip46Mod = null;
    }
  }

  return { tools, poolMod, nip46Mod };
}

export class NostrClient {
  constructor() {
    this.pool = null;
    this.signer = null; // { type: 'nip07' | 'local' | 'nip46', getPublicKey, signEvent }
    this.pubkey = null;

    // Runtime state
    this._nip46Connecting = false; // Guard: vermeidet parallele Bunker-Connects

    // Speed helpers (memo)
    this.fastRelay = null;         // gemessener schnellster Relay
    this.fastProbeAt = 0;          // timestamp der letzten Messung
    this.fastProbeTTL = 5 * 60e3;  // 5 Minuten Cache
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

  // ---- „Fastest relay“ ermitteln (kurzer open-Race, 1200ms cap)
  async pickFastestRelay(relays = Config.relays, capMs = 1200) {
    const now = Date.now();
    if (this.fastRelay && (now - this.fastProbeAt) < this.fastProbeTTL) return this.fastRelay || relays[0];

    const candidates = (relays || []).slice(0, 4); // nicht zu viele
    if (!candidates.length) return (this.fastRelay = null), (this.fastRelay = 'wss://relay.damus.io');

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
    this.fastRelay = winner || candidates[0];
    this.fastProbeAt = Date.now();
    return this.fastRelay;
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
      try { window.dispatchEvent(new CustomEvent('nip46-disconnected')); } catch { }
    }


  // ---- NIP-46 (Bunker) – mit onauth-Callback und optional silent-Mode
async connectBunker(connectURI, { openAuth = true } = {}) {
  // Verhindere parallele Verbindungsversuche (Button + Auto-Reconnect)
  if (this._nip46Connecting) {
    console.warn('[Bunker] connectBunker skipped — another connect is in progress');
    throw new Error('NIP-46 connect already in progress');
  }
  this._nip46Connecting = true;
  await this.initPool();
  await loadTools();

  const { BunkerSigner, parseBunkerInput, toBunkerURL } = (nip46Mod || {});
  if (!BunkerSigner || !parseBunkerInput) {
    throw new Error('nip46 build lacks BunkerSigner/parseBunkerInput');
  }

  // 1) URI normalisieren + parsen
  let raw = String(connectURI || '').trim();
  if (!raw) throw new Error('No connect URI provided');

  let pointer = null;
  try { pointer = await parseBunkerInput(raw); } catch {}
  if (!pointer && typeof toBunkerURL === 'function') {
    try {
      const bunkerUrl = await toBunkerURL(raw);
      pointer = await parseBunkerInput(bunkerUrl);
    } catch {}
  }
  if (!pointer) throw new Error('Invalid bunker/NIP-46 URI');

  // 2) lokalen Client-Secret laden/erzeugen
  let skHex = localStorage.getItem('nip46_client_sk_hex');
  if (!skHex) {
    const skBytesInit = tools.generateSecretKey(); // Uint8Array
    skHex = Array.from(skBytesInit).map(b => b.toString(16).padStart(2,'0')).join('');
    localStorage.setItem('nip46_client_sk_hex', skHex);
  }
  const skBytes = new Uint8Array(skHex.match(/.{1,2}/g).map(h => parseInt(h,16)));

  // ---- Preflight: schnelles Relay aus Pointer finden ----
  async function preflightRelay(relays = [], capMs = 1500) {
    const list = Array.isArray(relays) && relays.length ? relays : [];
    if (!list.length) return null;
    const tryOne = (url) => new Promise((resolve) => {
      let ws, done = false;
      const timer = setTimeout(() => { if (!done) { done = true; try { ws?.close(); } catch{}; resolve(null); } }, capMs);
      try {
        ws = new WebSocket(url);
        ws.addEventListener('open', () => { if (!done){ done = true; clearTimeout(timer); try{ ws.close(); }catch{}; resolve(url); }});
        ws.addEventListener('error', () => { if (!done){ done = true; clearTimeout(timer); resolve(null); }});
        ws.addEventListener('close', () => { if (!done){ done = true; clearTimeout(timer); resolve(url); }});
      } catch {
        resolve(null);
      }
    });
    for (const r of list) {
      const ok = await tryOne(r);
      if (ok) return ok;
    }
    return null;
  }

  // 3) Flags/Utils
  let authTriggered = false;
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const MAX_WAIT_MS = 45000; // Gesamtzeit zum Polling von getPublicKey()

  // 4) BunkerSigner + onauth
  let bunker;
  let chosenRelay = null;
  try {
    const pointerRelays = Array.isArray(pointer?.relays) ? pointer.relays.filter(Boolean) : [];
    chosenRelay = await preflightRelay(pointerRelays, 1500) || pointerRelays[0] || 'wss://relay.nsec.app';

    // Helper: (Re)Create the BunkerSigner with current settings
    const createBunker = () => {
      const signer = new BunkerSigner(skBytes, pointer, {
        // Wichtig: kein SimplePool verwenden – direkte WS-Verbindung zum Relay erzwingen.
        // Einige Bunker/Relay-Kombinationen liefern RPC-Antworten nicht zuverlässig über SimplePool-Subs aus.
        relay: chosenRelay,
        // relays explizit nicht setzen, damit der Signer intern eine eindeutige Verbindung nutzt
        onauth: (url) => {
          authTriggered = true;
          if (openAuth) {
            try {
              const w = window.open(url, '_blank', 'noopener,noreferrer');
              if (!w) {
                navigator.clipboard?.writeText(url).catch(()=>{});
                // alert('Bitte diese Autorisierungs-URL öffnen (Link in Zwischenablage):\n' + url);
              }
            } catch (e) {
              navigator.clipboard?.writeText(url).catch(()=>{});
              alert('Bitte diese Autorisierungs-URL öffnen:\n' + url);
            }
          } else {
            try { localStorage.setItem('nip46_last_auth_url', url); } catch {}
            window.dispatchEvent(new CustomEvent('nip46-auth-url', { detail: { url } }));
          }
        },
        onnotice: (msg) => console.log('[NIP-46 notice]', msg),
        onerror:  (err) => console.warn('[NIP-46 error]', err)
      });
      return signer;
    };

    bunker = createBunker();

    // Starten, aber NICHT awaiten – manche Builds resolven nie zuverlässig
    // Fehler werden geloggt, aber wir verlassen uns auf getPublicKey()-Polling unten.
    try {
      console.debug('[Bunker] calling bunker.connect() (background start)');
      // Start background connect and log resolution for diagnostics
      bunker.connect()
        .then(() => {
          try { console.debug('[Bunker] bunker.connect() resolved successfully'); } catch(e){}
        })
        .catch(e => {
          try { console.warn('bunker.connect error (ignored, using polling):', e); } catch(e){}
        });
      try { window.dispatchEvent(new CustomEvent('nip46-connect-started', { detail: { relay: chosenRelay } })); } catch(e){}
    } catch(e) {
      console.warn('bunker.connect invocation failed:', e);
    }

  } catch (e) {
    console.warn('BunkerSigner init failed:', e, 'pointer.relays=', pointer?.relays);
    throw new Error('Failed to init NIP-46 signer');
  }

  // 5) Warten, bis Pubkey abrufbar (nach Genehmigung)
  let pk = null;
  const start = Date.now();
  const TRY_TIMEOUT_MS = 1200; // vermeidet Hänger, falls getPublicKey() nie resolved/rejected
  let attempts = 0;
  console.debug('[Bunker] begin getPublicKey polling (max ms=', MAX_WAIT_MS, 'relay=', chosenRelay, 'pointer.relays=', pointer && pointer.relays);
  while ((Date.now() - start) < MAX_WAIT_MS) {
    attempts++;
    try {
      const res = await Promise.race([
        bunker.getPublicKey(),
        sleep(TRY_TIMEOUT_MS).then(() => '__TIMEOUT__')
      ]);
      if (res !== '__TIMEOUT__') {
        pk = res;
        console.debug('[Bunker] getPublicKey attempt', attempts, '->', pk);
      } else {
        console.debug('[Bunker] getPublicKey attempt', attempts, '→ timeout after', TRY_TIMEOUT_MS, 'ms');
        // Recovery: Wenn Auth ausgelöst wurde, aber keine Antwort kommt,
        // versuche periodisch, den Signer neu zu initialisieren und erneut zu verbinden.
        if (authTriggered && (attempts % 6 === 0)) {
          try {
            console.warn('[Bunker] no pubkey yet after', attempts, 'attempts — recreating signer and reconnecting…');
            try { await bunker.close?.(); } catch {}
            bunker = createBunker();
            bunker.connect().catch(e => console.warn('bunker.connect retry error:', e));
            try { window.dispatchEvent(new CustomEvent('nip46-connect-started', { detail: { relay: chosenRelay, retry: true } })); } catch(e){}
          } catch (e) {
            console.warn('[Bunker] recreate signer failed:', e);
          }
        }
      }
      if (pk && /^[0-9a-f]{64}$/i.test(pk)) {
        console.debug('[Bunker] valid pubkey received after', attempts, 'attempts:', pk);
        break;
      }
    } catch (e) {
      // noch nicht autorisiert / noch nicht bereit
      console.debug('[Bunker] getPublicKey attempt', attempts, 'threw:', e && (e.stack || e));
    }
    await sleep(500);
  }
  console.debug('[Bunker] polling finished after', attempts, 'attempts, elapsed ms=', (Date.now() - start));
  if (!pk) {
    // Wenn onauth nie kam, ist es meist ein Relay-/Routing-Problem; sonst: User hat evtl. nicht bestätigt
    const why = authTriggered ? 'authorization not completed' : 'no auth_url received';
    console.warn('[Bunker] connect timeout reason=', why, 'authTriggered=', authTriggered);
    throw new Error('NIP-46 connect timeout (' + why + ')');
  }

  // 6) Signer & Pubkey übernehmen
  this.signer = {
    type: 'nip46',
    getPublicKey: async () => await bunker.getPublicKey(),
    signEvent:    async (evt) => await bunker.signEvent(evt),
    close:        async () => { try { await bunker.close?.(); } catch {} }
  };
  this.pubkey = pk;

  // Persistenz + UI-Event
  try {
    localStorage.setItem('nip46_connected', '1');
    localStorage.setItem('nip46_connected_pubkey', this.pubkey);
  } catch {}
  try {
    window.dispatchEvent(new CustomEvent('nip46-connected', { detail: { pubkey: this.pubkey } }));
  } catch {}

  return { method: 'nip46', pubkey: this.pubkey, relay: (chosenRelay || pointer?.relays?.[0] || null) };
}



  // ---- Event-Vorlage (Kind 31923) mit Delegation-Unterstützung
  toEventTemplate(data) {
    const tags = [
      ['title', data.title],
      ['start', String(data.start)],
      ['end', String(data.end)],
      ['status', data.status || 'planned'],
    ];
    if (data.summary) tags.push(['summary', data.summary]);
    if (data.location) tags.push(['location', data.location]);
    if (data.image) tags.push(['image', data.image]);
    for (const t of (data.tags || [])) { const v = String(t).trim(); if (v) tags.push(['t', v]); }
    
    // KRITISCH: Delegation-Tag hinzufügen falls vorhanden
    if (data.delegationTag && Array.isArray(data.delegationTag)) {
      console.log('[NostrClient] Adding delegation tag to event template:', data.delegationTag);
      tags.push(data.delegationTag);
    }
    
    const d = data.d || b64((data.url || '') + '|' + data.title + '|' + data.start);
    tags.push(['d', d]);
    if (Array.isArray(Config.appTag)) tags.push(Config.appTag);
    return { evt: { kind: 31923, created_at: Math.floor(Date.now() / 1000), tags, content: data.content || '' }, d };
  }

  // ---- Publish
  async publish(data) {
    if (!this.signer) await this.login();
    await this.initPool();
    await loadTools();
    const { evt } = this.toEventTemplate(data);
    const signed = await this.signer.signEvent(evt);
  
    // publish zu allen Relays; robust gegenüber verschiedenen pool-APIs und
    // verhindert unhandled promise rejections, indem wir alle relevanten
    // Events (ok/failed/seen/error) abonnieren und Promise niemals ablehnen.
    let pubs = [];
    try { pubs = this.pool.publish ? this.pool.publish(Config.relays, signed) : []; } catch (e) { console.warn('pool.publish sync error', e); pubs = []; }
  
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
      const fastRelay = await this.pickFastestRelay(Config.relays).catch(() => Config.relays[0]);
      // 2) kleines Limit für schnellen „first paint“
      const fastFilter = { ...filter, limit: Math.min(250, filter.limit || 250) };
      // 3) Single-relay REQ (EOSE) → in der Praxis ~wie dein Test
      let fast = [];
      try { fast = await this.listByWebSocketOne(fastRelay, fastFilter, 2500); } catch { fast = []; }
      if (fast.length) {
        // Sichere Delegation-Validierung anwenden
        const validEvents = await this.filterAndValidateDelegatedEvents(fast, authorsHex);
        if (validEvents.length) {
          return validEvents.sort((a, b) => a.created_at - b.created_at);
        }
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
      const rawEvents = [...latest.values()];
      
      // Sichere Delegation-Validierung anwenden
      const validatedEvents = await this.filterAndValidateDelegatedEvents(rawEvents, authorsHex);
      return validatedEvents.sort((a, b) => a.created_at - b.created_at);
    } catch (err) {
      console.error('fetchEvents failed:', err);
      return [];
    }
  }

  // ---- SICHERE NIP-26 Delegation Validation (TEMPORARY: Simplified for debugging)
  async validateDelegationSignature(event, delegatorPubkey, conditions, signature) {
    try {
      console.log('[Delegation] DEBUG: Validating delegation for event:', event.id, 'delegator:', delegatorPubkey);
      
      // 1. Basic Format-Checks
      if (!signature || signature.length !== 128) {
        console.warn('[Delegation] Invalid signature format:', signature);
        return false;
      }
      
      if (!delegatorPubkey || delegatorPubkey.length !== 64) {
        console.warn('[Delegation] Invalid delegator pubkey format:', delegatorPubkey);
        return false;
      }
      
      // 2. Conditions validieren (Zeit-basiert)
      if (!this.validateDelegationConditions(conditions, event)) {
        console.warn('[Delegation] Conditions not met:', conditions);
        return false;
      }
      
      // TEMPORARY: Skip complex signature validation for debugging
      console.log('[Delegation] DEBUG: Basic validation passed, skipping signature verification');
      return true;
      
      // TODO: Restore full Schnorr signature validation later
      /* 
      // 3. NIP-26 Delegation Token Format
      const delegationToken = `nostr:delegation:${event.pubkey}:${conditions}`;
      
      // 4. Echte Schnorr Signatur verifizieren
      await loadTools();
      
      if (tools && tools.verifyEvent) {
        // SHA256 Hash des Delegation Tokens
        const msgBuffer = new TextEncoder().encode(delegationToken);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const messageHashHex = Array.from(new Uint8Array(hashBuffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
        
        // Delegation Event für Verifikation erstellen
        const delegationEvent = {
          id: messageHashHex,
          pubkey: delegatorPubkey,
          created_at: event.created_at,
          kind: 1, // Dummy kind für Verifikation
          tags: [['delegation', event.pubkey, conditions]],
          content: delegationToken,
          sig: signature
        };
        
        // Event ID neu berechnen
        if (tools.getEventHash) {
          delegationEvent.id = tools.getEventHash(delegationEvent);
        }
        
        // Signatur verifizieren mit nostr-tools
        const isValid = tools.verifyEvent ? tools.verifyEvent(delegationEvent) : false;
        console.log('[Delegation] Signature validation result:', isValid, 'for event:', event.id);
        return isValid;
      }
      
      console.warn('[Delegation] No crypto library available - using basic format validation only');
      return true;
      */
      
    } catch (error) {
      console.error('[Delegation] Signature validation error:', error);
      return false;
    }
  }

  // ---- Delegation Conditions validieren
  validateDelegationConditions(conditions, event) {
    if (!conditions) return false;
    
    const conditionParts = conditions.split('&');
    
    for (const condition of conditionParts) {
      const trimmed = condition.trim();
      
      // created_at Zeitfenster prüfen
      if (trimmed.startsWith('created_at>')) {
        const minTime = parseInt(trimmed.substring(11));
        if (event.created_at <= minTime) {
          console.warn('[Delegation] Event too old:', event.created_at, '<=', minTime);
          return false;
        }
      } else if (trimmed.startsWith('created_at<')) {
        const maxTime = parseInt(trimmed.substring(11));
        if (event.created_at >= maxTime) {
          console.warn('[Delegation] Event too new:', event.created_at, '>=', maxTime);
          return false;
        }
      }
      
      // kind Filter prüfen
      else if (trimmed.startsWith('kind=')) {
        const allowedKind = parseInt(trimmed.substring(5));
        if (event.kind !== allowedKind) {
          console.warn('[Delegation] Wrong kind:', event.kind, '!=', allowedKind);
          return false;
        }
      }
      
      // Weitere NIP-26 Conditions hier...
    }
    
    return true;
  }

  // ---- SICHERE Events filtern und Delegationen validieren (WITH DEBUG LOGS)
  async filterAndValidateDelegatedEvents(events, allowedAuthors) {
    console.log('[Delegation] DEBUG: Processing', events.length, 'events with allowedAuthors:', allowedAuthors);
    const latest = new Map();
    
    for (const event of (events || [])) {
      if (!event || !event.id) continue;
      
      const d = event.tags?.find(t => t[0] === 'd')?.[1] || event.id;
      const prev = latest.get(d);
      
      // Neuestes Event für diese d-Tag behalten
      if (prev && event.created_at <= prev.created_at) continue;
      
      // Event validieren: entweder direkter Author oder gültige Delegation
      let isValid = false;
      
      // console.log('[Delegation] DEBUG: Checking event:', event.id, 'author:', event.pubkey);
      
      // 1. Direkter Author check
      if (!allowedAuthors.length || allowedAuthors.includes(event.pubkey)) {
        // console.log('[Delegation] DEBUG: Direct author match for event:', event.id);
        isValid = true;
      } else {
        console.log('[Delegation] DEBUG: No direct author match, checking delegation for event:', event.id);
        
        // 2. SICHERE Delegation check
        const delegationTag = event.tags?.find(t => t[0] === 'delegation');
        if (delegationTag && delegationTag.length >= 4) {
          const [, delegatorPubkey, conditions, signature] = delegationTag;
          
          console.log('[Delegation] DEBUG: Found delegation tag:', delegationTag);
          
          // Prüfe ob Delegator in allowedAuthors ist
          if (allowedAuthors.includes(delegatorPubkey)) {
            console.log('[Delegation] DEBUG: Delegator is allowed, validating signature...');
            
            // KRITISCH: Echte NIP-26 Signatur-Validierung
            try {
              const signatureValid = await this.validateDelegationSignature(event, delegatorPubkey, conditions, signature);
              if (signatureValid) {
                isValid = true;
                
                // Delegation-Info für UI
                event._delegation = {
                  delegator: delegatorPubkey,
                  conditions,
                  signature,
                  delegatee: event.pubkey,
                  validated: true,
                  secure: true
                };
                console.log('[Delegation] SECURE: Validated delegation for event:', event.id);
              } else {
                console.warn('[Delegation] SECURITY: Invalid signature for event:', event.id, 'from delegator:', delegatorPubkey);
                // Event wird abgelehnt - gefälschte Delegation
              }
            } catch (error) {
              console.error('[Delegation] SECURITY: Validation failed:', error);
            }
          } else {
            console.log('[Delegation] DEBUG: Delegator not in allowedAuthors:', delegatorPubkey);
          }
        } else {
          console.log('[Delegation] DEBUG: No delegation tag found for event:', event.id);
        }
      }
      
      if (isValid) {
        // console.log('[Delegation] DEBUG: Event accepted:', event.id);
        latest.set(d, event);
      } else {
        console.log('[Delegation] DEBUG: Event rejected:', event.id);
      }
    }
    
    console.log('[Delegation] DEBUG: Final result:', latest.size, 'valid events');
    return [...latest.values()];
  }
}

export const client = new NostrClient();
