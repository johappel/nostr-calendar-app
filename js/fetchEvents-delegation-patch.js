// Enhanced fetchEvents with delegation support for nostr.js

// Replace the existing fetchEvents method in NostrClient class with this:

async fetchEvents({ sinceDays = 365, authors = Config.allowedAuthors }) {
  try {
    const since = Math.floor(Date.now() / 1000) - (sinceDays * 86400);
    const baseLimit = 1000;

    await this.initPool();

    // Autoren normalisieren (npub→hex, hex passt durch)
    let authorsHex = Array.isArray(authors) ? authors.map(a => npubToHex(a) || a).filter(Boolean) : [];
    
    // Basis-Filter für normale Events (ohne Delegation)
    const baseFilter = { kinds: [31923], since, limit: baseLimit };
    if (authorsHex && authorsHex.length) baseFilter.authors = authorsHex;

    // -------- FAST PATH --------
    // 1) schnellsten Relay messen
    const fastRelay = await this.pickFastestRelay(Config.relays).catch(() => Config.relays[0]);
    
    // 2) Zwei Filter: normale Events + delegierte Events
    const fastLimit = Math.min(250, baseFilter.limit || 250);
    const normalFilter = { ...baseFilter, limit: fastLimit };
    
    // Filter für delegierte Events: alle kind 31923 Events mit delegation tag
    const delegationFilter = { 
      kinds: [31923], 
      since, 
      limit: fastLimit,
      '#delegation': authorsHex.length ? authorsHex : undefined  // Suche nach delegation tag mit unseren pubkeys
    };

    // 3) Beide Filter parallel ausführen
    let allEvents = [];
    try {
      const [normal, delegated] = await Promise.all([
        this.listByWebSocketOne(fastRelay, normalFilter, 2500).catch(() => []),
        authorsHex.length ? this.listByWebSocketOne(fastRelay, delegationFilter, 2500).catch(() => []) : Promise.resolve([])
      ]);
      allEvents = [...normal, ...delegated];
    } catch { 
      allEvents = []; 
    }
    
    if (allEvents.length) {
      // Dedupe, validiere Delegationen und sortiere
      const validEvents = this.filterAndValidateDelegatedEvents(allEvents, authorsHex);
      if (validEvents.length) {
        return validEvents.sort((a, b) => a.created_at - b.created_at);
      }
    }

    // -------- Fallback (robust) --------
    const TIMEOUT = 6000;
    
    // Normale Events
    const normalPoolP = this.listFromPool(Config.relays, baseFilter, TIMEOUT).catch(() => []);
    const normalWsP = this.listByWebSocket(Config.relays, baseFilter, TIMEOUT).catch(() => []);
    
    // Delegierte Events (nur wenn Autoren definiert)
    const delegatedPoolP = authorsHex.length ? 
      this.listFromPool(Config.relays, { kinds: [31923], since, limit: baseLimit, '#delegation': authorsHex }, TIMEOUT).catch(() => []) :
      Promise.resolve([]);
    const delegatedWsP = authorsHex.length ?
      this.listByWebSocket(Config.relays, { kinds: [31923], since, limit: baseLimit, '#delegation': authorsHex }, TIMEOUT).catch(() => []) :
      Promise.resolve([]);

    const allResults = await Promise.race([
      Promise.allSettled([normalPoolP, normalWsP, delegatedPoolP, delegatedWsP]),
      new Promise(res => setTimeout(() => res([
        { status: 'fulfilled', value: [] },
        { status: 'fulfilled', value: [] },
        { status: 'fulfilled', value: [] },
        { status: 'fulfilled', value: [] }
      ]), TIMEOUT + 200))
    ]);

    let events = [];
    if (Array.isArray(allResults)) {
      const [normalPool, normalWs, delegatedPool, delegatedWs] = allResults;
      const normalPoolEvents = normalPool?.status === 'fulfilled' ? (normalPool.value || []) : [];
      const normalWsEvents = normalWs?.status === 'fulfilled' ? (normalWs.value || []) : [];
      const delegatedPoolEvents = delegatedPool?.status === 'fulfilled' ? (delegatedPool.value || []) : [];
      const delegatedWsEvents = delegatedWs?.status === 'fulfilled' ? (delegatedWs.value || []) : [];
      
      // Kombiniere alle Events
      const allFetchedEvents = [...normalPoolEvents, ...normalWsEvents, ...delegatedPoolEvents, ...delegatedWsEvents];
      events = this.filterAndValidateDelegatedEvents(allFetchedEvents, authorsHex);
    }

    return events.sort((a, b) => a.created_at - b.created_at);
  } catch (err) {
    console.error('fetchEvents failed:', err);
    return [];
  }
}

// Add this new helper method to NostrClient class:
filterAndValidateDelegatedEvents(events, allowedAuthors) {
  const latest = new Map();
  
  for (const event of (events || [])) {
    if (!event || !event.id) continue;
    
    const d = event.tags?.find(t => t[0] === 'd')?.[1] || event.id;
    const prev = latest.get(d);
    
    // Neuestes Event für diese d-Tag behalten
    if (prev && event.created_at <= prev.created_at) continue;
    
    // Event validieren: entweder direkter Author oder gültige Delegation
    let isValid = false;
    
    // 1. Direkter Author check
    if (!allowedAuthors.length || allowedAuthors.includes(event.pubkey)) {
      isValid = true;
    } else {
      // 2. Delegation check
      const delegationTag = event.tags?.find(t => t[0] === 'delegation');
      if (delegationTag && delegationTag.length >= 4) {
        const [, delegatorPubkey, conditions, signature] = delegationTag;
        
        // Prüfe ob Delegator in allowedAuthors ist
        if (allowedAuthors.includes(delegatorPubkey)) {
          // TODO: Hier könnte man die Delegation-Signatur validieren
          // Für jetzt akzeptieren wir alle Delegationen von erlaubten Autoren
          isValid = true;
          
          // Optional: Erweitere Event um Delegation-Info für UI
          event._delegation = {
            delegator: delegatorPubkey,
            conditions,
            signature,
            delegatee: event.pubkey
          };
        }
      }
    }
    
    if (isValid) {
      latest.set(d, event);
    }
  }
  
  return [...latest.values()];
}