// SECURE NIP-26 Delegation Validation for nostr.js
// This replaces the insecure delegation validation

// Add this to NostrClient class:

// ---- Sichere NIP-26 Delegation Validation
async validateDelegationSignature(event, delegatorPubkey, conditions, signature) {
  try {
    // 1. NIP-26 Delegation Token Format
    const delegationToken = `nostr:delegation:${event.pubkey}:${conditions}`;
    
    // 2. SHA256 Hash des Tokens
    const msgBuffer = new TextEncoder().encode(delegationToken);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const messageHash = Array.from(new Uint8Array(hashBuffer));
    
    // 3. Conditions validieren (Zeit-basiert)
    if (!this.validateDelegationConditions(conditions, event)) {
      console.warn('[Delegation] Conditions not met:', conditions);
      return false;
    }
    
    // 4. Schnorr Signatur verifizieren
    await loadTools(); // nostr-tools laden
    
    if (tools && tools.verifyEvent) {
      // Delegation Event für Verifikation erstellen
      const delegationEvent = {
        id: '', 
        pubkey: delegatorPubkey,
        created_at: event.created_at,
        kind: 1, // Dummy kind
        tags: [['delegation', event.pubkey, conditions]],
        content: delegationToken,
        sig: signature
      };
      
      // Event ID berechnen für Verifikation
      delegationEvent.id = tools.getEventHash ? 
        tools.getEventHash(delegationEvent) : 
        this.calculateEventId(delegationEvent);
      
      // Signatur verifizieren mit nostr-tools
      return tools.verifyEvent ? tools.verifyEvent(delegationEvent) : false;
    }
    
    // Fallback: Noble secp256k1 (wenn verfügbar)
    if (typeof window !== 'undefined' && window.nobleSecp256k1) {
      const msgHashHex = Array.from(messageHash).map(b => b.toString(16).padStart(2, '0')).join('');
      return window.nobleSecp256k1.verify(signature, msgHashHex, delegatorPubkey);
    }
    
    console.warn('[Delegation] No crypto library available for signature verification');
    return false;
    
  } catch (error) {
    console.error('[Delegation] Signature validation error:', error);
    return false;
  }
}

// ---- Delegation Conditions validieren
validateDelegationConditions(conditions, event) {
  if (!conditions) return false;
  
  const conditionParts = conditions.split('&');
  const now = Math.floor(Date.now() / 1000);
  
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

// ---- SICHERE Version von filterAndValidateDelegatedEvents
async filterAndValidateDelegatedEvents(events, allowedAuthors) {
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
      // 2. SICHERE Delegation check
      const delegationTag = event.tags?.find(t => t[0] === 'delegation');
      if (delegationTag && delegationTag.length >= 4) {
        const [, delegatorPubkey, conditions, signature] = delegationTag;
        
        // Prüfe ob Delegator in allowedAuthors ist
        if (allowedAuthors.includes(delegatorPubkey)) {
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
            } else {
              console.warn('[Delegation] SECURITY: Invalid signature for event:', event.id, 'from delegator:', delegatorPubkey);
              // Event wird abgelehnt - gefälschte Delegation
            }
          } catch (error) {
            console.error('[Delegation] SECURITY: Validation failed:', error);
          }
        }
      }
    }
    
    if (isValid) {
      latest.set(d, event);
    }
  }
  
  return [...latest.values()];
}

// ---- Event ID Berechnung (Fallback)
calculateEventId(event) {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  
  // SHA256 mit WebCrypto API
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(serialized))
    .then(hash => Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(''));
}