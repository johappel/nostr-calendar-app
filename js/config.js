export const Config = {
  // Server-URL für Nostr-Events (z. B. WebSocket-Relay)  
  relays: [
    'wss://relay-rpi.edufeed.org'
  ],
  // Optional: auf bestimmte Autoren einschränken (npub, hex oder leer lassen)
  allowedAuthors: [
    "54a340072ccc625516c8d572b638a828c5b857074511302fb4392f26e34e1913"
  ],
  // Subscriptions-Speicher: Standard lokal für nicht angemeldete Nutzer.
  // Bei Anmeldung bevorzugt NIP-51 (parameterized replaceable list) mit eigenem d-Namen.
  subscriptionsList: {
    strategy: 'auto', // 'auto' | 'local' | 'nip51' | 'contacts'
    nip51: {
      kind: 30000,
      d: 'nostr-calendar:subscriptions',
      name: 'Nostr Calendar Subscriptions',
      description: 'Autorisierte Aboliste für den Kalender'
    },
    contactsKind: 3 // Fallback: NIP-02 Contacts (nicht empfohlen zum Schreiben)
  },

  defaultTheme: 'light',
  // Optionaler NIP-96 Upload-Endpunkt (z. B. https://media.server/api/upload )
  mediaUploadEndpoint: '',
  // Blossom/NIP-96 Media Servers (für Datei-Uploads & Verwaltung)
  mediaServers: [
    { url: 'https://files.sovbit.host', protocol: 'nip96' }
    // Weitere Server können hier hinzugefügt werden
    // { url: 'https://blossom.band', protocol: 'blossom' } // hat derzeit Server-Bug
  ],
  // NIP-46 (Bunker) – optional vordefinierte Connect-URI (kann per UI gesetzt werden)
  nip46: { connectURI: '' },
  // App metadata for NIP-78 client tags
  appTag: ['client', 'nostr-calendar-demo']
};

// Dev-/Debug-Override: Relays per URL-Parameter setzen (?relay=wss://… oder ?relays=wss://a,wss://b)
try {
  const p = new URLSearchParams(location.search);
  const raw = p.get('relays') || p.get('relay');
  if (raw) {
    const list = raw.split(',').map(s => s.trim()).filter(Boolean);
    if (list.length) {
      Config.relays = list;
      console.info('[Config] Using relays from URL:', Config.relays);
    }
  }
} catch {}
