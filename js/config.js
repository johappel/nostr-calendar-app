export const Config = {
  // Nostr relays to connect to 'wss://relilab.nostr1.com',
    
  relays: [
    'wss://relilab.nostr1.com',
    'wss://relay-rpi.edufeed.org'
  ],
  // Optional: auf bestimmte Autoren einschränken (npub, hex oder leer lassen)
  //allowedAuthors: ["54a340072ccc625516c8d572b638a828c5b857074511302fb4392f26e34e1913", "323c252190634267a57367e94a7d21331156764d0ccfe99769edbcb5d85afe86", "6f50351f348f571316427ed65397e867b9c4f56f0911be9350c24bf97b36c393"],
  allowedAuthors: ["147ef995601c1693505c37ae9e0976229a00b3041a3cd38767b3ae3bc2302d3f" ],
  defaultTheme: 'light',
  // Optionaler NIP-96 Upload-Endpunkt (z. B. https://media.server/api/upload )
  mediaUploadEndpoint: '',
  // Blossom host (für Datei-Uploads & Verwaltung)
  blossom: { endpoint: 'https://blossom.band' },
  // NIP-46 (Bunker) – optional vordefinierte Connect-URI (kann per UI gesetzt werden)
  nip46: { connectURI: '' },
  // App metadata for NIP-78 client tags
  appTag: ['client', 'nostr-calendar-demo']
};
