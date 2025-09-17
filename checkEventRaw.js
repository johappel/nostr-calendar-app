import WebSocket from 'ws';

(async () => {
  const id = 'a9ae2dac918f1ee4a3aaf16a8af4c7778705354b82895a40b917c186e996f4c6';
  const relays = [
    'wss://relay-rpi.edufeed.org',
    'wss://relilab.nostr1.com'
  ];

  for (const url of relays) {
    console.log(`\n==> Verbinde zu ${url}`);
    const ws = new WebSocket(url);
    await new Promise((res, rej) => {
      ws.once('open', res);
      ws.once('error', rej);
    });

    // Nostr-REQ zum Abfragen dieses Events
    const subId = 'check1';
    ws.send(JSON.stringify(['REQ', subId, { ids: [id] }]));

    const found = await new Promise(resolve => {
      ws.on('message', data => {
        const [type, sid, event] = JSON.parse(data);
        if (type === 'EVENT' && sid === subId) {
          console.log('✅ Gefunden:', event);
          resolve(true);
          ws.close();
        } else if (type === 'EOSE' && sid === subId) {
          console.log('❌ Nicht gefunden');
          resolve(false);
          ws.close();
        }
      });
    });
  }
  process.exit(0);
})();