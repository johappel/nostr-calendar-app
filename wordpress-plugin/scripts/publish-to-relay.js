import WebSocket from 'ws';

const relay = process.argv[2];
if (!relay) {
  console.error('FAIL: missing relay argument');
  process.exit(2);
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => (input += c));
process.stdin.on('end', () => {
  let message;
  try {
    message = JSON.parse(input);
  } catch (e) {
    console.error('FAIL: invalid JSON input');
    process.exit(2);
  }

  const ws = new WebSocket(relay);
  const event = Array.isArray(message) && message[0] === 'EVENT' ? message[1] : null;
  const expectedId = event && event.id ? event.id : null;
  let finished = false;

  const timeout = setTimeout(() => {
    if (!finished) {
      console.error('FAIL: timeout waiting for relay reply');
      finished = true;
      ws.terminate();
      process.exit(2);
    }
  }, 8000);

  ws.on('open', () => {
    try {
      ws.send(JSON.stringify(message));
    } catch (err) {
      console.error('FAIL: send error: ' + err.message);
      finished = true;
      clearTimeout(timeout);
      ws.terminate();
      process.exit(2);
    }
  });

  ws.on('message', (data) => {
    try {
      const parsed = JSON.parse(data);
      const type = parsed[0];

      if (type === 'OK') {
        // ["OK", <id>, <true|false>, <message>]
        const okId = parsed[1];
        const okFlag = parsed[2];
        const okMsg = parsed[3] || '';
        if (expectedId && okId === expectedId && okFlag === true) {
          console.log('SUCCESS');
          console.log(JSON.stringify(parsed));
          finished = true;
          clearTimeout(timeout);
          ws.close();
          process.exit(0);
        } else {
          console.error('FAIL: OK response but not accepted: ' + JSON.stringify(parsed));
          finished = true;
          clearTimeout(timeout);
          ws.close();
          process.exit(2);
        }
      } else if (type === 'NOTICE') {
        // ["NOTICE", "reason"]
        console.error('FAIL: NOTICE: ' + (parsed[1] || ''));
        finished = true;
        clearTimeout(timeout);
        ws.close();
        process.exit(2);
      } else if (type === 'EOSE') {
        // End of stream without OK
        console.error('FAIL: EOSE without OK');
        finished = true;
        clearTimeout(timeout);
        ws.close();
        process.exit(2);
      } else {
        // ignore other messages
      }
    } catch (err) {
      // ignore parse errors of non-json frames
    }
  });

  ws.on('error', (err) => {
    if (!finished) {
      console.error('FAIL: ws error: ' + (err && err.message ? err.message : String(err)));
      finished = true;
      clearTimeout(timeout);
      process.exit(2);
    }
  });

  ws.on('close', () => {
    if (!finished) {
      console.error('FAIL: connection closed before OK');
      finished = true;
      clearTimeout(timeout);
      process.exit(2);
    }
  });
});