// NIP-96 (HTTP File Storage) helpers with NIP-98 style Authorization header.
import { Config } from './config.js';

async function sha256Hex(blob){
  const buf = await blob.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map(b=>b.toString(16).padStart(2,'0')).join('');
}
function b64json(obj){
  return btoa(decodeURI(encodeURIComponent(JSON.stringify(obj))));
}

export async function signHttpAuth({ signer, method, url, payloadSha256='' }){
  // Build NIP-98 event (kind 27235) with method/url/sha256
  const evt = {
    kind: 27235,
    created_at: Math.floor(Date.now()/1000),
    tags: [
      ['u', url],
      ['method', method.toUpperCase()],
    ],
    content: payloadSha256
  };
  const signed = await signer.signEvent(evt);
  return 'Nostr ' + b64json(signed);
}

export async function uploadWithNip96(file, signer){
  const endpoint = (Config.mediaUploadEndpoint||'').replace(/\/$/,''); // expect server supports multipart + Authorization
  if(!endpoint) throw new Error('No mediaUploadEndpoint configured');

  const url = endpoint;
  const fd = new FormData();
  fd.append('file', file);

  const sha = await sha256Hex(file);
  const auth = await signHttpAuth({ signer, method:'POST', url, payloadSha256: sha });

  const res = await fetch(url, {
    method: 'POST',
    body: fd,
    headers: { 'Authorization': auth }
  });
  if(!res.ok) throw new Error('NIP-96 upload failed: ' + res.status);
  const json = await res.json().catch(()=> ({}));
  const outUrl = json.url || json.location || json.href;
  if(!outUrl) throw new Error('Upload ok, aber keine URL in Antwort.');
  return { url: outUrl, meta: json };
}
