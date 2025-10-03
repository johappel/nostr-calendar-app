export function secsToLocalInput(secs){
  const d = new Date(secs*1000);
  const tzoffset = d.getTimezoneOffset()*60000;
  const localISO = new Date(d - tzoffset).toISOString().slice(0,16);
  return localISO;
}
export function localInputToSecs(val){
  if(!val) return null;
  const d = new Date(val);
  return Math.floor(d.getTime()/1000);
}
export function formatDateRange(startS, endS){
  const s = new Date(startS*1000), e = new Date(endS*1000);
  const optsDate = {weekday:'short', day:'2-digit', month:'short', year:'numeric'};
  const optsTime = {hour:'2-digit', minute:'2-digit'};
  const sameDay = s.toDateString()===e.toDateString();
  const date = s.toLocaleDateString(undefined, optsDate);
  const time = s.toLocaleTimeString(undefined, optsTime) + (sameDay? ' – '+e.toLocaleTimeString(undefined, optsTime) : '');
  return date + ', ' + time;
}
export function uid(len=8){
  return Math.random().toString(36).slice(2,2+len);
}
export function b64(str){
  return btoa(decodeURI(encodeURIComponent(str)));
}
export function unb64(str){
  try { return decodeURIComponent(escape(atob(str))); } catch(e){ return str; }
}
export function sanitizeHTML(html){
  // very tiny sanitizer (keeps a, strong, em, p, img)
  const div = document.createElement('div');
  div.innerHTML = html;
  div.querySelectorAll('*').forEach(el=>{
    if(!['A','P','EM','STRONG','B','I','UL','OL','LI','BR','IMG','H1','H2','H3','H4'].includes(el.tagName)){
      el.replaceWith(...el.childNodes);
    }
    if(el.tagName==='A'){
      el.setAttribute('rel','noopener noreferrer');
      el.setAttribute('target','_blank');
    }
  });
  return div.innerHTML;
}
export function mdToHtml(md){
  // minimal markdown -> html (bold, italic, links, images, line breaks)
  let h = md
    .replace(/^### (.*$)/gim,'<h3>$1</h3>')
    .replace(/^## (.*$)/gim,'<h2>$1</h2>')
    .replace(/^# (.*$)/gim,'<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/gim,'<strong>$1</strong>')
    .replace(/\*(.*?)\*/gim,'<em>$1</em>')
    .replace(/!\[(.*?)\]\((.*?)\)/gim,'<img alt="$1" src="$2" />')
    .replace(/\[(.*?)\]\((.*?)\)/gim,'<a href="$2">$1</a>')
    .replace(/\n$/gim,'<br/>');

  return sanitizeHTML(h);
}

// Neue DOM-Helpers aus app.js ausgelagert
export function on(el, evt, fn){ 
  if(el && el.addEventListener) el.addEventListener(evt, fn); 
}

export function chip(label, onRemove) {
  const c = document.createElement('span');
  c.className='chip';
  c.innerHTML = `<span>${label}</span>`;
  const x = document.createElement('button'); 
  x.textContent='✕';
  x.addEventListener('click', ()=>{
    onRemove(label);
    c.remove();
  });
  c.appendChild(x);
  return c;
}

export function setupModal(dlg, onClose) {
  // Basis-Setup für Modals (erweiterbar)
  if (onClose) {
    dlg.addEventListener('close', onClose);
  }
  return dlg;
}
