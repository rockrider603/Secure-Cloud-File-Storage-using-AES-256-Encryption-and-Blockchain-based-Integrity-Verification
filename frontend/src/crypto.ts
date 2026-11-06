const encoder = new TextEncoder();
const iterations = 600_000;
const hex = (bytes: Uint8Array) => [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex = (value:string) => { if(!/^(?:[0-9a-f]{2})+$/i.test(value)) throw new Error('Malformed encrypted key backup'); return Uint8Array.from(value.match(/.{2}/g)!,b=>parseInt(b,16)); };
function random(size:number){ return crypto.getRandomValues(new Uint8Array(size)); }
async function passphraseKey(passphrase:string,salt:Uint8Array){
  if(passphrase.length<12) throw new Error('Use a key passphrase with at least 12 characters.');
  const material=await crypto.subtle.importKey('raw',encoder.encode(passphrase),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
export type Backup={salt:string;nonce:string;wrapped_key:string;iterations:number};
export async function createBackup(passphrase:string){
  const salt=random(16), nonce=random(12), master=random(32), kek=await passphraseKey(passphrase,salt);
  const wrapped=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce},kek,master));
  const key=await crypto.subtle.importKey('raw',master,'AES-GCM',false,['encrypt','decrypt']); master.fill(0);
  return {backup:{salt:hex(salt),nonce:hex(nonce),wrapped_key:hex(wrapped),iterations},key};
}
export async function unlockBackup(passphrase:string,backup:Backup){
  if(backup.iterations<600000||backup.iterations>2_000_000) throw new Error('Unsupported key backup parameters');
  try { const kek=await passphraseKey(passphrase,unhex(backup.salt)); const raw=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(backup.nonce)},kek,unhex(backup.wrapped_key))); const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']); raw.fill(0); return key; }
  catch { throw new Error('Passphrase is incorrect or the encrypted key backup is damaged.'); }
}
export async function encryptFile(file:File){
  const dek=random(32), nonce=random(12);
  const key=await crypto.subtle.importKey('raw',dek,'AES-GCM',false,['encrypt','decrypt']);
  const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce},key,await file.arrayBuffer()));
  const envelope=new Uint8Array(17+ciphertext.length); envelope.set(encoder.encode('SCFS'),0); envelope[4]=1; envelope.set(nonce,5); envelope.set(ciphertext,17);
  const digest=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',envelope)));
  return {envelope,digest,dek};
}
export async function protectDek(master:CryptoKey,dek:Uint8Array){
  const nonce=random(12), wrapped=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce},master,dek));
  return {nonce:hex(nonce),wrapped:hex(wrapped)};
}
export async function decryptFile(master:CryptoKey,envelope:Uint8Array,expectedDigest:string,backup:{nonce:string;wrapped:string},mime:string){
  if(envelope.length<33) throw new Error('Encrypted object is truncated.');
  const actual=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',envelope)));
  if(actual!==expectedDigest.toLowerCase()) throw new Error('Integrity check failed: downloaded ciphertext does not match the blockchain record. No plaintext was released.');
  if(new TextDecoder().decode(envelope.slice(0,4))!=='SCFS'||envelope[4]!==1) throw new Error('Unsupported encrypted file format.');
  try {
    const dek=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(backup.nonce)},master,unhex(backup.wrapped)));
    const key=await crypto.subtle.importKey('raw',dek,'AES-GCM',false,['decrypt']); dek.fill(0);
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:envelope.slice(5,17)},key,envelope.slice(17));
    return new Blob([plain],{type:mime||'application/octet-stream'});
  } catch { throw new Error('Decryption failed: key is wrong or ciphertext authentication failed.'); }
}
export const bytesToHex=hex;
