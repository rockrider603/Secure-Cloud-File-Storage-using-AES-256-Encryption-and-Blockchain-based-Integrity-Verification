import {useEffect,useState} from 'react';
import {api,setToken} from './api';
import {createBackup,unlockBackup,encryptFile,protectDek,decryptFile,type Backup} from './crypto';
type Version={id:string;version_number:number;size:number;digest:string;status:string;created_at:string};
type StoredFile={id:string;filename:string;mime_type:string;versions:Version[];created_at:string};
type Session={access_token:string;user:{id:string;email:string};crypto_backup:Backup|null};
const sizeText=(bytes:number)=>bytes<1024?`${bytes} B`:bytes<1048576?`${(bytes/1024).toFixed(1)} KB`:`${(bytes/1048576).toFixed(1)} MB`;
export default function App(){
 const [session,setSession]=useState<Session|null>(null),[master,setMaster]=useState<CryptoKey|null>(null),[files,setFiles]=useState<StoredFile[]>([]),[busy,setBusy]=useState(false),[message,setMessage]=useState(''),[error,setError]=useState(''),[selected,setSelected]=useState(''),[mode,setMode]=useState<'login'|'register'>('login');
 useEffect(()=>{const raw=sessionStorage.getItem('scfs-session');if(raw){try{const s=JSON.parse(raw) as Session;setSession(s);setToken(s.access_token)}catch{sessionStorage.removeItem('scfs-session')}}},[]);
 useEffect(()=>{if(session&&master) refresh().catch(e=>setError(e.message))},[session,master]);
 async function refresh(){const result=await api<{items:StoredFile[]}>('/files');setFiles(result.items)}
 function clearStatus(){setError('');setMessage('')}
 async function authenticate(e:React.FormEvent<HTMLFormElement>){e.preventDefault();clearStatus();setBusy(true);const form=new FormData(e.currentTarget);const email=String(form.get('email')),password=String(form.get('password')),passphrase=String(form.get('passphrase'));
  let issuedToken='';
  try{
   const s=await api<Session>(mode==='register'?'/auth/register':'/auth/login',{method:'POST',body:JSON.stringify({email,password})});
   issuedToken=s.access_token;setToken(s.access_token);let k:CryptoKey;
   if(s.crypto_backup){k=await unlockBackup(passphrase,s.crypto_backup)}else{const created=await createBackup(passphrase);k=created.key;s.crypto_backup=created.backup;await api('/auth/crypto-backup',{method:'PUT',body:JSON.stringify(created.backup)})}
   setSession(s);sessionStorage.setItem('scfs-session',JSON.stringify(s));setMaster(k);setMessage(mode==='register'?'Account created. Keep your key passphrase safe; it cannot be recovered.':'Signed in and key unlocked.');
  }catch(err){if(issuedToken){try{await api('/auth/logout',{method:'POST'})}catch{}}setToken(null);setError((err as Error).message)}finally{setBusy(false)}
 }
 async function upload(e:React.FormEvent<HTMLFormElement>){e.preventDefault();clearStatus();const input=e.currentTarget.elements.namedItem('file') as HTMLInputElement;const file=input.files?.[0];if(!file||!session||!master)return;
  if(file.size>100*1024*1024){setError('Files must be 100 MB or smaller.');return}setBusy(true);
  try{
   setMessage('Encrypting in this browser…');const encrypted=await encryptFile(file);
   setMessage('Creating private upload…');const record=await api<{file_id:string;version_id:string;upload:{url:string;fields:Record<string,string>}}>('/files',{method:'POST',body:JSON.stringify({filename:file.name,mime_type:file.type||'application/octet-stream',size:encrypted.envelope.length,digest:encrypted.digest})});
   const wrapped=await protectDek(master,encrypted.dek);encrypted.dek.fill(0);
   await api(`/files/${record.file_id}/versions/${record.version_id}/key-backup`,{method:'PUT',body:JSON.stringify({nonce:wrapped.nonce,wrapped_dek:wrapped.wrapped})});
   const form=new FormData();for(const [name,value] of Object.entries(record.upload.fields))form.append(name,value);form.append('file',new Blob([encrypted.envelope],{type:'application/octet-stream'}));
   const response=await fetch(record.upload.url,{method:'POST',body:form});if(!response.ok)throw new Error(`Encrypted upload failed (${response.status}); the version remains pending.`);
   setMessage('Anchoring ciphertext digest…');await api(`/files/${record.file_id}/versions/${record.version_id}/complete`,{method:'POST'});
   await refresh();setMessage(`Uploaded and verified ${file.name} (${sizeText(file.size)}).`);input.value='';setSelected('');
  }catch(err){setError((err as Error).message)}finally{setBusy(false)}
 }
 async function download(file:StoredFile,version:Version){clearStatus();if(!session||!master)return;setBusy(true);
  try{
   const info=await api<{download_url:string;filename:string;mime_type:string}>(`/files/${file.id}/versions/${version.id}/download-url`,{method:'POST'});
   const [response,anchor,key]=await Promise.all([fetch(info.download_url),api<{digest:string}>(`/files/${file.id}/versions/${version.id}/integrity`),api<{nonce:string;wrapped_dek:string}>(`/files/${file.id}/versions/${version.id}/key-backup`)]);
   if(!response.ok)throw new Error('Encrypted object is missing or unavailable.');const envelope=new Uint8Array(await response.arrayBuffer());
   const blob=await decryptFile(master,envelope,anchor.digest,{nonce:key.nonce,wrapped:key.wrapped_dek},info.mime_type);
   const href=URL.createObjectURL(blob),a=document.createElement('a');a.href=href;a.download=info.filename;a.click();setTimeout(()=>URL.revokeObjectURL(href),1000);setMessage(`Verified against the blockchain and downloaded ${info.filename}.`);
  }catch(err){const detail=(err as Error).message;const outcome=detail.startsWith('Integrity check failed')?'digest_mismatch':detail.startsWith('Encrypted object is missing')?'object_missing':detail.startsWith('Decryption failed')?'decrypt_failed':null;if(outcome)api(`/files/${file.id}/versions/${version.id}/integrity/report`,{method:'POST',body:JSON.stringify({outcome})}).catch(()=>{});setError(detail)}finally{setBusy(false)}
 }
 async function logout(){try{await api('/auth/logout',{method:'POST'})}catch{}setToken(null);setMaster(null);setSession(null);setFiles([]);sessionStorage.removeItem('scfs-session');clearStatus()}
 if(!session||!master)return <main className="auth-shell"><section className="auth-intro"><div className="brand"><span className="brand-mark">V</span> VAULT <small>PRIVATE FILE STORAGE</small></div><div><div className="eyebrow">CLIENT SIDE ENCRYPTION · VERIFIED STORAGE</div><h1>Your files,<br/><em>under your key.</em></h1><p>Encrypted in your browser before upload. Every version independently checked against a local integrity registry before it can be opened.</p></div><div className="trust-note"><span className="dot"/> AES-256-GCM · SHA-256 · ETHEREUM COMPATIBLE</div></section>
 <section className="auth-panel"><div className="panel-top"><span>SECURE ACCESS</span><span>01 / 01</span></div><div className="form-wrap"><div className="eyebrow">YOUR PRIVATE VAULT</div><h2>{mode==='login'?'Welcome back':'Create your vault'}</h2><p className="muted">{mode==='login'?'Sign in and unlock your local encryption key.':'Your key passphrase never reaches the server.'}</p>
 <form onSubmit={authenticate}><label>Email<input name="email" type="email" autoComplete="email" required placeholder="you@example.com"/></label><label>Account password<input name="password" type="password" minLength={12} autoComplete={mode==='login'?'current-password':'new-password'} required placeholder="At least 12 characters"/></label><label>Key passphrase<input name="passphrase" type="password" minLength={12} autoComplete="off" required placeholder="At least 12 characters"/><small>Forgotten passphrases cannot be recovered by the service.</small></label><button className="primary" disabled={busy}>{busy?'SECURELY PROCESSING…':mode==='login'?'SIGN IN & UNLOCK':'CREATE ACCOUNT'}</button></form>
 <div className="switch">{mode==='login'?"New to Vault?":"Already have an account?"} <button onClick={()=>{setMode(mode==='login'?'register':'login');clearStatus()}}>{mode==='login'?'Create account':'Sign in'}</button></div>{error&&<div className="alert error">{error}</div>}{message&&<div className="alert">{message}</div>}</div><div className="panel-footer">YOUR PASSPHRASE NEVER LEAVES THIS DEVICE <span>⌁</span></div></section></main>;
 return <main className="dashboard"><header className="topbar"><div className="brand dark"><span className="brand-mark">V</span> VAULT</div><div className="user-chip"><span className="avatar">{session.user.email[0].toUpperCase()}</span><span>{session.user.email}</span><button onClick={logout}>SIGN OUT ↗</button></div></header>
 <section className="dash-head"><div><div className="eyebrow">YOUR PRIVATE STORAGE</div><h1>File vault<span className="count">{files.length.toString().padStart(2,'0')}</span></h1><p>Each file is encrypted locally and verified against an immutable digest.</p></div><div className="security-pill"><span className="dot"/> KEY UNLOCKED LOCALLY</div></section>
 <section className="upload-card"><div className="upload-symbol">↑</div><div className="upload-copy"><h3>Add an encrypted file</h3><p>{selected||'Choose a file up to 100 MB. Plaintext stays in this browser.'}</p></div><form onSubmit={upload} className="upload-form"><label className="file-button">CHOOSE FILE<input type="file" name="file" required disabled={busy} onChange={e=>{const f=e.target.files?.[0];setSelected(f?`${f.name} · ${sizeText(f.size)}`:'')}}/></label><button className="primary" disabled={busy}>ENCRYPT & UPLOAD ↗</button></form></section>
 {(error||message)&&<div className={`alert ${error?'error':''}`}>{error||message}</div>}
 <div className="section-title"><span>YOUR FILES</span><span>{files.length} {files.length===1?'FILE':'FILES'} · OWNER ONLY</span></div>
 {files.length===0?<section className="empty"><div>▧</div><h3>Your vault is ready</h3><p>Files are encrypted here before they leave your device.</p></section>:<div className="file-list">{files.map(file=><article className="file-card" key={file.id}><div className="file-icon">▤</div><div className="file-main"><h3>{file.filename}</h3><p>{file.versions.length} immutable {file.versions.length===1?'version':'versions'} · {file.mime_type}</p></div><div className="version-stack">{file.versions.map(v=><div className="version-row" key={v.id}><span className={`status ${v.status}`}>{v.status==='ready'?'● VERIFIED':'◌ PENDING'}</span><span>V{v.version_number} · {sizeText(v.size)}</span><button disabled={busy||v.status!=='ready'} onClick={()=>download(file,v)}>VERIFY & DOWNLOAD ↓</button></div>)}</div></article>)}</div>}
 <footer className="security-footer"><span>◈</span><div><b>Client-side privacy</b><p>Files and decryption keys never reach the application server. Blockchain records contain only random identifiers and ciphertext digests.</p></div><span className="chain-label">LOCAL EVM · SHA-256</span></footer>
 </main>;
}
