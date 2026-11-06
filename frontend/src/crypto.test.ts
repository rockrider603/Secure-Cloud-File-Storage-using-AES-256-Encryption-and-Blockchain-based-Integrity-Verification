import {describe,it,expect} from 'vitest';
import {createBackup,unlockBackup,encryptFile,protectDek,decryptFile} from './crypto';
describe('secure file envelope',()=>{
 it('round trips binary content after digest verification',async()=>{
  const {backup,key}=await createBackup('correct horse battery staple');
  const file=new File([new Uint8Array([0,1,255,20])],'sample.bin',{type:'application/octet-stream'});
  const encrypted=await encryptFile(file);const protectedKey=await protectDek(key,encrypted.dek);
  const recoveredKey=await unlockBackup('correct horse battery staple',backup);
  const plain=await decryptFile(recoveredKey,encrypted.envelope,encrypted.digest,protectedKey,file.type);
  expect([...new Uint8Array(await plain.arrayBuffer())]).toEqual([0,1,255,20]);expect(backup.iterations).toBeGreaterThanOrEqual(600000);
 });
 it('refuses modified ciphertext before decryption',async()=>{
  const {key}=await createBackup('correct horse battery staple');const file=new File(['secret'],'x.txt');const encrypted=await encryptFile(file);const wrapped=await protectDek(key,encrypted.dek);encrypted.envelope[18]^=1;
  await expect(decryptFile(key,encrypted.envelope,encrypted.digest,wrapped,'text/plain')).rejects.toThrow(/Integrity check failed/);
 });
 it('rejects incorrect passphrase',async()=>{const {backup}=await createBackup('correct horse battery staple');await expect(unlockBackup('wrong passphrase',backup)).rejects.toThrow(/incorrect/)});
});
