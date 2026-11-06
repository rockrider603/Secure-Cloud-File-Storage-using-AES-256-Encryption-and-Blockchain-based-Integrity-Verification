const base=import.meta.env.VITE_API_URL||'http://localhost:8000/api/v1';
let token:string|null=null;
export const setToken=(value:string|null)=>{token=value};
export async function api<T>(path:string,init:RequestInit={}){
  const headers=new Headers(init.headers); if(token) headers.set('Authorization',`Bearer ${token}`);
  if(init.body && !(init.body instanceof FormData)) headers.set('Content-Type','application/json');
  const response=await fetch(base+path,{...init,headers});
  if(!response.ok){let detail=`Request failed (${response.status})`; try{detail=(await response.json()).detail||detail}catch{} throw new Error(detail)}
  return response.json() as Promise<T>;
}
