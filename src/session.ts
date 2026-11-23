import { createHmac, randomBytes } from "node:crypto";

export interface Session { id:string; user:string; createdAt:number; expiresAt:number; }

export class SessionStore {
  private sessions=new Map<string,Session>();
  create(user:string,ttlMs:number,now=Date.now()):Session {
    const s={id:randomBytes(32).toString("base64url"),user,createdAt:now,expiresAt:now+ttlMs};
    this.sessions.set(s.id,s); return s;
  }
  get(id:string,now=Date.now()):Session|null {
    const s=this.sessions.get(id);
    if(!s)return null;
    if(s.expiresAt<=now){this.sessions.delete(id);return null;}
    return s;
  }
  delete(id:string){return this.sessions.delete(id);}
}

export function signSessionId(id:string,secret:string){
  return createHmac("sha256",secret).update(id).digest("base64url");
}
export function createCookie(id:string,secret:string,maxAge:number){
  return `sid=${id}.${signSessionId(id,secret)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
export function verifyCookie(cookie:string|undefined,secret:string):string|null {
  if(!cookie)return null;
  const m=cookie.match(/(?:^|;\s*)sid=([^;]+)/); if(!m)return null;
  const [id,sig]=m[1].split("."); if(!id||!sig)return null;
  return sig===signSessionId(id,secret)?id:null;
}
