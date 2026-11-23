import { createServer,IncomingMessage,ServerResponse } from "node:http";
import { SessionStore,createCookie,verifyCookie } from "./session.js";

const port=Number(process.env.PORT||3000);
const secret=process.env.SESSION_SECRET||"dev-only-secret";
const user=process.env.DEMO_USER||"demo";
const password=process.env.DEMO_PASSWORD||"change-me";
const store=new SessionStore();
const audit:Array<{at:string,event:string,user?:string}>=[];

function send(res:ServerResponse,status:number,data:unknown,headers:Record<string,string>={}) {
  res.writeHead(status,{"content-type":"application/json; charset=utf-8",...headers}); res.end(JSON.stringify(data));
}
function sid(req:IncomingMessage){return verifyCookie(req.headers.cookie,secret);}
function event(name:string,who?:string){audit.push({at:new Date().toISOString(),event:name,user:who}); if(audit.length>100)audit.shift();}
async function body(req:IncomingMessage){const chunks:Buffer[]=[];for await(const c of req)chunks.push(Buffer.from(c));try{return JSON.parse(Buffer.concat(chunks).toString()||"{}")}catch{return {}}}

createServer(async(req,res)=>{
  if(req.method==="GET"&&req.url==="/me"){
    const s=sid(req)?store.get(sid(req)!):null;
    return s?send(res,200,{authenticated:true,user:s.user,expiresAt:s.expiresAt}):send(res,401,{authenticated:false});
  }
  if(req.method==="POST"&&req.url==="/login"){
    const data=await body(req);
    if(data.username!==user||data.password!==password){event("login_failed",data.username);return send(res,401,{error:"invalid credentials"});}
    const s=store.create(user,1800000);event("login",user);
    return send(res,200,{authenticated:true,user},{ "set-cookie":createCookie(s.id,secret,1800)});
  }
  if(req.method==="POST"&&req.url==="/logout"){
    const id=sid(req);const s=id?store.get(id):null;if(id)store.delete(id);if(s)event("logout",s.user);
    return send(res,200,{loggedOut:true},{"set-cookie":"sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"});
  }
  if(req.method==="GET"&&req.url==="/audit")return send(res,200,audit);
  send(res,404,{error:"not found"});
}).listen(port,"127.0.0.1",()=>console.log(`SessionVault listening on http://127.0.0.1:${port}`));
