import { getStore } from '@netlify/blobs';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const STORE = 'trade-private-records-v1';
const KEY = 'master';
const COOKIE = 'trade_session';
const MAX_BYTES = 4_000_000;
const TTL_MS = 12 * 60 * 60 * 1000;
function json(data,status=200,extra={}) {
  return new Response(JSON.stringify(data), {status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer',...extra}});
}
function cookie(name, value, more='') {return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; ${more}`}
function envOk(){return (process.env.APP_PASSWORD||'').length>=14&&(process.env.APP_SESSION_SECRET||'').length>=32}
function sig(v){return createHmac('sha256',process.env.APP_SESSION_SECRET).update(v).digest('base64url')}
function equal(a,b){const ab=Buffer.from(a),bb=Buffer.from(b);return ab.length===bb.length&&timingSafeEqual(ab,bb)}
function validSession(req){
 const cookies=req.headers.get('cookie')||'';
 const value=cookies.split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1);
 if(!value)return false;
 const [expiry,nonce,signature]=value.split('.');
 if(!/^\d{13}$/.test(expiry||'')||!nonce||!signature||Number(expiry)<Date.now())return false;
 return equal(sig(`${expiry}.${nonce}`),signature);
}
function sameOrigin(req) {
 const origin=req.headers.get('origin');
 if(!origin)return false;
 try{return new URL(origin).origin===new URL(req.url).origin}catch{return false}
}
function verifyPassword(input,expected){
 const salt='netlify-trade-login-v1';
 const a=scryptSync(input,salt,64,{N:16384,r:8,p:1});
 const b=scryptSync(expected,salt,64,{N:16384,r:8,p:1});
 return timingSafeEqual(a,b);
}
function validateBody(body){
 if(!body||!Array.isArray(body.headers)||body.headers.length!==67||!Array.isArray(body.rows)||body.rows.length>20000)return false;
 if(body.headers[1]!=='상호'||body.headers[2]!=='대표자명')return false;
 if(!body.headers.every(x=>typeof x==='string'&&x.length<150))return false;
 return body.rows.every(row=>Array.isArray(row)&&row.length===67&&row.every(x=>typeof x==='string'&&x.length<=4000));
}
export default async (req) => {
 try {
  if(!envOk())return json({error:'서버 환경변수 APP_PASSWORD(14자 이상), APP_SESSION_SECRET(32자 이상)을 설정해야 합니다.'},503);
  const url=new URL(req.url),route=url.pathname.replace(/\/$/,'').split('/').at(-1);
  if(route==='session'&&req.method==='GET')return json({authenticated:validSession(req)});
  if(route==='login'&&req.method==='POST'){
   if(!sameOrigin(req))return json({error:'유효하지 않은 출처입니다.'},403);
   const raw=await req.text();if(raw.length>1000)return json({error:'입력 크기를 초과했습니다.'},413);
   const {password}=JSON.parse(raw);
   if(typeof password!=='string'||password.length<1||password.length>256||!verifyPassword(password,process.env.APP_PASSWORD))return json({error:'비밀번호가 올바르지 않습니다.'},401);
   const expiry=String(Date.now()+TTL_MS),nonce=randomBytes(12).toString('base64url');
   return json({authenticated:true},200,{'set-cookie':cookie(COOKIE,`${expiry}.${nonce}.${sig(expiry+'.'+nonce)}`,'Max-Age=43200')});
  }
  if(route==='logout'&&req.method==='POST'){
   if(!sameOrigin(req))return json({error:'유효하지 않은 출처입니다.'},403);
   return json({ok:true},200,{'set-cookie':cookie(COOKIE,'','Max-Age=0')});
  }
  if(!validSession(req))return json({error:'로그인이 필요합니다.'},401);
  if(route!=='data')return json({error:'존재하지 않는 API입니다.'},404);
  const store=getStore(STORE);
  if(req.method==='GET'){
   const entry=await store.getWithMetadata(KEY,{type:'json',consistency:'strong'});
   return json(entry?{initialized:true,headers:entry.data.headers,rows:entry.data.rows,etag:entry.etag}:{initialized:false,headers:null,rows:[],etag:null});
  }
  if(req.method==='PUT'){
   if(!sameOrigin(req))return json({error:'유효하지 않은 출처입니다.'},403);
   const raw=await req.text();if(Buffer.byteLength(raw,'utf8')>MAX_BYTES)return json({error:'저장 데이터가 너무 큽니다.'},413);
   const body=JSON.parse(raw);
   if(!validateBody(body))return json({error:'엑셀 데이터 형식이 올바르지 않습니다.'},400);
   const opts=body.etag?{onlyIfMatch:body.etag}:{onlyIfNew:true};
   const result=await store.setJSON(KEY,{headers:body.headers,rows:body.rows},opts);
   if(!result.modified)return json({error:'다른 기기에서 데이터가 변경되었습니다. 최신 데이터 불러오기 후 다시 수정해 주세요.'},409);
   return json({ok:true,etag:result.etag});
  }
  return json({error:'지원하지 않는 요청입니다.'},405);
 } catch(err){
  console.error('private API error:',err?.message||err);
  return json({error:err instanceof SyntaxError?'요청 형식이 올바르지 않습니다.':'서버 처리 중 오류가 발생했습니다.'},err instanceof SyntaxError?400:500);
 }
};
export const config={path:['/api/session','/api/login','/api/logout','/api/data']};
