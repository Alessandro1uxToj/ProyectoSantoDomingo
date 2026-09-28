'use strict';
const {Pool}=require('pg');
const crypto=require('node:crypto');
const {requestScope,executeOperation,GRADES,SUBJECTS,YEAR,all,get,put}=require('./engine');
const SESSION_COOKIE='sd_session';
const WRITE_OPS=new Set(['createUser','resetPassword','updateUser','deleteUser','changeAdminPassword','changeOwnPassword','addSubject','editSubject','saveStudentCard','submitStudent','submitGrade','reopenStudent','publishStudent','publishAll','markResultsRead']);
const OPS=new Set(['login','logout','me','users','createUser','credentials','resetPassword','updateUser','deleteUser','changeAdminPassword','changeOwnPassword','subjects','addSubject','editSubject','debtList','studentList','studentCard','saveStudentCard','submitStudent','submitGrade','reopenStudent','publishStudent','publishAll','honors','overview','studentUpdates','studentSubjects','markResultsRead','studentResults']);
let pool;
function config(){
 const url=process.env.DATABASE_URL||process.env.POSTGRES_URL;
 const session=process.env.SESSION_SECRET,secret=process.env.AUTH_ENCRYPTION_KEY;
 if(!url||!session||session.length<32||!secret||secret.length<32)throw new Error('Faltan DATABASE_URL, SESSION_SECRET o AUTH_ENCRYPTION_KEY. Revisa README.md.');
 if(!pool)pool=new Pool({connectionString:url,max:2,connectionTimeoutMillis:7000,idleTimeoutMillis:20000});
 return{pool,session,key:crypto.createHash('sha256').update(secret).digest()};
}
function seal(value,key){
 const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);
 const encrypted=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
 return Buffer.concat([iv,cipher.getAuthTag(),encrypted]).toString('base64url');
}
function unseal(value,key){
 const bytes=Buffer.from(value,'base64url');if(bytes.length<29)throw new Error('Contraseña almacenada no válida.');
 const decipher=crypto.createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));decipher.setAuthTag(bytes.subarray(12,28));
 return Buffer.concat([decipher.update(bytes.subarray(28)),decipher.final()]).toString('utf8');
}
function encodeUser(user,ctx){
 const row=structuredClone(user);const password=row.password;delete row.password;
 const prior=ctx.secrets.get(String(user.id));
 if(prior&&prior.password===password)row._secret=prior.secret;
 else{
  const salt=crypto.randomBytes(16);
  row._secret={hash:crypto.scryptSync(password,salt,64).toString('base64url'),salt:salt.toString('base64url'),encrypted:seal(password,ctx.key)};
 }
 return row;
}
function decodeUser(value,ctx){
 const row=structuredClone(value);const secret=row._secret;
 if(!secret||!secret.encrypted)throw new Error('Cuenta sin credenciales protegidas.');
 delete row._secret;row.password=unseal(secret.encrypted,ctx.key);
 ctx.secrets.set(String(row.id),{secret,password:row.password});return row;
}
function verifyPassword(password,user,ctx){
 if(typeof password!=='string')return false;
 const entry=ctx.secrets.get(String(user.id));if(!entry)return false;
 const salt=Buffer.from(entry.secret.salt,'base64url');
 const expected=Buffer.from(entry.secret.hash,'base64url');
 if(expected.length!==64)return false;
 return crypto.timingSafeEqual(crypto.scryptSync(password,salt,64),expected);
}
function signSession(user,secret){
 const value=Buffer.from(JSON.stringify({id:user.id,version:user.token_version,exp:Date.now()+12*3600*1000})).toString('base64url');
 const mac=crypto.createHmac('sha256',secret).update(value).digest('base64url');return value+'.'+mac;
}
function parseSession(req,secret){
 const cookie=String(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(SESSION_COOKIE+'='));
 if(!cookie)return null;const token=cookie.slice(SESSION_COOKIE.length+1);const [payload,sig,...rest]=token.split('.');
 if(!payload||!sig||rest.length||payload.length>1024)return null;
 const mac=crypto.createHmac('sha256',secret).update(payload).digest();
 let received;try{received=Buffer.from(sig,'base64url');}catch{return null;}
 if(mac.length!==received.length||!crypto.timingSafeEqual(mac,received))return null;
 try{const data=JSON.parse(Buffer.from(payload,'base64url').toString());if(!Number.isSafeInteger(data.id)||!Number.isSafeInteger(data.version)||!Number.isSafeInteger(data.exp)||Date.now()>data.exp)return null;return data;}catch{return null;}
}
function sessionCookie(req,token,maxAge=43200){
 const https=String(req.headers['x-forwarded-proto']||'').split(',')[0].trim()==='https'||Boolean(req.socket?.encrypted);
 return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; ${https?'Secure; ':''}Max-Age=${maxAge}`;
}
function send(res,status,body){res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store, private');res.setHeader('X-Content-Type-Options','nosniff');res.end(JSON.stringify(body));}
function ipKey(req,username){
 const ip=String(req.headers['x-forwarded-for']||req.socket?.remoteAddress||'unknown').split(',')[0].trim().slice(0,80);
 return crypto.createHash('sha256').update(ip+'\0'+username).digest('hex');
}
async function beforeLogin(client,key){
 const {rows}=await client.query('SELECT attempts, first_at, locked_until FROM sd_login_attempts WHERE key=$1',[key]);
 if(rows[0]?.locked_until&&new Date(rows[0].locked_until).getTime()>Date.now())return false;
 return true;
}
async function failedLogin(client,key){
 await client.query(`INSERT INTO sd_login_attempts(key, attempts, first_at, locked_until) VALUES ($1,1,now(),NULL)
 ON CONFLICT(key) DO UPDATE SET
 attempts=CASE WHEN sd_login_attempts.first_at<now()-interval '15 minutes' THEN 1 ELSE sd_login_attempts.attempts+1 END,
 first_at=CASE WHEN sd_login_attempts.first_at<now()-interval '15 minutes' THEN now() ELSE sd_login_attempts.first_at END,
 locked_until=CASE WHEN sd_login_attempts.first_at>=now()-interval '15 minutes' AND sd_login_attempts.attempts>=7 THEN now()+interval '15 minutes' ELSE NULL END`,[key]);
}
async function loadContext(client,key){
 const ctx={client,key,stores:{users:new Map(),subjects:new Map(),scores:new Map(),periods:new Map(),studentPeriods:new Map()},dirty:new Map(),secrets:new Map(),lastId:0,nextId:async()=>{const {rows}=await client.query("SELECT nextval('sd_record_ids') AS id");return Number(rows[0].id);}};
 const {rows}=await client.query('SELECT kind, record_key, payload FROM sd_records');
 for(const {kind,record_key,payload} of rows){
  if(!(kind in ctx.stores))throw new Error('Tipo de registro desconocido.');
  const row=kind==='users'?decodeUser(payload,ctx):payload;
  ctx.stores[kind].set(record_key,row);
  if((kind==='users'||kind==='subjects')&&Number(record_key)>ctx.lastId)ctx.lastId=Number(record_key);
 }
 return ctx;
}
async function ensureInitialData(ctx){
 const {rows}=await ctx.client.query("SELECT value FROM sd_meta WHERE key='initialized'");
 if(rows.length)return;
 const initial=process.env.ADMIN_INITIAL_PASSWORD;
 if(!initial||initial.length<12)throw new Error('Configura ADMIN_INITIAL_PASSWORD con 12 caracteres o más antes del primer uso.');
 const adminId=await put('users',{username:'admin',password:initial,full_name:'Dirección',role:'admin',grade_code:null,delinquent:false,active:true,token_version:0});
 const admin=await get('users',adminId);const secured=encodeUser(admin,ctx);ctx.secrets.set(String(adminId),{secret:secured._secret,password:initial});
 for(const g of GRADES){const seed=SUBJECTS[g.code]||[];for(let i=0;i<seed.length;i++)await put('subjects',{grade_code:g.code,name:seed[i],seed_key:seed[i],order:i+1,active:true,deleted:false});}
 await ctx.client.query("INSERT INTO sd_meta(key,value) VALUES ('initialized',$1)",[JSON.stringify({year:YEAR,created:new Date().toISOString()})]);
}
async function persist(ctx){
 const upserts=[],deletions=[];
 for(const change of ctx.dirty.values()){
  if(change.row===null){deletions.push(change);continue;}
  const value=change.name==='users'?encodeUser(change.row,ctx):change.row;
  upserts.push([change.name,change.key,JSON.stringify(value)]);
 }
 if(upserts.length){
  await ctx.client.query(`INSERT INTO sd_records(kind,record_key,payload)
 SELECT t.kind,t.record_key,t.payload FROM UNNEST($1::text[],$2::text[],$3::jsonb[]) AS t(kind,record_key,payload)
 ON CONFLICT (kind,record_key) DO UPDATE SET payload=EXCLUDED.payload`,[upserts.map(x=>x[0]),upserts.map(x=>x[1]),upserts.map(x=>x[2])]);
 }
 if(deletions.length){
  await ctx.client.query(`DELETE FROM sd_records r USING UNNEST($1::text[],$2::text[]) AS t(kind,record_key)
 WHERE r.kind=t.kind AND r.record_key=t.record_key`,[deletions.map(x=>x.name),deletions.map(x=>x.key)]);
 }
}
async function run(req,res,configuration){
 const client=await configuration.pool.connect();let begun=false;
 try{
  await client.query('BEGIN');begun=true;
  await client.query('SELECT pg_advisory_xact_lock(8202211)');
  const ctx=await loadContext(client,configuration.key);
  let response,code=200,token=null,clear=false;
  await requestScope.run(ctx,async()=>{
   await ensureInitialData(ctx);
   const {op,body={},query={}}=req.body;
   if(op==='login'){
    const username=String(body.username||'').trim().toLowerCase().slice(0,80);
    const key=ipKey(req,username);
    if(!await beforeLogin(client,key)){code=429;response={error:'Demasiados intentos. Espera 15 minutos para volver a intentarlo.'};return;}
    const person=(await all('users')).find(u=>u.active&&u.username.toLowerCase()===username);
    if(!person||!verifyPassword(body.password,person,ctx)){
     await failedLogin(client,key);code=401;response={error:'Usuario o contraseña incorrectos.'};return;
    }
    await client.query('DELETE FROM sd_login_attempts WHERE key=$1',[key]);
    token=signSession(person,configuration.session);response={success:true};return;
   }
   if(op==='logout'){clear=true;response={success:true};return;}
   const session=parseSession(req,configuration.session);
   const actor=session?await get('users',session.id):null;
   if(!actor||!actor.active||actor.token_version!==session.version){code=401;response={error:'Tu sesión finalizó. Vuelve a iniciar sesión.'};clear=true;return;}
   try{response=await executeOperation(op,{body,query},actor);if(op==='changeAdminPassword'||op==='changeOwnPassword')clear=true;}
   catch(e){code=/Sin autorización|Solo dirección|Solo estudiantes|Solo puedes|No puedes|exclusivamente|Solo el docente/.test(e.message)?403:400;response={error:e.message};}
  });
  await persist(ctx);
  await client.query('COMMIT');begun=false;
  if(token)res.setHeader('Set-Cookie',sessionCookie(req,token));
  if(clear)res.setHeader('Set-Cookie',sessionCookie(req,'',0));
  send(res,code,response||{success:true});
 }catch(e){if(begun)try{await client.query('ROLLBACK');}catch{};console.error('Fallo interno de plataforma:',e?.code||e?.message||'desconocido');send(res,503,{error:'No se pudo conectar con la base de datos o inicializar la plataforma. Consulta los registros del proyecto y su configuración.'});}
 finally{client.release();}
}
module.exports=async function handler(req,res){
 if(req.method!=='POST'){res.setHeader('Allow','POST');return send(res,405,{error:'Método no permitido.'});}
 const origin=req.headers.origin;
 if(origin){try{const o=new URL(origin),host=String(req.headers.host||'').toLowerCase();if(o.host.toLowerCase()!==host||!['http:','https:'].includes(o.protocol))return send(res,403,{error:'Origen no autorizado.'});}catch{return send(res,403,{error:'Origen no autorizado.'});}}
 const fetchSite=req.headers['sec-fetch-site'];if(fetchSite&&!['same-origin','none'].includes(fetchSite))return send(res,403,{error:'Solicitud de otro sitio no autorizada.'});
 const length=Number(req.headers['content-length']||0);if(length>100000)return send(res,413,{error:'La solicitud es demasiado grande.'});
 if(!String(req.headers['content-type']||'').toLowerCase().startsWith('application/json'))return send(res,415,{error:'Envía datos en formato JSON.'});
 if(!req.body||typeof req.body!=='object'||Array.isArray(req.body)||!OPS.has(req.body.op))return send(res,400,{error:'Operación no reconocida.'});
 if(req.body.body&& (typeof req.body.body!=='object'||Array.isArray(req.body.body)))return send(res,400,{error:'Datos inválidos.'});
 if(req.body.query&& (typeof req.body.query!=='object'||Array.isArray(req.body.query)))return send(res,400,{error:'Consulta inválida.'});
 try{const cfg=config();return await run(req,res,cfg);}catch(e){console.error('Plataforma:',e.message);return send(res,503,{error:'Servicio no configurado o temporalmente no disponible. Revisa las variables de entorno de Vercel.'});}
};
