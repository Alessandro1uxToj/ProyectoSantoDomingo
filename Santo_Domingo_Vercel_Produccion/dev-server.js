'use strict';
require('node:http').createServer(async(req,res)=>{
 if(req.url==='/api'){
  let content='';
  for await(const piece of req){content+=piece.toString();if(content.length>100000){res.writeHead(413).end();return;}}
  try{req.body=JSON.parse(content);}catch{res.writeHead(400).end('JSON inválido');return;}
  return require('./api/index.js')(req,res);
 }
 if(!['/','/index.html','/LogoCSD.png'].includes(req.url)){res.writeHead(404).end('No encontrado');return;}
 const filename=req.url==='/LogoCSD.png'?'LogoCSD.png':'index.html';
 const path=require('node:path').join(__dirname,'public',filename);
 const fs=require('node:fs');res.setHeader('Content-Type',filename.endsWith('.png')?'image/png':'text/html; charset=utf-8');
 fs.createReadStream(path).on('error',()=>res.writeHead(500).end()).pipe(res);
}).listen(Number(process.env.PORT||3000),()=>console.log('Portal local disponible en http://localhost:'+(process.env.PORT||3000)));
