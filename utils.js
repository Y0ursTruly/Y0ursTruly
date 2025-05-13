atob ||= (text) => Buffer.from(text, 'base64').toString('binary')
btoa ||= (text) => Buffer.from(text, 'binary').toString('base64')
var http=require('node:http'), https=require('node:https'), crypto=require('node:crypto'), fs=require('node:fs')
const {createHash,scrypt,createCipheriv,createDecipheriv}=crypto, {aes256key,salt}=process.env
//abstraction to use https where it is available, else http
//https is seen as available if "tls_key" and "tls_cert" are environment variables
//where "tls_key" is the private key file location and "tls_cert" is the certificate file location (fullchain.pem for letsencrypt)

//alternatively, these attributes can be passed in as an object as the second argument to the exported module with the same attributes mentioned
//and if the values are NOT strings (like buffers), they would be treated as the key and cert DIRECTLY

//also ensure that "port" is set in either the environment
const https=require('node:https'), http=require('node:http'), fs=require('node:fs')
function create_server(responder,options={}){
  let {tls_key,tls_cert}=options
  tls_key ||= process.env.tls_key || process.env.TLS_KEY
  tls_cert ||= process.env.tls_cert || process.env.TLS_CERT
  const ownsCert=tls_key&&tls_cert
  let key=typeof tls_key==="string"? fs.readFileSync(tls_key): tls_key
  let cert=typeof tls_cert==="string"? fs.readFileSync(tls_cert): tls_cert
  const envPort=process.env.port||process.env.PORT
  const PORT=envPort? Number(envPort): (typeof options==="number"?options:(options.port||options.PORT))
  const server=ownsCert?
    https.createServer({key,cert}, responder):
    http.createServer(responder)
  server.listen(PORT||(ownsCert?443:80), function(){
    console.log(`hosting http${ownsCert?'s':''} server @ PORT ${server.address().port}`)
  })
  if(!options.key_renewer){
    options.key_renewer = typeof tls_key==="string"?
      function(){return fs.readFileSync(tls_key)}:
      function(){return tls_key}
  }
  if(!options.cert_renewer){
    options.cert_renewer = typeof tls_cert==="string"?
      function(){return fs.readFileSync(tls_cert)}:
      function(){return tls_cert}
  }
  if(ownsCert){
    const {key_renewer,cert_renewer}=options
    //every 60 seconds check to renew certificate data
    setInterval(async function(){
      //the key_renewer and cert_renewer if given can be asynchronous
      const key_next = await key_renewer()
      const cert_next = await cert_renewer()
      if(key_next===key && cert_next===cert) return null; //no changes to be made
      key = key_next
      cert = cert_next
      server.setSecureContext({key,cert})
    },6e4)
  }
  return server
}
//const scryptPbkdf = require('scrypt-pbkdf')
let ab_map=[], str_map={__proto__:null}, cache=new Map()
for(let i=0;i<256;i++){
  ab_map[i]=String.fromCharCode(i);
  str_map[ab_map[i]]=i;
}
function str2ab(str) {
  let buf=new ArrayBuffer(str.length), bufView=new Uint8Array(buf);
  for (let i=0;i<str.length;i++) bufView[i]=str_map[str[i]];
  return buf;
}
function ab2str(buf) {
  let arr=new Uint8Array(buf), chars="";
  for(let i=0;i<arr.length;i++) chars+=ab_map[arr[i]];
  return chars;
}
function str2bfr(str,typedarray) {
  let buf=Buffer.alloc(str.length);
  for (let i=0;i<str.length;i++) buf[i]=str_map[str[i]];
  return !typedarray? buf: new typedarray(buf);
}
function bfr2str(buf) {
  let chars="";
  for(let i=0;i<buf.length;i++) chars+=ab_map[buf[i]];
  return chars;
}
async function bufferChunk(stream,maxLength=Infinity){
  return new Promise((resolve,reject)=>{
    var temp="" //adding text faster than Buffer.concat
    if(!(stream?.on)) return temp; //loosely ensuring stream is stream
    stream.on('data', function(chunk){
      if(temp.length+chunk.length>maxLength)
        return reject("data length exceeded");
      temp+=bfr2str(chunk)
    })
    stream.on('end', function(){resolve(temp)})
    stream.on('error', reject)
  })
}
let rIndex=0, u32arr=new Uint32Array(2**8), pow32=pow(2,32)
function random(){
  const result=(rIndex? u32arr[rIndex]: webcrypto.getRandomValues(u32arr)[rIndex]) / pow32
  rIndex = (rIndex+1)%2**8
  return result
}
Array.prototype.random=random
String.prototype.random=random
function randomText(alphabet,length){
  do{
    var str="";
    for(let i=0;i<length;i++) str+=alphabet.random();
  }while(cache.get(str));
  cache.set(str,1);
  return str;
}
function HASH(text){
  return createHash('sha256').update(text).digest('base64')
}
async function requestURL(url,method="GET",headers={},data=""){
  if(typeof data==="string") data=str2bfr(data);
  try{var {hostname,protocol,pathname,search}=new URL(url)}
  catch{return "INVALID URL"}
  return new Promise(function(resolve,reject){
    let options={hostname, port:protocol==="https:"?443:80, path:pathname+search, method, headers}
    let request=(protocol==="https:"?https:http).request(options,async function respond(response){
      resolve(  {headers:response.headers, body:await bufferChunk(response)}  )
    })
    request.on('error',function(error){ reject(error.code||error.message||error) })
    request.write(data)
    request.end()
  })
}
//aes256key and salt are both of length 32, encrypted text is base64(iv+ciphertext)
async function AES_ENC(data,key,s,throwErrors){
  s ||= String(salt)
  key ||= String(aes256key)
  return new Promise(function(resolve,reject){
    scrypt(key,s,32,function(err,key){
      if(err) return throwErrors?reject(err):resolve("");
      const iv=Buffer.from( (crypto.webcrypto||crypto).getRandomValues(new Uint8Array(16)) )
      let cipher=createCipheriv('aes-256-ctr',key,iv), str=bfr2str(iv)
      cipher.on('error',function(err){throwErrors?reject(err):resolve("")})
      cipher.on('data',function(chunk){str+=bfr2str(chunk)})
      cipher.on('end',function(){resolve(btoa(str))})
      cipher.write(data)
      cipher.end()
    })
  })
}
async function AES_DEC(base64str,key,s,throwErrors){
  s ||= String(salt)
  key ||= String(aes256key)
  const encrypted=atob(base64str), iv=str2bfr(encrypted.substring(0,16)), data=encrypted.substring(16)
  return new Promise(function(resolve,reject){
    //scryptPbkdf.scrypt(key,s,32,{N:16384,r:8,p:1}).then(function(key,err){
    scrypt(key,s,32,function(err,key){
      if(err) return throwErrors?reject(err):resolve("");
      let decipher=createDecipheriv('aes-256-ctr',key,iv), str=""
      decipher.on('readable',function(){
        for(let chunk=decipher.read(); chunk!==null; chunk=decipher.read())
          str+=bfr2str(chunk);
      })
      decipher.on('error',function(err){throwErrors?reject(err):resolve("")})
      decipher.on('end',function(){resolve(str)})
      decipher.write(data,'binary')
      decipher.end()
    })
  })
}
function parseCookies(request){
  const list = {__proto__:null};
  const cookieHeader = request.headers?.cookie;
  if (!cookieHeader) return list;
  cookieHeader.split(`;`).forEach(function(cookie){
      let [ name, ...rest] = cookie.split(`=`);
      name = name?.trim();
      if (!name) return null;
      const value = rest.join(`=`).trim();
      if (!value) return null;
      list[name] = decodeURIComponent(value);
  })
  return list;
}
let randList=new Map() //this block here is for recording random UNIQUE keys
let random =_=> (crypto.webcrypto||crypto).getRandomValues(new Uint32Array(1))[0];
let range =(max,min)=> (random()%(max-min))+min; //numeric range
var arr='abcdefgjiklmnopqrstuvwxyz-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('')

function randomChar(n=16){
  do{
    var str="", length=range(2*n,n)
    for(let i=0;i<length;i++) str+=arr[range(arr.length-1,0)];
  }while(randList.has(str));
  randList.set(str,1); //so that this key won't repeat
  return str;
}
global.utils||={create_server,str2ab,ab2str,str2bfr,bfr2str,bufferChunk,randomText,HASH,requestURL,AES_ENC,AES_DEC,parseCookies,randomChar,randList};
module.exports=global.utils;
