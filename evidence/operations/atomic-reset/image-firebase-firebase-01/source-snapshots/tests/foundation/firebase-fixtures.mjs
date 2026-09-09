// ExpertAuth contributors, 2026. Apache-2.0. Synthetic, public test credentials.
// Node/OpenSSL supplies the independent KDF and AES primitives; no custom crypto.
import {scryptSync, createCipheriv, createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';

const signer = 'gRhC3eDeQOdyEn4bMd9c6kxguWVmcIVq/SKa0JDPFeM6TcEevkaW56sIWfx88OHbJKnCXdWscZx0l2WbCJ1wbg==';
function fixture(id, password, salt, memCost=14, rounds=8) {
  const separator='Bw==';
  const derived=scryptSync(Buffer.from(password,'utf8'),Buffer.concat([Buffer.from(salt,'base64'),Buffer.from(separator,'base64')]),64,{N:2**memCost,r:rounds,p:1,maxmem:64*1024*1024});
  const cipher=createCipheriv('aes-256-ctr',derived.subarray(0,32),Buffer.alloc(16));
  const hash=Buffer.concat([cipher.update(Buffer.from(signer,'base64')),cipher.final()]).toString('base64');
  derived.fill(0);
  return {id,password,encoded:`$f_scrypt$${hash}$${salt}$m=${memCost}$r=${rounds}$s=${separator}`,memCost,rounds};
}
const fixtures=[fixture('upstream-ascii','testPass123','/cj0jC1br5o4+w=='),
  fixture('utf8','p\u00e4ss\u{1f511}\u65e5\u672c\u8a9e','YW5vdGhlci1zYWx0'),
  fixture('question-mark','?','cXVlc3Rpb24tc2FsdA=='),
  fixture('cost-two','shift-alias','c2hpZnQtc2FsdA==',1,8)];
const expected='qZM035es5AXYqavsKD6/rhtxg7t5PhcyRgv5blc3doYbChX8keMfQLq1ra96O2Pf2TP/eZrR5xtPCYN6mX3ESA==';
if(fixtures[0].encoded.split('$')[2]!==expected)throw new Error('Original public Core fixture differs');
for(let i=0;i<8;i++) fixtures.push(fixture('owner-'+i,'Owner-'+i+'-\u00e9',createHash('sha256').update('public-fixture-'+i).digest().subarray(0,16).toString('base64'),10,8));
const primitives=[];
for(const [password,salt,N,r,p] of [['','',16,1,1],['password','NaCl',1024,8,16],['pleaseletmein','SodiumChloride',16384,8,1]]) {
  primitives.push({password,salt,N,r,p,length:64,hex:scryptSync(password,salt,64,{N,r,p,maxmem:64*1024*1024}).toString('hex')});
}
writeFileSync('/out/firebase-fixtures.json',JSON.stringify({kind:'public-node-openssl-firebase-fixtures',signer,fixtures,primitives,
  node:process.version,openssl:process.versions.openssl,original_ascii_fixture_matches:true,full_firebase_migration_qualified:false},null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({generated:true,fixtures:fixtures.length,primitives:primitives.length,original_ascii_fixture_matches:true}));
