#!/usr/bin/env node
'use strict';
/* nid-hunt.js — the export-table NID analysis.
 * Format established: entry = {nid32, selfrel32} qword = (nid << 32) | selfrel,
 * where selfrel = text_rva - 0x48000 (negative, 0xFFFB-class when text < 0x48000).
 * The 4-byte-shifted dumps interleave pairs; both halves are recoverable.
 * GOAL: find the entry with selfrel 0xfffb8b50 (text 0xB50 = gettimeofday,
 * 14.10-named-import-proven) -> its nid = NID(gettimeofday) -> crack the hash
 * -> NID(thr_self) -> its entry -> text RVA -> the single-arg witness call. */
const fs = require('fs');

// Session 53's [512+] harvest (the full reply, saved from the shell output)
const D = JSON.parse(fs.readFileSync(__dirname + '/harvest-s53-entries.json', 'utf8'));

// Session 49's first-512 dump (the visible portion, 4-byte-shifted the same way)
const F = ["0xbd5cfffb80d0","0x13094fffb8130","0xa9f0fffb81e0","0xb904fffb8200","0xd878fffb8230","0xec18fffb82c0","0xbe58fffb8340","0x119c8fffb83a0","0xf49cfffb8410","0xa838fffb8460","0xc77cfffb8480","0xc66cfffb8510","0xe5d8fffb85c0","0xd42cfffb8620","0xea70fffb86d0","0x12a68fffb8750","0x9a20fffb87a0","0xdf00fffb88b0","0xa1ccfffb8940","0xd1f0fffb89e0","0xaa9cfffb8a10","0x9d68fffb8a30","0x12004fffb8a40","0x12be8fffb8a80","0x12a40fffb8b10","0x12c4cfffb8ba0","0x110b8fffb8be0","0x12078fffb8ca0","0xdcb0fffb8cb0","0xaabcfffb8cc0","0xba24fffb8ce0","0xae90fffb8d60","0x9ee0fffb8d80","0xa154fffb8df0","0xa818fffb8e30","0x11db4fffb8e50","0xaf10fffb8ec0","0x9b60fffb8ee0","0x1168cfffb8f30","0xce80fffb8f90","0xd3b0fffb9060","0xcadcfffb90f0"];

function halves(s){const v=BigInt(s);return{lo:Number(v&0xFFFFFFFFn),hi:Number(v>>32n)};}

// Search the [512+] harvest for selfrel 0xfffb8b50 (in either half - the shift direction varies with read start)
let hits=[];
for(let i=0;i<D.length;i++){
  const {lo,hi}=halves(D[i]);
  if(lo===0xfffb8b50)hits.push({where:'lo',idx:i,other:'0x'+hi.toString(16)});
  if(hi===0xfffb8b50)hits.push({where:'hi',idx:i,other:'0x'+lo.toString(16)});
}
console.log('[512+] harvest: '+D.length+' qwords; 0xB50 search: '+(hits.length?JSON.stringify(hits):'NOT FOUND'));

// Search the first-512 visible dump
let f2=[];
for(let i=0;i<F.length;i++){
  const {lo,hi}=halves(F[i]);
  if(lo===0xfffb8b50)f2.push({where:'lo',idx:i,other:'0x'+hi.toString(16)});
  if(hi===0xfffb8b50)f2.push({where:'hi',idx:i,other:'0x'+lo.toString(16)});
}
console.log('first-512 visible ('+F.length+' qwords): '+(f2.length?JSON.stringify(f2):'NOT FOUND'));

// Also: the OTHER verified stubs - which of them are export entries?
const stubs={0x3B0:0xfffb83b0,0x3F0:0xfffb83f0,0x410:0xfffb8410,0xB50:0xfffb8b50,0xB70:0xfffb8b70,0xD50:0xfffb8d50,0xFF0:0xfffb8ff0,0x10F0:0xfffb90f0};
const all=F.concat(D);
for(const [txt,sr] of Object.entries(stubs)){
  let found=[];
  for(let i=0;i<all.length;i++){
    const {lo,hi}=halves(all[i]);
    if(lo===sr)found.push('lo@'+i);
    if(hi===sr)found.push('hi@'+i);
  }
  console.log('stub text 0x'+txt.toString(16)+': '+(found.length?found.join(',')+' -> nid alongside' : 'not an export entry'));
}

// Extract every {nid, selfrel} pair from BOTH dumps for the full pair table
const pairs=[];
for(let i=0;i<all.length;i++){
  const {lo,hi}=halves(all[i]);
  // the shift: {lo32: selfrel(k-1), hi32: nid(k)} - pair hi32 with the lo32 of the NEXT qword
  if(i+1<all.length){
    const n=halves(all[i+1]);
    pairs.push({nid:hi,sr:n.lo}); // nid(k) with selfrel(k)?? - approximate; verify by monotonicity
  }
}
// monotonicity check of sr
let mono=0,nonmono=0;
for(let i=1;i<pairs.length;i++){if(pairs[i].sr>pairs[i-1].sr)mono++;else nonmono++;}
console.log('pair reconstruction: '+pairs.length+' pairs, monotone '+mono+' / non-monotone '+nonmono);
