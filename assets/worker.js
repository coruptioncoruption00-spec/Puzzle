// worker.js — параллельный сканер диапазона
import { getPublicKey } from 'https://esm.sh/@noble/secp256k1@2.0.0';
import { secp256k1 as secpC } from 'https://esm.sh/@noble/curves@1.4.0/secp256k1';
import { b58c, u8, bigIntTo32, writeBigTo32, pubkeyHash160 as h160JsCommon, addrFromH160 as toAddr, privToWIF as wif, EC_ORDER as EC_N, sha256, ripemd160, eqH160 } from './common.js';

// HASH160: JS по умолчанию, ускорение через WASM при наличии
const h160Js=(pub)=>h160JsCommon(pub);
let __wasmReady=false, __wasmErr=false, __shaWasm=null, __ripWasm=null;
async function ensureWasm(){
  if(__wasmReady || __wasmErr) return __wasmReady;
  try{
    const m = await import('https://esm.sh/hash-wasm@4.11.0');
    __shaWasm = await m.createSHA256();
    __ripWasm = await m.createRIPEMD160();
    __wasmReady=true; return true;
  }catch(_){ __wasmErr=true; return false; }
}
function h160Fast(pub){
  if(__wasmReady && __shaWasm && __ripWasm){
    __shaWasm.init(); __shaWasm.update(pub); const mid=__shaWasm.digest();
    __ripWasm.init(); __ripWasm.update(mid); return __ripWasm.digest();
  }
  return h160Js(pub);
}
// Пакетное HASH160 — ускоряет обработку нескольких ключей подряд
function h160Batch(inputs, count){
  const n = (typeof count === 'number' && count>=0) ? count : inputs.length; const out = new Array(n);
  if(__wasmReady && __shaWasm && __ripWasm){
    for(let i=0;i<n;i++){
      const pub=inputs[i];
      __shaWasm.init(); __shaWasm.update(pub); const mid=__shaWasm.digest();
      __ripWasm.init(); __ripWasm.update(mid); out[i]=__ripWasm.digest();
    }
    return out;
  }
  for(let i=0;i<n;i++){ out[i]=h160Js(inputs[i]); }
  return out;
}
const G = secpC.ProjectivePoint.BASE;
try{ secpC.utils?.precompute?.(8); }catch{}
const modN = (x)=>{ let r = x % EC_N; if(r<0n) r += EC_N; return r; };
function prefixBytes(a,b){
  const n = Math.min(a.length,b.length);
  let i=0; while(i<n && a[i]===b[i]) i++; return i;
}

// Noble‑фоллбек: конвертация сжатого pubkey (33) в несжатый (65)
function nobleUncompress(pubC){
  try{
    const P = secpC.ProjectivePoint.fromHex(pubC);
    const A = P.toAffine();
    const u = new Uint8Array(65);
    u[0]=0x04; writeBigTo32(u,1,A.x); writeBigTo32(u,33,A.y);
    return u;
  }catch{ return null; }
}

// Опциональная интеграция wasm‑ECC (bitcoin-secp256k1-wasm)
let __eccReady=false, __eccErr=false, __ecc=null;
async function ensureEcc(){
  if(__eccReady||__eccErr) return __eccReady;
  try{
    // Пытаемся загрузить wasm‑ECC. Если не выйдет — тихо откатываемся.
    const m = await import('https://esm.sh/bitcoin-secp256k1-wasm@3.0.0');
    let e = m;
    // Попробуем инициализировать, если требуется фабрика/инициализация
    if(typeof m?.default === 'function'){
      try{ e = await m.default(); }catch{}
    } else if(typeof m?.init === 'function'){
      try{ await m.init(); }catch{}
    }
    // Проверим наличие нужных функций
    const ok = !!(e && (e.publicKeyCreate||e.pubKeyCreate) && (e.publicKeyTweakAdd||e.pubKeyTweakAdd));
    if(!ok){ __eccErr=true; return false; }
    __ecc = e; __eccReady=true; return true;
  }catch(_){ __eccErr=true; return false; }
}

function eccPubCreate(priv32, compressed=true){
  const f = __ecc.publicKeyCreate || __ecc.pubKeyCreate;
  return f(priv32, compressed);
}
function eccPubTweakAdd(pubKey, tweak32, compressed=true){
  const f = __ecc.publicKeyTweakAdd || __ecc.pubKeyTweakAdd;
  return f(pubKey, tweak32, compressed);
}
function eccPubConvert(pubKey, compressed){
  const f = __ecc.publicKeyConvert || __ecc.pubKeyConvert;
  if(!f) return null;
  return f(pubKey, compressed);
}

let stop=false;
self.onmessage=async (e)=>{
  const msg=e.data;
  if(msg?.type==='stop'){ stop=true; return; }
  if(msg?.type==='throttle'){ self.__throttleMs = Math.max(0, Number(msg.throttleMs)||0); return; }
  // Лёгкий ping для self-test доступности модульных воркеров
  if(msg?.type==='ping'){
    try{ self.postMessage({ type:'pong' }); }catch{}; return;
  }
  if(msg?.type==='scan'){
    stop=false;
    const {start, stopKey, stride, chunk, targetH160} = msg;
    let cur=start; let checked=0;
    try{
  await ensureWasm();
  const eccOK = await ensureEcc();
      const end=stopKey;
      while(!stop && cur<=end){
        const upto=cur+BigInt(chunk)-1n;
        for(; cur<=end && cur<=upto; cur+=BigInt(stride)){
          const priv=bigIntTo32(cur);
          const hC=h160Fast(getPublicKey(priv,true)); if(eqH160(hC,targetH160)){ const addr=toAddr(hC); const keyWif=wif(priv,true); self.postMessage({type:'found', key:cur.toString(16).padStart(64,'0'), addr, wif:keyWif, compressed:true}); return; }
          const hU=h160Fast(getPublicKey(priv,false)); if(eqH160(hU,targetH160)){ const addr=toAddr(hU); const keyWif=wif(priv,false); self.postMessage({type:'found', key:cur.toString(16).padStart(64,'0'), addr, wif:keyWif, compressed:false}); return; }
          checked++;
        }
        self.postMessage({type:'progress', checked});
      }
      self.postMessage({type:'done'});
    }catch(err){ self.postMessage({type:'error', message: (err?.message||String(err))}); }
    return;
  }
  if(msg?.type==='warmup'){
    try{
      await ensureWasm();
      const eccOK = await ensureEcc();
      await ensureEcc();
      // лёгкая нагрузка для JIT/инициализации
      const dummy = new Uint8Array(33); dummy[0]=0x02;
      for(let i=0;i<8;i++){ dummy[1]=i; h160Fast(dummy); }
      self.postMessage({ type:'warmok' });
    }catch(e){ self.postMessage({ type:'warmfail', message: (e?.message||String(e)) }); }
    return;
  }
  if(msg?.type==='verifyEc'){
    // Параллельный верификационный проход:
    // По умолчанию Δ = 1·G (последовательные ключи),
    // при interleaved=true — Δ = W·G и k += W (распределение по классам по модулю W)
    stop=false;
  const { start, offset, count, chunk=8192, targetH160, format='both', throttleMs=0, interleaved=false, W=1, progressEvery, startShift=0, emitNear=true } = msg;
    try{
      // Не блокируем старт на загрузке WASM/ECC: пусть подгружается в фоне
      try{ ensureWasm(); }catch{}
      try{ ensureEcc(); }catch{}
      const eccOK = (__eccReady===true);
      // Локальная копия цели (20 байт)
      const tgt = (targetH160 && targetH160.length===20) ? new Uint8Array(targetH160) : new Uint8Array(20);
      const startBI = (typeof start==='bigint') ? start : BigInt(start);
      const offBI = (typeof offset==='bigint') ? offset : BigInt(offset);
      const cntBI = (typeof count==='bigint') ? count : BigInt(count);
  const stepW = interleaved ? BigInt(W) : 1n;
  const cntAll = cntBI;
      const baseK = startBI + offBI;
      // Рандомный сдвиг старта внутри класса: сначала идём от (baseK + shift*W), затем добираем оставшееся
      let shiftBI = 0n;
      try{ shiftBI = BigInt(startShift>>>0); }catch{ shiftBI = 0n; }
      if(cntAll>0n) shiftBI = shiftBI % cntAll;
      const phases = [];
      if(shiftBI>0n){
        phases.push({ kStart: baseK + shiftBI*stepW, left: cntAll - shiftBI });
        phases.push({ kStart: baseK, left: shiftBI });
      } else {
        phases.push({ kStart: baseK, left: cntAll });
      }
      let phaseIdx=0;
      let k = phases[0].kStart;
      let left = phases[0].left;
      // Ветвление: wasm‑ECC (tweakAdd) или noble‑EC
  let P = null;
      let PpubC = null; // 33‑байтная форма для wasm
      let delta32 = null, wrapFwd32 = null, wrapBwd32 = null;
  if(eccOK && __ecc && (__ecc.publicKeyCreate||__ecc.pubKeyCreate) && (__ecc.publicKeyTweakAdd||__ecc.pubKeyTweakAdd)){
        // Готовим стартовый pub и твики
        PpubC = eccPubCreate(bigIntTo32(k), true);
        delta32 = bigIntTo32(modN(stepW));
        wrapFwd32 = bigIntTo32(modN(-BigInt(cntAll))); // -len (перенос вперёд)
        wrapBwd32 = bigIntTo32(modN(BigInt(cntAll)));  // +len (перенос назад)
      } else {
        P = G.multiply(k);
      }
  const DELTA = interleaved ? G.multiply(stepW) : G; // шаг W·G либо 1·G
  // Mixed-add: предсоздадим точку с z=1 для быстрого сложения (для noble‑ветки)
  let DELTA_MIX;
  try{ const affD=DELTA.toAffine(); DELTA_MIX = secpC.ProjectivePoint.fromAffine(affD); }catch{ DELTA_MIX = DELTA; }
      // Предварительные пулы и настройки - ТУРБО-РЕЖИМ
  const useWasm = (__wasmReady && __shaWasm && __ripWasm);
  
  // 🚀 МАКСИМАЛЬНЫЕ батчи для сверхскорости
  let MAX_BATCH;
  if (useWasm && cntAll <= 2_000_000n) {
    MAX_BATCH = 8192; // Огромные батчи для малых диапазонов с WASM
  } else if (useWasm) {
    MAX_BATCH = 1024; // Большие батчи с WASM
  } else if (cntAll <= 2_000_000n) {
    MAX_BATCH = 2048; // Большие батчи для малых диапазонов без WASM
  } else {
    MAX_BATCH = 256; // Стандартные батчи
  }
  
  // Поддержка отдельного параметра batch (если задан), иначе ориентируемся на chunk
  const BATCH = Math.max(2, Math.min(MAX_BATCH, Number(msg.batch)||Number(chunk)||8192));
  const pts = new Array(BATCH);
  const keys = new Array(BATCH);
  const poolC = Array.from({length:BATCH},()=>new Uint8Array(33));
  const poolU = Array.from({length:BATCH},()=>new Uint8Array(65));
  const batchC = new Array(BATCH);
  const batchU = new Array(BATCH);
      const toAffineBatch = secpC?.ProjectivePoint?.toAffineBatch;

      let done=0n, reported=0n;
      
      // 🚀 ТУРБО-РЕЖИМ: минимальные прогресс-репорты для максимальной скорости
      let progStep;
      if (cntAll <= 2_000_000n) {
        progStep = BigInt(131072); // Очень редкие репорты для малых диапазонов
      } else {
        progStep = BigInt((progressEvery|0) || 4096);
        if(progStep < 512n) progStep = 512n;
      }

  let lastNearTs = 0;
  const NEAR_MIN_BYTES = emitNear ? 2 : 255; // если emitNear=false — отключаем
  const NEAR_FORCE_BYTES = emitNear ? 3 : 255;
  while(!stop && (left>0n || (phaseIdx+1<phases.length))){
        if(left===0n && (phaseIdx+1<phases.length)){
          phaseIdx++;
          k = phases[phaseIdx].kStart;
          left = phases[phaseIdx].left;
          P = G.multiply(k);
          // продолжаем тем же шагом и DELTA
          continue;
        }
        let toDo = Number(left > BigInt(chunk) ? BigInt(chunk) : left);
        while(toDo>0 && left>0n){
          const take = Math.min(BATCH, toDo);
          let aff = null;
          if(PpubC){
            // wasm‑ветка: собираем compressed сразу из tweakAdd
            let bc=0;
            if(format!=='uncompressed'){
              for(let i=0;i<take;i++){
                batchC[bc++] = new Uint8Array(PpubC);
                keys[i] = k;
                // шаг
                k = k + stepW; left -= 1n; toDo -= 1; done += 1n;
                // переносы не нужны в verifyEc (класс по модулю W), двигаемся строго Δ=W
                PpubC = eccPubTweakAdd(PpubC, delta32, true);
              }
              const hsC = h160Batch(batchC, bc);
              for(let j=0;j<bc;j++){
                if(eqH160(hsC[j], tgt)){
                  const kk = keys[j];
                  const keyHex = kk.toString(16).padStart(64,'0');
                  const addr = toAddr(hsC[j]);
                  const keyWif = wif(bigIntTo32(kk), true);
                  self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:true}); return;
                }
                // near-hit по префиксу байт HASH160 (редко, троттлим)
                const pb = prefixBytes(hsC[j], tgt);
                if(pb>=NEAR_MIN_BYTES){
                  const now=Date.now();
                  if(pb>=NEAR_FORCE_BYTES || now - lastNearTs > 500){
                    lastNearTs = now;
                    const kk = keys[j];
                    self.postMessage({ type:'near', key: kk.toString(16).padStart(64,'0'), compressed:true, prefixBytes: pb, h160: hsC[j] });
                  }
                }
              }
            } else {
              // Если нужны только uncompressed — всё равно идём через compressed и конвертируем
              for(let i=0;i<take;i++){
                batchC[i] = new Uint8Array(PpubC);
                keys[i] = k;
                k = k + stepW; left -= 1n; toDo -= 1; done += 1n;
                PpubC = eccPubTweakAdd(PpubC, delta32, true);
              }
            }
            // При необходимости — конвертируем в uncompressed и проверяем
            if(format!=='compressed'){
              let bu=0;
              for(let i=0;i<take;i++){
                const u = eccPubConvert(batchC[i], false) || batchC[i];
                batchU[bu++] = u;
              }
              const hsU = h160Batch(batchU, bu);
              for(let j=0;j<bu;j++){
                if(eqH160(hsU[j], tgt)){
                  const kk = keys[j];
                  const keyHex = kk.toString(16).padStart(64,'0');
                  const addr = toAddr(hsU[j]);
                  const keyWif = wif(bigIntTo32(kk), false);
                  self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:false}); return;
                }
                const pb = prefixBytes(hsU[j], tgt);
                if(pb>=NEAR_MIN_BYTES){
                  const now=Date.now();
                  if(pb>=NEAR_FORCE_BYTES || now - lastNearTs > 500){
                    lastNearTs = now;
                    const kk = keys[j];
                    self.postMessage({ type:'near', key: kk.toString(16).padStart(64,'0'), compressed:false, prefixBytes: pb, h160: hsU[j] });
                  }
                }
              }
            }
            continue; // следующая порция
          } else {
            // noble‑ветка: как было — собираем точки и переводим в аффинные
            for(let i=0;i<take;i++){
              pts[i] = P;
              keys[i] = k;
              k = k + stepW; left -= 1n; toDo -= 1; done += 1n;
              P = P.add(DELTA_MIX);
            }
            aff = (typeof toAffineBatch==='function') ? toAffineBatch(pts.slice(0,take)) : pts.slice(0,take).map(p=>p.toAffine());
          }
          // Сначала считаем и проверяем compressed для всей пачки
          let bc=0;
          if(format!=='uncompressed'){
            if(aff){ for(let i=0;i<take;i++){ const A = aff[i]; const c = poolC[bc]; c[0] = (A.y & 1n) ? 0x03 : 0x02; writeBigTo32(c,1,A.x); batchC[bc++] = c; } }
            const hsC = h160Batch(batchC, bc);
            for(let j=0;j<bc;j++){
              if(eqH160(hsC[j], tgt)){
                const kk = keys[j];
                const keyHex = kk.toString(16).padStart(64,'0');
                const addr = toAddr(hsC[j]);
                const keyWif = wif(bigIntTo32(kk), true);
                self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:true}); return;
              }
              const pb = prefixBytes(hsC[j], tgt);
              if(pb>=NEAR_MIN_BYTES){
                const now=Date.now();
                if(pb>=NEAR_FORCE_BYTES || now - lastNearTs > 500){
                  lastNearTs = now;
                  const kk = keys[j];
                  self.postMessage({ type:'near', key: kk.toString(16).padStart(64,'0'), compressed:true, prefixBytes: pb, h160: hsC[j] });
                }
              }
            }
          }
          // Если нужно, считаем uncompressed только при отсутствии совпадений
          if(format!=='compressed'){
            let bu=0;
            if(aff){ for(let i=0;i<take;i++){ const A = aff[i]; const u = poolU[bu]; u[0] = 0x04; writeBigTo32(u,1,A.x); writeBigTo32(u,33,A.y); batchU[bu++] = u; } }
            const hsU = h160Batch(batchU, bu);
            for(let j=0;j<bu;j++){
              if(eqH160(hsU[j], tgt)){
                const kk = keys[j];
                const keyHex = kk.toString(16).padStart(64,'0');
                const addr = toAddr(hsU[j]);
                const keyWif = wif(bigIntTo32(kk), false);
                self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:false}); return;
              }
              const pb = prefixBytes(hsU[j], tgt);
              if(pb>=NEAR_MIN_BYTES){
                const now=Date.now();
                if(pb>=NEAR_FORCE_BYTES || now - lastNearTs > 500){
                  lastNearTs = now;
                  const kk = keys[j];
                  self.postMessage({ type:'near', key: kk.toString(16).padStart(64,'0'), compressed:false, prefixBytes: pb, h160: hsU[j] });
                }
              }
            }
          }
        }
        if(done - reported >= progStep){ self.postMessage({type:'progress', checkedBigStr: done.toString()}); reported = done; }
        const thr = (typeof self.__throttleMs==='number' ? self.__throttleMs : throttleMs);
        if(thr && !stop){ await new Promise(r=>setTimeout(r, Math.min(50, thr))); }
      }
      if(done>reported){ self.postMessage({type:'progress', checkedBigStr: done.toString()}); }
      self.postMessage({type:'done'});
    }catch(err){ self.postMessage({type:'error', message: (err?.message||String(err))}); }
    return;
  }
  if(msg?.type==='scanEc'){
    stop=false;
  const { start, len, W, s, seed, workerIndex, limit, chunk, targetH160, format='both', order='normal', throttleMs=0, batch=4, seedMode='start', progressEvery } = msg;
    try{
  await ensureWasm();
  const eccOK = await ensureEcc();
  const rawStep=W*s;
  const lenBig=(typeof len === 'bigint') ? len : BigInt(len);
    const Wb=BigInt(W), sb=BigInt(s), rawStepB=BigInt(rawStep);
      // реальный индекс в диапазоне [0,len)
      let i0 = (BigInt(seed >>> 0) + (BigInt(workerIndex) * sb) ) % lenBig;
      if(seedMode==='end'){
        // отталкиваемся от конца диапазона
        i0 = (lenBig - 1n - i0 + lenBig) % lenBig;
      }
      let k = start + i0;
      let P = null;
      let pubC = null;
      if(eccOK && __ecc){
        pubC = eccPubCreate(bigIntTo32(k), true);
      } else {
        P = G.multiply(k);
      }
      const DELTA_POINT = G.multiply(rawStepB);
      const LEN_POINT = G.multiply(lenBig);
      const WRAP_POINT = LEN_POINT.negate();
  let done=0n; let reported=0n;
  const limBig=(typeof limit === 'bigint') ? limit : BigInt(limit);
  let dir = (order==='zigzag' && (workerIndex & 1)===1) ? -1 : 1;
  // Выделим буферы один раз на воркер
  const cBuf=new Uint8Array(33);
  const uBuf=new Uint8Array(65);
  // небольшой пакет для хеширования за один проход (сборка batch за раз)
  const maxBatch = (__wasmReady && __shaWasm && __ripWasm) ? 128 : 64;
  const BATCH = Math.max(2, Math.min(maxBatch, Number(batch)||4));
  // Пулы буферов для снижения аллокаций
  const poolC = Array.from({length:BATCH},()=>new Uint8Array(33));
  const poolU = Array.from({length:BATCH},()=>new Uint8Array(65));
  const batchC=new Array(BATCH); const batchU=new Array(BATCH); const keysC=new Array(BATCH); const keysU=new Array(BATCH);
  const toAffineBatch = secpC?.ProjectivePoint?.toAffineBatch;
  let lastNearTs=0; const NEAR_MIN_BYTES=2; const NEAR_FORCE_BYTES=3;
  while(!stop && done<limBig){
        // Чанком
        let toDo=Number((limBig-done) > BigInt(chunk) ? BigInt(chunk) : (limBig-done));
        while(toDo>0 && done<limBig){
          // собираем мини-пакет из min(BATCH, toDo)
          const take = Math.min(BATCH, toDo);
          let bc=0, bu=0;
          const keysAll = new Array(take);
          if(pubC){
            // wasm‑ECC ветка: формируем compressed напрямую, шаг через tweakAdd с учётом обёрток
            for(let t=0;t<take;t++){
              // сохранить текущий pubC и ключ
              const dst = poolC[bc]; dst.set(pubC); batchC[bc]=dst; keysC[bc]=k; keysAll[t]=k; bc++;
              // шаг индекса и корректировка обёрток
              if(order==='zigzag'){
                let nextIdx = (dir===-1)? (i0 - rawStepB) : (i0 + rawStepB);
                if(dir===1){
                  const wrap= nextIdx>=lenBig ? Number(nextIdx/lenBig) : 0;
                  nextIdx = nextIdx>=0n ? (nextIdx % lenBig) : ((nextIdx % lenBig + lenBig) % lenBig);
                  // tweak = +rawStep - wrap*len
                  const tweak = rawStepB - BigInt(wrap)*lenBig;
                  pubC = eccPubTweakAdd(pubC, bigIntTo32(modN(tweak)), true);
                } else {
                  const wrap = nextIdx<0n ? Number(((-nextIdx)+(lenBig-1n))/lenBig) : 0;
                  nextIdx = (nextIdx % lenBig + lenBig) % lenBig;
                  // tweak = -rawStep + wrap*len
                  const tweak = -rawStepB + BigInt(wrap)*lenBig;
                  pubC = eccPubTweakAdd(pubC, bigIntTo32(modN(tweak)), true);
                }
                i0 = nextIdx; k = start + i0;
              } else {
                let nextIdx=i0 + rawStepB;
                const wrap=Number(nextIdx / lenBig);
                i0 = nextIdx % lenBig;
                // tweak = +rawStep - wrap*len
                const tweak = rawStepB - BigInt(wrap)*lenBig;
                pubC = eccPubTweakAdd(pubC, bigIntTo32(modN(tweak)), true);
                k = start + i0;
              }
              done+=1n; toDo-=1;
            }
          } else {
            // noble‑ветка как было: точки → аффинные → сериализация
            const pts = new Array(take);
            for(let t=0;t<take;t++){
              pts[t] = P; keysAll[t]=k; done+=1n; toDo-=1;
              if(order==='zigzag'){
                let nextIdx = (dir===-1)? (i0 - rawStepB) : (i0 + rawStepB);
                if(dir===1){
                  const wrap= nextIdx>=lenBig ? Number(nextIdx/lenBig) : 0;
                  nextIdx = nextIdx>=0n ? (nextIdx % lenBig) : ((nextIdx % lenBig + lenBig) % lenBig);
                  P = P.add(DELTA_POINT);
                  for(let w=0; w<wrap; w++) P = P.add(WRAP_POINT);
                } else {
                  const wrap = nextIdx<0n ? Number(((-nextIdx)+(lenBig-1n))/lenBig) : 0;
                  nextIdx = (nextIdx % lenBig + lenBig) % lenBig;
                  P = P.add(DELTA_POINT.negate());
                  for(let w=0; w<wrap; w++) P = P.add(WRAP_POINT.negate());
                }
                i0 = nextIdx; k = start + i0;
              } else {
                let nextIdx=i0 + rawStepB;
                const wrap=Number(nextIdx / lenBig);
                i0 = nextIdx % lenBig;
                k = start + i0;
                P = P.add(DELTA_POINT);
                for(let w=0; w<wrap; w++) P = P.add(WRAP_POINT);
              }
            }
            let aff;
            if(typeof toAffineBatch === 'function') aff = toAffineBatch(pts); else aff = pts.map(p=>p.toAffine());
            if(format!=='uncompressed'){
              for(let t=0;t<take;t++){
                const A = aff[t]; cBuf[0]=(A.y & 1n) ? 0x03 : 0x02; writeBigTo32(cBuf,1,A.x);
                const dst=poolC[bc]; dst.set(cBuf); batchC[bc]=dst; keysC[bc]=keysAll[t]; bc++;
              }
            }
            if(format!=='compressed'){
              for(let t=0;t<take;t++){
                const A = aff[t]; uBuf[0]=0x04; writeBigTo32(uBuf,1,A.x); writeBigTo32(uBuf,33,A.y);
                const dstU=poolU[bu]; dstU.set(uBuf); batchU[bu]=dstU; keysU[bu]=keysAll[t]; bu++;
              }
            }
          }
          // HASH160 compressed
          if(bc>0){ const hs=h160Batch(batchC, bc); for(let j=0;j<bc;j++){ if(eqH160(hs[j], targetH160)){ const kk=keysC[j]; const keyHex=kk.toString(16).padStart(64,'0'); const addr=toAddr(hs[j]); const keyWif=wif(bigIntTo32(kk), true); self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:true}); return; } const pb=prefixBytes(hs[j], targetH160); if(pb>=NEAR_MIN_BYTES){ const now=Date.now(); if(pb>=NEAR_FORCE_BYTES || now-lastNearTs>500){ lastNearTs=now; const kk=keysC[j]; self.postMessage({type:'near', key: kk.toString(16).padStart(64,'0'), compressed:true, prefixBytes: pb, h160: hs[j]}); } } } }
          // Если не нашли и требуется — готовим/хэшируем uncompressed
          if(format!=='compressed'){
            if(bu===0){ // wasm‑ветка: конвертируем из batchC
              for(let j=0;j<bc;j++){
                const conv = (__ecc && eccPubConvert(batchC[j], false)) || nobleUncompress(batchC[j]);
                const dstU = poolU[bu]; dstU.set(conv||batchC[j]); batchU[bu]=dstU; keysU[bu]=keysAll[j]; bu++;
              }
            }
            if(bu>0){ const hs=h160Batch(batchU, bu); for(let j=0;j<bu;j++){ if(eqH160(hs[j], targetH160)){ const kk=keysU[j]; const keyHex=kk.toString(16).padStart(64,'0'); const addr=toAddr(hs[j]); const keyWif=wif(bigIntTo32(kk), false); self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:false}); return; } const pb=prefixBytes(hs[j], targetH160); if(pb>=NEAR_MIN_BYTES){ const now=Date.now(); if(pb>=NEAR_FORCE_BYTES || now-lastNearTs>500){ lastNearTs=now; const kk=keysU[j]; self.postMessage({type:'near', key: kk.toString(16).padStart(64,'0'), compressed:false, prefixBytes: pb, h160: hs[j]}); } } } }
          }
        }
  let progStep2 = BigInt((progressEvery|0) || 1024);
  if(progStep2 < 512n) progStep2 = 512n;
  if(done - reported >= progStep2){ self.postMessage({type:'progress', checkedBigStr: done.toString()}); reported = done; }
        // уступаем квант CPU между пакетами
        const thr = (typeof self.__throttleMs==='number' ? self.__throttleMs : throttleMs);
        if(thr && !stop){ await new Promise(r=>setTimeout(r, Math.min(50, thr))); }
      }
      // финальный флаш прогресса
      if(done>reported){ self.postMessage({type:'progress', checkedBigStr: done.toString()}); reported = done; }
      // при необходимости — уступаем квант CPU
  const thr = (typeof self.__throttleMs==='number' ? self.__throttleMs : throttleMs);
  if(thr && !stop){ await new Promise(r=>setTimeout(r, Math.min(50, thr))); }
      self.postMessage({type:'done'});
    }catch(err){ self.postMessage({type:'error', message: (err?.message||String(err))}); }
    return;
  }
};
