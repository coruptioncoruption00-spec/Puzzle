// worker.js — параллельный сканер диапазона
import { getPublicKey } from 'https://esm.sh/@noble/secp256k1@2.0.0';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.4.0/sha256';
import { ripemd160 } from 'https://esm.sh/@noble/hashes@1.4.0/ripemd160';
import { base58check } from 'https://esm.sh/@scure/base@1.1.5';
import { secp256k1 as secpC } from 'https://esm.sh/@noble/curves@1.4.0/secp256k1';

const b58c=base58check(sha256);
const u8=(a)=>new Uint8Array(a);
const hexToBytes=(hex)=>{ if(hex.startsWith('0x')) hex=hex.slice(2); if(hex.length%2!==0) throw new Error('HEX длина нечетная'); const out=new Uint8Array(hex.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(hex.slice(i*2,i*2+2),16); return out; };
const bigIntTo32=(x)=>{ let hex=x.toString(16); if(hex.length>64) throw new Error('Большое значение'); hex=hex.padStart(64,'0'); return hexToBytes(hex); };
// HASH160: JS по умолчанию, ускорение через WASM при наличии
const h160Js=(pub)=>ripemd160(sha256(pub));
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
function h160Batch(inputs){
  const n = inputs.length; const out = new Array(n);
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
const eq=(a,b)=>{ if(a.length!==b.length) return false; for(let i=0;i<a.length;i++) if(a[i]!==b[i]) return false; return true; };
const toAddr=(h)=>{ const p=new Uint8Array(21); p[0]=0x00; p.set(h,1); return b58c.encode(p); };
const wif=(priv32,compressed)=>{ const body=compressed?u8([0x80,...priv32,0x01]):u8([0x80,...priv32]); return b58c.encode(body); };
const G = secpC.ProjectivePoint.BASE;
try{ secpC.utils?.precompute?.(8); }catch{}
// Кеш маленьких кратных базовой точки: ускоряет поправку при residue‑skip (skip < 16)
const GMUL_CACHE = new Map();
function gMulSmall(skip){
  const n = Number(skip);
  if(n<=0) return G.multiply(skip);
  if(n>32) return G.multiply(skip);
  let p = GMUL_CACHE.get(n);
  if(!p){ p = G.multiply(BigInt(n)); GMUL_CACHE.set(n,p); }
  return p;
}
function writeBigTo32(dst, off, bi){ let x=bi; for(let i=31;i>=0;i--){ dst[off+i]=Number(x & 0xffn); x >>= 8n; } }
function eqH160(a,b){ if(a.length!==20||b.length!==20) return false; for(let i=0;i<20;i++){ if(a[i]!==b[i]) return false; } return true; }

let stop=false;
self.onmessage=async (e)=>{
  const msg=e.data;
  if(msg?.type==='stop'){ stop=true; return; }
  if(msg?.type==='throttle'){ self.__throttleMs = Math.max(0, Number(msg.throttleMs)||0); return; }
  if(msg?.type==='scan'){
    stop=false;
    const {start, stopKey, stride, chunk, targetH160} = msg;
    let cur=start; let checked=0;
    try{
      await ensureWasm();
      const end=stopKey;
      while(!stop && cur<=end){
        const upto=cur+BigInt(chunk)-1n;
        for(; cur<=end && cur<=upto; cur+=BigInt(stride)){
          const priv=bigIntTo32(cur);
          const hC=h160Fast(getPublicKey(priv,true)); if(eq(hC,targetH160)){ const addr=toAddr(hC); const keyWif=wif(priv,true); self.postMessage({type:'found', key:cur.toString(16).padStart(64,'0'), addr, wif:keyWif, compressed:true}); return; }
          const hU=h160Fast(getPublicKey(priv,false)); if(eq(hU,targetH160)){ const addr=toAddr(hU); const keyWif=wif(priv,false); self.postMessage({type:'found', key:cur.toString(16).padStart(64,'0'), addr, wif:keyWif, compressed:false}); return; }
          checked++;
        }
        self.postMessage({type:'progress', checked});
      }
      self.postMessage({type:'done'});
    }catch(err){ self.postMessage({type:'error', message: (err?.message||String(err))}); }
    return;
  }
  if(msg?.type==='verifyEc'){
    // Параллельный верификационный проход:
    // По умолчанию Δ = 1·G (последовательные ключи),
    // при interleaved=true — Δ = W·G и k += W (распределение по классам по модулю W)
    stop=false;
    const { start, offset, count, chunk=8192, targetH160, format='both', throttleMs=0, interleaved=false, W=1 } = msg;
    try{
      await ensureWasm();
      // Локальная копия цели (20 байт)
      const tgt = (targetH160 && targetH160.length===20) ? new Uint8Array(targetH160) : new Uint8Array(20);
      const startBI = (typeof start==='bigint') ? start : BigInt(start);
      const offBI = (typeof offset==='bigint') ? offset : BigInt(offset);
      const cntBI = (typeof count==='bigint') ? count : BigInt(count);
      let k = startBI + offBI;
      let left = cntBI;
      let P = G.multiply(k);
      const stepW = interleaved ? BigInt(W) : 1n;
      const DELTA = interleaved ? G.multiply(stepW) : G; // шаг W·G либо 1·G
      const cBuf=new Uint8Array(33);
      const uBuf=new Uint8Array(65);
      let done=0n, reported=0n;
      while(!stop && left>0n){
        let toDo = Number(left > BigInt(chunk) ? BigInt(chunk) : left);
        while(toDo>0 && left>0n){
          const A=P.toAffine();
          // compressed
          cBuf[0]=(A.y & 1n)?0x03:0x02; writeBigTo32(cBuf,1,A.x);
          if(format!=='uncompressed'){
            // Для надёжности верификации используем чисто JS-реализацию HASH160
            const hC=ripemd160(sha256(cBuf));
            if(eqH160(hC, tgt)){
              const keyHex=k.toString(16).padStart(64,'0'); const addr=toAddr(hC); const keyWif=wif(bigIntTo32(k), true);
              self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:true}); return;
            }
          }
          if(format!=='compressed'){
            uBuf[0]=0x04; writeBigTo32(uBuf,1,A.x); writeBigTo32(uBuf,33,A.y);
            const hU=ripemd160(sha256(uBuf));
            if(eqH160(hU, tgt)){
              const keyHex=k.toString(16).padStart(64,'0'); const addr=toAddr(hU); const keyWif=wif(bigIntTo32(k), false);
              self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:false}); return;
            }
          }
          // следующий ключ
          k = k + stepW; left -= 1n; toDo -= 1; done += 1n;
          P = P.add(DELTA);
        }
        if(done - reported >= 2048n){ self.postMessage({type:'progress', checkedBigStr: done.toString()}); reported = done; }
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
  const { start, len, W, s, seed, workerIndex, limit, chunk, targetH160, format='both', order='normal', throttleMs=0, mask=0, residue=0, batch=4, seedMode='start' } = msg;
    try{
  await ensureWasm();
  const rawStep=W*s;
  const lenBig=(typeof len === 'bigint') ? len : BigInt(len);
      const Wb=BigInt(W), sb=BigInt(s), rawStepB=BigInt(rawStep);
      // безопасные BigInt-константы для residue split
      const maskBI = BigInt((mask>>>0));
      const useResidue = maskBI > 0n;
      const mBI = maskBI + 1n;
      const wantResid = BigInt((residue>>>0) & Number(maskBI));
      // реальный индекс в диапазоне [0,len)
      let i0 = (BigInt(seed % 0xffffffff) + (BigInt(workerIndex) * sb) ) % lenBig;
      if(seedMode==='end'){
        // отталкиваемся от конца диапазона
        i0 = (lenBig - 1n - i0 + lenBig) % lenBig;
      }
      // Подтягиваем i0 к своему классу вычетов по нижним битам, если задан mask
      if(useResidue){
        const cur = i0 % mBI;
        const delta = (wantResid - cur + mBI) % mBI;
        i0 = (i0 + delta) % lenBig;
      }
      let k = start + i0;
      let P = G.multiply(k);
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
  const BATCH = Math.max(2, Math.min(32, Number(batch)||4));
  // Пулы буферов для снижения аллокаций
  const poolC = Array.from({length:BATCH},()=>new Uint8Array(33));
  const poolU = Array.from({length:BATCH},()=>new Uint8Array(65));
  const batchC=new Array(BATCH); const batchU=new Array(BATCH); const keysC=new Array(BATCH); const keysU=new Array(BATCH);
  while(!stop && done<limBig){
        // Чанком
        let toDo=Number((limBig-done) > BigInt(chunk) ? BigInt(chunk) : (limBig-done));
        while(toDo>0 && done<limBig){
          // собираем мини-пакет из min(BATCH, toDo)
          const take = Math.min(BATCH, toDo);
          let bc=0, bu=0;
          const pts = new Array(take);
          const keysAll = new Array(take);
          for(let t=0;t<take;t++){
            // фиксируем точку и ключ до шага
            pts[t] = P;
            keysAll[t] = k;
            done+=1n; toDo-=1;
            // шаг индекса и точки, с учётом обёрток и residue
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
              i0 = nextIdx;
              if(useResidue){
                const cur=i0 % mBI;
                const skip=(wantResid - cur + mBI) % mBI;
                if(skip!==0n){
                  i0 = (i0 + skip) % lenBig;
                  // ВАЖНО: изменение индекса на +skip соответствует добавлению G*skip, а не Δ*skip
                  P = P.add(gMulSmall(skip));
                }
              }
              k = start + i0;
            } else {
              let nextIdx=i0 + rawStepB;
              const wrap=Number(nextIdx / lenBig);
              i0 = nextIdx % lenBig;
              if(useResidue){
                const cur=i0 % mBI;
                const skip=(wantResid - cur + mBI) % mBI;
                if(skip!==0n){
                  i0 = (i0 + skip) % lenBig;
                  // Корректная поправка точки при смещении индекса на +skip: P += G*skip
                  P = P.add(gMulSmall(skip));
                }
              }
              k = start + i0;
              P = P.add(DELTA_POINT);
              for(let w=0; w<wrap; w++) P = P.add(WRAP_POINT);
            }
          }
          // Одна аффинная конверсия на пакет
          const aff = secpC.ProjectivePoint.toAffineBatch(pts);
          for(let t=0;t<take;t++){
            const A = aff[t];
            cBuf[0]=(A.y & 1n) ? 0x03 : 0x02; writeBigTo32(cBuf,1,A.x);
            if(format!=='uncompressed'){ const dst=poolC[bc]; dst.set(cBuf); batchC[bc] = dst; keysC[bc] = keysAll[t]; bc++; }
            if(format!=='compressed'){ uBuf[0]=0x04; writeBigTo32(uBuf,1,A.x); writeBigTo32(uBuf,33,A.y); const dstU=poolU[bu]; dstU.set(uBuf); batchU[bu] = dstU; keysU[bu] = keysAll[t]; bu++; }
          }
          // считаем хеши пакетами
          if(bc>0){ const hs=h160Batch(batchC.slice(0,bc)); for(let j=0;j<bc;j++){ if(eqH160(hs[j], targetH160)){ const kk = keysC[j]; const keyHex=(kk).toString(16).padStart(64,'0'); const addr=toAddr(hs[j]); const keyWif=wif(bigIntTo32(kk), true); self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:true}); return; } } }
          if(bu>0){ const hs=h160Batch(batchU.slice(0,bu)); for(let j=0;j<bu;j++){ if(eqH160(hs[j], targetH160)){ const kk = keysU[j]; const keyHex=(kk).toString(16).padStart(64,'0'); const addr=toAddr(hs[j]); const keyWif=wif(bigIntTo32(kk), false); self.postMessage({type:'found', key:keyHex, addr, wif:keyWif, compressed:false}); return; } } }
        }
        if(done - reported >= 1024n){ self.postMessage({type:'progress', checkedBigStr: done.toString()}); reported = done; }
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
