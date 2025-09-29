// Импорты (ESM через CDN)
import { getPublicKey } from 'https://esm.sh/@noble/secp256k1@2.0.0';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.4.0/sha256';
import { ripemd160 } from 'https://esm.sh/@noble/hashes@1.4.0/ripemd160';
import { base58check } from 'https://esm.sh/@scure/base@1.1.5';
import { secp256k1 as secpC } from 'https://esm.sh/@noble/curves@1.4.0/secp256k1';

// Инициализация Base58Check (нужна фабрика с sha256)
const b58c = base58check(sha256);

// DOM helpers
const $ = (id) => document.getElementById(id);
const statusEl = $('status');
const resultEl = $('result');
const logsEl = $('logs');
const currentKeyEl = $('currentKey');
const checkedEl = $('checked');
const speedEl = $('speed');
const elapsedEl = $('elapsed');
const progressBar = $('progressBar');
const progressPct = $('progressPct');
const startBtn = $('startBtn');
const stopBtn = $('stopBtn');
const targetAddrInput = $('targetAddr');
const startKeyInput = $('startKey');
const stopKeyInput = $('stopKey');
const chunkSizeInput = $('chunkSize');
const preset19Btn = $('preset19');
const preset10Btn = $('preset10');
const preset20Btn = $('preset20');
const preset70Btn = $('preset70');
const preset71Btn = $('preset71');
const diagKeyInput = $('diagKey');
const turboToggle = $('turboToggle');
const diagBtn = $('diagBtn');
const diagOut = $('diagOut');

function log(line){
  const ts = new Date().toLocaleTimeString();
  logsEl.textContent += `[${ts}] ${line}\n`;
  logsEl.scrollTop = logsEl.scrollHeight;
}

// Utils
const hexToBytes=(hex)=>{ if(hex.startsWith('0x')) hex=hex.slice(2); if(hex.length%2!==0) throw new Error('HEX длина нечетная'); const out=new Uint8Array(hex.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(hex.slice(i*2,i*2+2),16); return out; };
const bigIntTo32=(x)=>{ if(x<0n) throw new Error('Отрицательный ключ'); const out=new Uint8Array(32); let v=x; for(let i=31;i>=0;i--){ out[i]=Number(v & 0xffn); v >>= 8n; } if(v!==0n) throw new Error('Слишком большое значение для приватного ключа'); return out; };
const u8=(arr)=>new Uint8Array(arr);
// Запись 32-байтного BigInt в буфер (big-endian)
function writeBigTo32(dst, off, bi){ let x=bi; for(let i=31;i>=0;i--){ dst[off+i]=Number(x & 0xffn); x >>= 8n; } }

// Хелперы адресов
function addrFromH160(h160){ const payload=new Uint8Array(21); payload[0]=0x00; payload.set(h160,1); return b58c.encode(payload); }
function pubkeyToP2PKH(pub){ const h160=ripemd160(sha256(pub)); return addrFromH160(h160); }
function pubkeyHash160(pub){ return ripemd160(sha256(pub)); }
function privToWIF(priv32,compressed){ const body=compressed?u8([0x80,...priv32,0x01]):u8([0x80,...priv32]); return b58c.encode(body); }
// Строгая валидация: доверяем только Base58Check-декодированию и версии 0x00 (mainnet P2PKH)
function decodeBase58P2PKH(addr){ let raw; try{ raw=b58c.decode(addr); }catch(e){ throw new Error('Некорректный Base58Check адрес'); }
  if(!(raw instanceof Uint8Array)||raw.length!==21) throw new Error('Некорректная длина адреса');
  if(raw[0]!==0x00) throw new Error('Ожидается только mainnet P2PKH (префикс 0x00)');
  return raw.slice(1);
}
function eqBytes(a,b){ if(a.length!==b.length) return false; for(let i=0;i<a.length;i++) if(a[i]!==b[i]) return false; return true; }
// Быстрое сравнение именно для хеша160 (20 байт)
function eqH160(a,b){ if(a.length!==20||b.length!==20) return false; const da=new DataView(a.buffer,a.byteOffset,20); const db=new DataView(b.buffer,b.byteOffset,20); for(let i=0;i<20;i+=4){ if(da.getUint32(i,true)!==db.getUint32(i,true)) return false; } return true; }

// Состояние
let scanning=false, abortFlag=false;
let counters={checked:0,startedAt:0,lastTs:0,lastChecked:0, checkedBig:0n};
let totalKeys=0; let totalKeysBig=0n; let rangeStart=0n, rangeStop=0n;
// Последний найденный результат — чтобы удобнее проверять в диагностике
let lastFoundKeyHex=null, lastFoundAddr=null, lastFoundWIF=null, lastFoundCompressed=null;
// Глобальный колбэк завершения сканирования (для двухфазного режима)
let onScanComplete=null;
// Пул воркеров (для стратегии workers)
let workerPool=[]; // Array<Worker>
let workerMeta=[]; // {checked:number, done:boolean}
let workersRunning=false; let workersFound=false;

function updateStats(){ const now=performance.now(); const elapsedSec=scanning?(now-counters.startedAt)/1000:(counters.startedAt? (counters.lastTs-counters.startedAt)/1000:0); const dt=Math.max(0.001,(now-counters.lastTs)/1000); const d=counters.checked-counters.lastChecked; const speed=Math.floor(d/dt); checkedEl.textContent=counters.checked.toLocaleString('ru-RU'); speedEl.textContent=speed.toLocaleString('ru-RU'); elapsedEl.textContent=(elapsedSec).toFixed(1)+' c'; counters.lastTs=now; counters.lastChecked=counters.checked; }
function setRunningUI(run){ scanning=run; startBtn.disabled=run; stopBtn.disabled=!run; }
function setProgressBig(checkedBig,totalBig){ let pct=0; if(totalBig>0n){ // масштабируем через целочисленную математику, чтобы избежать переполнений
    const scaled=(checkedBig*10000n)/totalBig; pct=Number(scaled)/100; if(pct>100) pct=100; if(pct<0) pct=0;
  }
  progressBar.style.width=pct.toFixed(2)+'%'; progressPct.textContent=Math.floor(pct)+'%';
}

// -------------------- Монитор ресурсов и eco‑троттлинг --------------------
const Resource = (()=>{
  let lagSamples=[]; let lagTimer=null; let lastTs=performance.now();
  let eco=false; let throttleMs=0; let batteryInfo=null;
  const MAX_SAMPLES=20;
  function start(){
    stop();
    lagTimer=setInterval(()=>{
      const now=performance.now();
      const drift=now - lastTs - 500; // интервал 500мс
      lastTs=now;
      const lag = Math.max(0, drift);
      lagSamples.push(lag); if(lagSamples.length>MAX_SAMPLES) lagSamples.shift();
      // авто‑эко: если средний лаг > 40мс — слегка притормаживаем
      const avg=getLagAvg();
      const wantEco = avg>40;
      const wasEco=eco;
      eco = wantEco || document.visibilityState==='hidden' || (batteryInfo && batteryInfo.dischargingTime !== Infinity);
      throttleMs = eco ? (avg>80? 30 : 15) : 0;
      if(wasEco!==eco){ log(`Режим ресурсов: ${eco? 'экономия' : 'норма'} (lag≈${avg.toFixed(0)}мс)`); }
    },500);
    try{ navigator.getBattery?.().then(b=>{ batteryInfo=b; b.addEventListener('chargingchange',()=>{}); }); }catch{}
    document.addEventListener('visibilitychange',()=>{});
  }
  function stop(){ if(lagTimer){ clearInterval(lagTimer); lagTimer=null; } }
  function getLagAvg(){ if(!lagSamples.length) return 0; return lagSamples.reduce((a,b)=>a+b,0)/lagSamples.length; }
  function getThrottleMs(){ return turboToggle?.checked ? 0 : throttleMs; }
  function isEco(){ return eco; }
  return { start, stop, getLagAvg, getThrottleMs, isEco };
})();
Resource.start();

// EC
const EC_ORDER=BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const G=secpC.ProjectivePoint.BASE;
// Прекомпьют базовой точки ускоряет умножения (инициализация P0, Δ, LEN)
try{ secpC.utils?.precompute?.(8); }catch{}

// Быстрый микробенч — оцениваем хеш‑пропускную способность и подбираем chunk
function quickBench(){
  try{
    const N=8192; // ~8k HASH160
    const buf=new Uint8Array(33); buf[0]=0x02; for(let i=1;i<33;i++) buf[i]=i&255;
    const t0=performance.now();
    for(let i=0;i<N;i++) { const b=buf; b[1]=(i&255); ripemd160(sha256(b)); }
    const dt=(performance.now()-t0)/1000; const qps=Math.max(1, Math.floor(N/dt));
    let workerChunkMin=4096; if(qps>500_000) workerChunkMin=16384; else if(qps>200_000) workerChunkMin=8192;
    return { qps, workerChunkMin };
  }catch{ return { qps: 100_000, workerChunkMin: 4096 }; }
}

async function scanRange({targetAddr,startHex,stopHex,chunkSize}){
  // Строго проверяем адрес: корректный Base58Check и версия 0x00
  const targetH160=decodeBase58P2PKH(targetAddr);
  const start=BigInt('0x'+startHex.replace(/^0x/,''));
  const stop=BigInt('0x'+stopHex.replace(/^0x/,''));
  if(stop<start) throw new Error('Stop Key должен быть >= Start Key');
  if(start===0n||start>=EC_ORDER||stop>=EC_ORDER) throw new Error('Ключи должны быть в диапазоне [1, n-1] секрета secp256k1');

  log(`Диапазон: 0x${start.toString(16)} – 0x${stop.toString(16)} (вкл.)`);
  statusEl.textContent='Сканирование…'; resultEl.textContent='—';
  counters={checked:0,startedAt:performance.now(),lastTs:performance.now(),lastChecked:0, checkedBig:0n};
  abortFlag=false; setRunningUI(true);
  rangeStart=start; rangeStop=stop; totalKeysBig=(stop-start+1n); totalKeys= Number(totalKeysBig>BigInt(Number.MAX_SAFE_INTEGER)? Number.MAX_SAFE_INTEGER : totalKeysBig); setProgressBig(0n,totalKeysBig);

  // Двухфазный режим: compressed → uncompressed. Включаем для средних и больших диапазонов
  const lenBig = stop-start+1n;
  const LARGE = 10_000n;
  const phased = lenBig >= LARGE;
  const format = phased ? 'compressed' : 'both';
  const order = 'zigzag';

  // Автоматическая комбинированная стратегия:
  // 1) Пытаемся запустить Web Workers + EC step
  // 2) Если недоступно или слишком маленький диапазон — interleaved (однопоточно)
  // 3) В крайнем случае — linear
  // Обработчик завершения для двухфазного режима
  onScanComplete = (found)=>{
    if(!phased || found || abortFlag) { onScanComplete=null; return; }
    // Фаза 2: uncompressed
    log('Фаза 1 завершена без результата. Запускаю фазу 2: только uncompressed…');
    counters={checked:0,startedAt:performance.now(),lastTs:performance.now(),lastChecked:0,checkedBig:0n};
    setProgressBig(0n,totalKeysBig);
    setRunningUI(true); statusEl.textContent='Сканирование…';
    try{
      const canWorkers=typeof Worker!== 'undefined' && (navigator.hardwareConcurrency||0) >= 2 && lenBig>10000n;
      if(canWorkers){ scanWorkers({targetAddr,targetH160,start,stop,chunkSize, format:'uncompressed', order}); }
      else { scanInterleaved({targetAddr,targetH160,start,stop,chunkSize, format:'uncompressed', order}); }
    }catch(_){ scanLinear({targetAddr,targetH160,start,stop,chunkSize, format:'uncompressed' }); }
  };

  const bench=quickBench();
  try{
    const canWorkers=typeof Worker!== 'undefined' && (navigator.hardwareConcurrency||0) >= 2;
    // Для малых диапазонов эффективнее сразу запустить параллельную верификацию Δ=G
    if(canWorkers && lenBig <= 1_000_000n){
      return scanWorkersVerifyDirect({targetH160,start,stop,chunkSize, format});
    }
    if(canWorkers && lenBig>10000n){ return scanWorkers({targetAddr,targetH160,start,stop,chunkSize, format, order, bench}); }
  }catch(_){ /* ignore, fallback ниже */ }
  try{ return scanInterleaved({targetAddr,targetH160,start,stop,chunkSize, format, order}); }catch(_){ /* fallback */ }
  return scanLinear({targetAddr,targetH160,start,stop,chunkSize, format});
}

function emitFound(val,compressed,addr,wif){
  updateStats(); const privHex=val.toString(16).padStart(64,'0');
  resultEl.innerHTML=[`НАЙДЕНО ✅`,`Address: ${addr}`,`Private Key (hex): ${privHex}`,`WIF (${compressed?'compressed':'uncompressed'}): ${wif}`].join('\n');
  statusEl.innerHTML='<span class="ok">Успех: адрес совпал</span>';
  log(`Совпадение на ключе 0x${privHex} (${compressed?'compressed':'uncompressed'})`);
  // запомним для диагностики и подставим автоматически
  lastFoundKeyHex=privHex; lastFoundAddr=addr; lastFoundWIF=wif; lastFoundCompressed=compressed;
  try{ if(diagKeyInput) diagKeyInput.value=privHex; }catch{}
  counters.checked=totalKeys; counters.checkedBig=totalKeysBig; setProgressBig(totalKeysBig,totalKeysBig); setRunningUI(false);
  try{ onScanComplete?.(true); }finally{ onScanComplete=null; }
}

function scanLinear({targetAddr,targetH160,start,stop,chunkSize, format}){
  let cur=start; let adaptiveChunk=chunkSize>>>0; const autoTune=true;
  const tick=()=>{
    const t0=performance.now(); const now=performance.now(); if(now-counters.lastTs>400) updateStats();
    if(abortFlag){ statusEl.textContent='Остановлено пользователем'; setRunningUI(false); return; }
    try{
      const end=cur+BigInt(adaptiveChunk)-1n;
      for(;cur<=stop && cur<=end;cur++){
        const priv=bigIntTo32(cur);
        if(format!=='uncompressed'){
          const hC=pubkeyHash160(getPublicKey(priv,true)); if(eqBytes(hC,targetH160)){ const payload=new Uint8Array(21); payload[0]=0x00; payload.set(hC,1); const addrStr=b58c.encode(payload); const wif=privToWIF(priv,true); emitFound(cur,true,addrStr,wif); return; }
        }
        if(format!=='compressed'){
          const hU=pubkeyHash160(getPublicKey(priv,false)); if(eqBytes(hU,targetH160)){ const payload=new Uint8Array(21); payload[0]=0x00; payload.set(hU,1); const addrStr=b58c.encode(payload); const wif=privToWIF(priv,false); emitFound(cur,false,addrStr,wif); return; }
        }
          counters.checked++; counters.checkedBig+=1n; if((counters.checked & 0xff)===0) currentKeyEl.textContent='0x'+cur.toString(16).padStart(64,'0');
      }
  if(cur>stop){ updateStats(); setProgressBig(totalKeysBig,totalKeysBig); statusEl.innerHTML='<span class="warn-text">Совпадений не найдено</span>'; setRunningUI(false); try{ onScanComplete?.(false); }finally{ onScanComplete=null; } return; }
      setProgressBig(counters.checkedBig,totalKeysBig);
      if(autoTune){ const dt=performance.now()-t0; if(dt<8 && adaptiveChunk<1_000_000) adaptiveChunk=Math.min(1_000_000,(adaptiveChunk*1.3)>>>0); else if(dt>40 && adaptiveChunk>1) adaptiveChunk=Math.max(1,(adaptiveChunk*0.75)>>>0); if((counters.checked & 0x7fff)===0) chunkSizeInput.value=String(adaptiveChunk); }
      const pause=Resource.getThrottleMs(); setTimeout(tick, pause||0);
    }catch(e){ console.error(e); log('Ошибка: '+(e?.message||e)); statusEl.innerHTML='<span class="danger">Ошибка во время сканирования</span>'; setRunningUI(false); }
  };
  tick();
}

function gcd(a,b){ while(b){ const t=a%b; a=b; b=t; } return a; }
function gcdBig(a,b){ a=BigInt(a); b=BigInt(b); while(b!==0n){ const t=a%b; a=b; b=t; } return a; }
function pickStride(len, lanes=1){
  // Стремимся к rawStep = lanes*s ≈ len - δ (маленький), чтобы редко происходили обёртки и был 1 EC‑add на шаг
  let s = Math.max(3, Math.floor(len/lanes) - 1);
  // ограничим адекватным максимумом, не критично если меньше
  s = Math.min(s, 1<<20);
  if((s & 1)===0) s-=1; if(s<3) s=3;
  while(gcd(s,len)!==1){ s-=2; if(s<3){ s=3; break; } }
  return s;
}
function pickStrideOddCoprimeW(W){
  // Нужен нечётный s, взаимнопростой с W (для len=2^k любое нечётное s также взаимнопросто с len)
  const candidates=[65537, 32771, 131071, 8191, 4099, 2053, 1021, 523, 257, 193, 97, 73, 53, 41, 37, 29, 23, 19, 17, 13, 11, 7, 5, 3];
  for(const c of candidates){ if((c & 1)===1 && gcd(c,W)===1) return c; }
  let s=3; while(gcd(s,W)!==1) s+=2; return s;
}

function scanInterleaved({targetAddr,targetH160,start,stop,chunkSize, format, order}){
  const len=Number(stop-start+1n);
  const lanes=Math.max(2,Math.min(8,(navigator.hardwareConcurrency||4)>>>0));
  const perLane=(n)=>Math.ceil(n/lanes);
  const seed=Math.floor(Math.random()*len)>>>0;
  const s=pickStride(len, lanes);
  const rawStep=lanes*s;
  // Эвристика: если шаг слишком велик относительно диапазона, нормальный порядок эффективнее зигзага
  let effOrder = order;
  if(rawStep > Math.max(8, Math.floor(len/lanes))){ effOrder='normal'; }
  const DELTA_POINT=G.multiply(BigInt(rawStep));
  const LEN_POINT=G.multiply(BigInt(len));
  const WRAP_POINT=LEN_POINT.negate();

  const laneState=new Array(lanes);
  const laneBufC=new Array(lanes);
  const laneBufU=new Array(lanes);
  for(let j=0;j<lanes;j++){
    const idx0=(seed+((j*s)%len))%len; const k0=start+BigInt(idx0); const P0=G.multiply(k0);
    const dir=(effOrder==='zigzag' && (j&1)===1)? -1 : 1;
    laneState[j]={idx:idx0,k:k0,P:P0, dir};
    laneBufC[j]=new Uint8Array(33);
    laneBufU[j]=new Uint8Array(65);
  }
  log(`Инновационная стратегия: ${lanes} поток(ов), шаг s=${s}, seed=${seed}, порядок=${effOrder}`);

  let adaptiveChunk=chunkSize>>>0; const autoTune=true;
  const tick=()=>{
    const t0=performance.now(); const now=performance.now(); if(now-counters.lastTs>400) updateStats();
    if(abortFlag){ statusEl.textContent='Остановлено пользователем'; setRunningUI(false); return; }
    try{
      const totalToDo=Math.min(adaptiveChunk,totalKeys-counters.checked);
      const each=perLane(totalToDo);
      for(let j=0;j<lanes;j++){
        let take=Math.min(each,totalToDo-j*each);
        while(take-->0 && counters.checked<totalKeys){
          const st=laneState[j];
          // Однократная аффинная конверсия
          const A=st.P.toAffine();
          // Переиспользуем буферы на уровень лейна
          const cBuf=laneBufC[j];
          const uBuf=laneBufU[j];
          // compressed
          cBuf[0] = (A.y & 1n) ? 0x03 : 0x02;
          writeBigTo32(cBuf, 1, A.x);
          // Сначала проверяем compressed
          if(format!=='uncompressed'){
            const hC=pubkeyHash160(cBuf); if(eqH160(hC,targetH160)){ const addrStr=addrFromH160(hC); const wif=privToWIF(bigIntTo32(st.k),true); emitFound(st.k,true,addrStr,wif); return; }
          }
          // uncompressed только если нужно
          if(format!=='compressed'){
            uBuf[0]=0x04; writeBigTo32(uBuf,1,A.x); writeBigTo32(uBuf,33,A.y);
            const hU=pubkeyHash160(uBuf); if(eqH160(hU,targetH160)){ const addrStr=addrFromH160(hU); const wif=privToWIF(bigIntTo32(st.k),false); emitFound(st.k,false,addrStr,wif); return; }
          }
          counters.checked++; counters.checkedBig+=1n; if((counters.checked & 0xff)===0) currentKeyEl.textContent='0x'+st.k.toString(16).padStart(64,'0');
          // шаг в зависимости от порядка
          const step = (effOrder==='zigzag') ? (st.dir===-1? -rawStep : rawStep) : rawStep;
          let nextIdxAbs=st.idx+step;
          if(step>=0){
            const wrapCount = nextIdxAbs>=len ? Math.floor(nextIdxAbs/len) : 0;
            nextIdxAbs = nextIdxAbs>=0 ? (nextIdxAbs % len) : ((nextIdxAbs % len + len) % len);
            // добавляем один раз +Δ, затем корректируем WRAP столько раз, сколько обёрток
            st.P = st.P.add(DELTA_POINT);
            for(let w=0; w<wrapCount; w++) st.P = st.P.add(WRAP_POINT);
          } else {
            // шаг назад: -Δ и, если ушли ниже 0, прибавляем LEN_POINT (т.е. -WRAP) соответствующее число раз
            const wrapCount = nextIdxAbs<0 ? Math.floor(((-nextIdxAbs)+len-1)/len) : 0;
            nextIdxAbs = (nextIdxAbs % len + len) % len;
            st.P = st.P.add(DELTA_POINT.negate());
            for(let w=0; w<wrapCount; w++) st.P = st.P.add(WRAP_POINT.negate());
          }
          st.idx=nextIdxAbs; st.k=start+BigInt(st.idx);
          // направление постоянное — не переключаем, чтобы сохранять покрытие арифм. прогрессией
        }
      }
  if(counters.checkedBig>=totalKeysBig){ updateStats(); setProgressBig(totalKeysBig,totalKeysBig); statusEl.innerHTML='<span class="warn-text">Совпадений не найдено</span>'; setRunningUI(false); try{ onScanComplete?.(false); }finally{ onScanComplete=null; } return; }
      setProgressBig(counters.checkedBig,totalKeysBig);
      if(autoTune){ const dt=performance.now()-t0; if(dt<8 && adaptiveChunk<1_000_000) adaptiveChunk=Math.min(1_000_000,(adaptiveChunk*1.25)>>>0); else if(dt>40 && adaptiveChunk>1) adaptiveChunk=Math.max(1,(adaptiveChunk*0.8)>>>0); if((counters.checked & 0x7fff)===0) chunkSizeInput.value=String(adaptiveChunk); }
      const pause=Resource.getThrottleMs(); setTimeout(tick, pause||0);
    }catch(e){ console.error(e); log('Ошибка: '+(e?.message||e)); statusEl.innerHTML='<span class="danger">Ошибка во время сканирования</span>'; setRunningUI(false); }
  };
  tick();
}

// Верификационный однотредовый EC‑скан: шаг Δ=1·G, гарантированное покрытие
function scanVerifyEC({targetH160,start,stop,format}){
  const len = Number(stop - start + 1n);
  let idx = 0; let k = start; let P = G.multiply(start);
  const DELTA = G; // 1·G
  const WRAP = G.multiply(BigInt(len)).negate();
  // предсоздадим буферы
  const cBuf=new Uint8Array(33);
  const uBuf=new Uint8Array(65);
  const tick=()=>{
    const now=performance.now(); if(now-counters.lastTs>400) updateStats();
    if(abortFlag){ statusEl.textContent='Остановлено пользователем'; setRunningUI(false); return; }
    // обработаем порцию (адаптивно по CPU лагу)
    let toDo = 1<<14; // 16384 за тик — быстро и гладко
    try{
      while(toDo-- > 0 && idx < len){
        const A=P.toAffine();
        cBuf[0] = (A.y & 1n) ? 0x03 : 0x02; writeBigTo32(cBuf,1,A.x);
        if(format!== 'uncompressed'){
          const hC=pubkeyHash160(cBuf); if(eqH160(hC,targetH160)){ const addrStr=addrFromH160(hC); const wif=privToWIF(bigIntTo32(k),true); emitFound(k,true,addrStr,wif); return; }
        }
        if(format!== 'compressed'){
          uBuf[0]=0x04; writeBigTo32(uBuf,1,A.x); writeBigTo32(uBuf,33,A.y);
          const hU=pubkeyHash160(uBuf); if(eqH160(hU,targetH160)){ const addrStr=addrFromH160(hU); const wif=privToWIF(bigIntTo32(k),false); emitFound(k,false,addrStr,wif); return; }
        }
        counters.checked++; counters.checkedBig+=1n; if((counters.checked & 0x7ff)===0) currentKeyEl.textContent='0x'+k.toString(16).padStart(64,'0');
        // шаг +1 с корректировкой обёрток
        idx += 1; k = start + BigInt(idx);
        P = P.add(DELTA);
        if(idx % len === 0){ P = P.add(WRAP); }
      }
      if(counters.checkedBig>=totalKeysBig){ updateStats(); setProgressBig(totalKeysBig,totalKeysBig); statusEl.innerHTML='<span class="warn-text">Совпадений не найдено</span>'; setRunningUI(false); try{ onScanComplete?.(false); }finally{ onScanComplete=null; } return; }
      setProgressBig(counters.checkedBig,totalKeysBig);
      const pause=Resource.getThrottleMs(); setTimeout(tick, pause||0);
    }catch(e){ console.error(e); log('Ошибка верификации: '+(e?.message||e)); statusEl.innerHTML='<span class="danger">Ошибка во время сканирования</span>'; setRunningUI(false); }
  };
  tick();
}

// -------------------- Web Workers стратегия --------------------
function cleanupWorkers(){
  for(const w of workerPool){ try{ w.terminate(); }catch(_){/* ignore */} }
  workerPool=[]; workerMeta=[]; workersRunning=false; workersFound=false;
}

function stopWorkers(){
  for(const w of workerPool){ try{ w.postMessage({type:'stop'}); w.terminate(); }catch(_){/* ignore */} }
  cleanupWorkers();
}

function scanWorkers({targetAddr,targetH160,start,stop,chunkSize, format, order, bench}){
  // Распределяем диапазон по W воркерам с шагом stride=W*s и EC-приращением точки
  const lenBig=stop-start+1n;
  let W=(navigator.hardwareConcurrency||4)>>>0; W=Math.max(2,Math.min(16,W));
  if(lenBig<BigInt(W)) W=Number(lenBig);
  if(W<=1){ log('Недостаточно ядер: fallback на interleaved'); return scanInterleaved({targetAddr,targetH160,start,stop,chunkSize, format, order}); }
  // Подберём s так, чтобы rawStep = W*s ≈ len/W (меньше обёрток и лишних EC‑операций)
  let s;
  try{
    const desired = Number(lenBig / BigInt(W*W));
    if(desired>=5){
      let cand = Math.min(desired-1, 1<<20);
      if((cand & 1)===0) cand-=1; if(cand<3) cand=3;
      // Требуем взаимную простоту с W и с длиной диапазона (для покрытия без дыр)
      while(gcd(cand, W)!==1 || gcdBig(BigInt(cand), lenBig)!==1n){
        cand-=2; if(cand<3){ cand=3; break; }
      }
      s = cand;
    } else {
      // Ищем небольшой нечётный s, взаимнопростой и с W, и с lenBig
      let cand = pickStrideOddCoprimeW(W);
      while(gcdBig(BigInt(cand), lenBig)!==1n){ cand += 2; if(cand> (1<<20)) { cand = 3; break; } }
      s = cand;
    }
  }catch(_){ s = pickStrideOddCoprimeW(W); }
  // Случайный seed; предпочитаем криптографический источник
  let seed;
  try{
    const tmp=new Uint32Array(1);
    self.crypto?.getRandomValues(tmp);
    seed = (tmp[0]>>>0) || (Math.floor(Math.random()*0xffffffff)>>>0);
  }catch{ seed = (Math.floor(Math.random()*0xffffffff)>>>0); }
  const q=lenBig/BigInt(W), r=(lenBig%BigInt(W));
  const rawStep=W*s;
  // Если rawStep слишком велик относительно длины, зигзаг невыгоден
  let effOrder = order;
  if(BigInt(rawStep) > lenBig/2n){ effOrder = 'normal'; }
  // Остаточное разбиение: m — степень двойки, m<=W, и len делится на m
  let m=1; let mask=0;
  const pow2 = (x)=>{ let p=1; while((p<<1)<=x) p<<=1; return p; };
  const candidate = pow2(W);
  if(candidate>=4){ // начинаем с 4, если хватает ядер
    const mTry = Math.min(candidate, 16); // углубим до 16 при возможности
    if(lenBig % BigInt(mTry) === 0n){ m = mTry; mask = m-1; }
  }
  // Выравнивание шага под residue split: хотим rawStep % m == 0 и gcd(rawStep/m, len/m) == 1
  if(m>1){
    const g = gcd(W, m);
    const f = Math.max(1, Math.floor(m / g)); // требуемая кратность для s, чтобы W*s % m == 0
    // s := ближайшее вверх кратное f, сохранить нечётность (добавляем шагами f)
    const modf = s % f; if(modf !== 0) s += (f - modf);
    if((s & 1)===0) s += f;
    // Теперь проверим взаимную простоту шага внутри класса (rawStep/m)
    const lenPerClass = (lenBig / BigInt(m));
    let stepPerClass = BigInt((W / g)) * BigInt(Math.floor(s / f));
    let guard=0;
    while(gcdBig(stepPerClass, lenPerClass) !== 1n && guard++ < 128){ s += (2*f); stepPerClass = BigInt((W / g)) * BigInt(Math.floor(s / f)); }
  }
  let batchSz = (bench?.qps||0) > 1_200_000 ? 32 : ( (bench?.qps||0) > 750_000 ? 16 : ( (bench?.qps||0) > 300_000 ? 8 : 4 ) );
  if(Resource.isEco()) batchSz = Math.max(4, Math.floor(batchSz/2));
  log(`Стратегия: Web Workers ×${W} (EC step, s≈${s} (+пер-воркер вариация), seed=${seed}, Δ≈${W*s}, порядок=${effOrder}${m>1?`, residue m=${m}, aligned`:''}, batch=${batchSz}${lenBig>(1n<<40n)?', epoch mode':''})`);

  workersRunning=true; workersFound=false; workerPool=[]; workerMeta=[];
  counters.startedAt=performance.now(); counters.lastTs=performance.now();
  let workersFailed=false;
  const hugeEpoch = (lenBig > (1n<<40n));
  // Порог для одного «эпохального» прохода воркера ~1–2 секунды
  const benchQps = Math.max(50_000, bench?.qps||100_000);
  const targetEpochSec = 2;
  const perWorkerQps = Math.max(20_000, Math.floor(benchQps/Math.max(1,W)));
  const epochLimitNum = Math.max(1_000_000, Math.min(50_000_000, perWorkerQps*targetEpochSec));
  const chunkMin = Math.max(bench?.workerChunkMin||4096, Number(chunkSize)||500);

  const maybeFinish=()=>{
    if(workersFound) return; // уже нашли
    if(workerMeta.length===W && workerMeta.every(m=>m.done)){
      updateStats(); setProgressBig(totalKeysBig,totalKeysBig);
      // Автопроверка на малых диапазонах (<= 1e6): распараллелим верификацию Δ=G на все воркеры
      if(totalKeysBig <= 1_000_000n && !abortFlag){
        log('Совпадений не найдено в воркерах. Запускаю параллельную верификацию (Δ=G) на воркерах…');
        const total = stop - start + 1n;
        // обнулим метрики и переиспользуем текущий пул воркеров
        counters={checked:0,startedAt:performance.now(),lastTs:performance.now(),lastChecked:0,checkedBig:0n};
        setProgressBig(0n,totalKeysBig); setRunningUI(true); statusEl.textContent='Сканирование…';
        let finished=0; workersFound=false;
        for(let i=0;i<W;i++){
          // interleaved: класс i по модулю W
          const offset = BigInt(i);
          const cnt = total>BigInt(i) ? ((total - BigInt(i) + BigInt(W) - 1n) / BigInt(W)) : 0n;
          const w = workerPool[i];
          workerMeta[i]={checked:0, done:false};
          w.onmessage=(ev)=>{
            const msg=ev.data||{};
            if(msg.type==='progress'){
              if(typeof msg.checkedBigStr==='string'){
                const inc = BigInt(msg.checkedBigStr);
                // в verifyEc воркер шлёт абсолют, но мы сбрасываем по 0 и суммируем дельту
                const prev = BigInt(workerMeta[i].checked);
                if(inc>prev){ const d=inc-prev; counters.checked+=Number(d<=BigInt(1<<30)?d:0n); counters.checkedBig+=d; workerMeta[i].checked=Number(inc<=BigInt(0xffffffff)?inc:BigInt(0xffffffff)); }
              }
              const now=performance.now(); if(now-counters.lastTs>300){ updateStats(); setProgressBig(counters.checkedBig,totalKeysBig); }
            }else if(msg.type==='found'){
              if(workersFound) return; workersFound=true;
              const keyHex=(msg.key||'').padStart(64,'0');
              resultEl.innerHTML=[`НАЙДЕНО ✅`,`Address: ${msg.addr}`,`Private Key (hex): ${keyHex}`,`WIF (${msg.compressed?'compressed':'uncompressed'}): ${msg.wif}`].join('\n');
              statusEl.innerHTML='<span class="ok">Успех: адрес совпал</span>';
              log(`Совпадение на ключе 0x${keyHex} (${msg.compressed?'compressed':'uncompressed'})`);
              counters.checked=totalKeys; counters.checkedBig=totalKeysBig; setProgressBig(totalKeysBig,totalKeysBig); updateStats();
              stopWorkers(); setRunningUI(false);
              try{ onScanComplete?.(true); }finally{ onScanComplete=null; }
            }else if(msg.type==='done'){
              workerMeta[i].done=true; finished++;
              if(!workersFound && finished===W){
                // доводим прогресс до 100%
                counters.checked=totalKeys; counters.checkedBig=totalKeysBig; setProgressBig(totalKeysBig,totalKeysBig); updateStats();
                statusEl.innerHTML='<span class="warn-text">Совпадений не найдено</span>';
                setRunningUI(false); cleanupWorkers();
                try{ onScanComplete?.(false); }finally{ onScanComplete=null; }
              }
            }else if(msg.type==='error'){
              log('Worker verifyEc error: '+msg.message);
            }
          };
          w.postMessage({ type:'verifyEc', start, offset, count: cnt, chunk: Math.max(4096, Number(chunkSize)||500), throttleMs: Resource.getThrottleMs(), targetH160, format, interleaved: true, W });
        }
        workersRunning=true;
        return;
      }
      statusEl.innerHTML='<span class="warn-text">Совпадений не найдено</span>';
      setRunningUI(false); cleanupWorkers();
      try{ onScanComplete?.(false); }finally{ onScanComplete=null; }
    }
  };

  for(let i=0;i<W;i++){
    const w=new Worker(new URL('./worker.js', import.meta.url), { type:'module' });
    const meta={checked:0, done:false};
    workerMeta.push(meta);
    w.onmessage=(ev)=>{
      const msg=ev.data||{};
      if(msg.type==='progress'){
        if(typeof msg.checkedBigStr === 'string'){
          const newBig=BigInt(msg.checkedBigStr);
          const metaBig=BigInt(meta.checked);
          if(newBig>metaBig){ const deltaBig=newBig-metaBig; const deltaNum = Number(deltaBig <= BigInt(1<<30) ? deltaBig : BigInt(0));
            counters.checked += deltaNum; counters.checkedBig += deltaBig; meta.checked = Number(newBig <= BigInt(0xffffffff) ? newBig : BigInt(0xffffffff));
          }
        }else if(typeof msg.checked === 'number'){
          const total=(msg.checked>>>0);
          if(total>meta.checked){ const delta=total - meta.checked; counters.checked+=delta; counters.checkedBig+=BigInt(delta); meta.checked=total; }
        }
        const now=performance.now(); if(now-counters.lastTs>300){ updateStats(); setProgressBig(counters.checkedBig,totalKeysBig); }
      }else if(msg.type==='found'){
        if(workersFound) return; workersFound=true;
        const keyHex=(msg.key||'').padStart(64,'0');
        resultEl.innerHTML=[`НАЙДЕНО ✅`,`Address: ${msg.addr}`,`Private Key (hex): ${keyHex}`,`WIF (${msg.compressed?'compressed':'uncompressed'}): ${msg.wif}`].join('\n');
        statusEl.innerHTML='<span class="ok">Успех: адрес совпал</span>';
        log(`Совпадение на ключе 0x${keyHex} (${msg.compressed?'compressed':'uncompressed'})`);
        counters.checked=totalKeys; counters.checkedBig=totalKeysBig; setProgressBig(totalKeysBig,totalKeysBig); updateStats();
        stopWorkers(); setRunningUI(false);
        try{ onScanComplete?.(true); }finally{ onScanComplete=null; }
      }else if(msg.type==='done'){
        if(hugeEpoch && !workersFound && !abortFlag){
          // Пере‑запускаем воркера с новым seed и иногда новым stride s — рандомизируем покрытие
          const newSeed = (Math.floor(Math.random()*0xffffffff)>>>0);
          let sNew = s;
          if((Math.random()<0.5)){
            let cand = pickStrideOddCoprimeW(W);
            let guard=0; while(gcdBig(BigInt(cand), lenBig)!==1n && guard++<64){ cand += 2; }
            sNew = cand;
          }
          meta.checked=0; meta.done=false;
          w.postMessage({
            type:'scanEc', start, len: lenBig, W, s: sNew,
            seed: newSeed, workerIndex: i,
            limit: BigInt(epochLimitNum), chunk: chunkMin,
            throttleMs: Resource.getThrottleMs(), targetH160, format, order: effOrder,
            mask, residue: (m>1? (i & (m-1)) : 0)
          });
          return;
        }
        meta.done=true; maybeFinish();
      }else if(msg.type==='error'){
        meta.done=true; log('Worker error: '+msg.message);
        if(!workersFailed && !workersFound){
          workersFailed=true; // мгновенный fallback на interleaved
          stopWorkers();
          // Запускаем interleaved как запасной вариант
          setTimeout(()=>scanInterleaved({targetAddr,targetH160,start,stop,chunkSize, format, order}), 0);
          return;
        }
        maybeFinish();
      }
    };
    w.onerror=(e)=>{ meta.done=true; log('Worker onerror: '+(e?.message||e)); maybeFinish(); };

    workerPool.push(w);
    const limit = hugeEpoch ? BigInt(epochLimitNum) : (q + (BigInt(i) < r ? 1n : 0n)); // BigInt
    // Пер-воркер шаг s_i для независимости обходов
    let s_i = s;
    if(W>1){
      const g = gcd(W, m);
      const f = m>1 ? Math.max(1, Math.floor(m / g)) : 1;
      const lenPerClass = m>1 ? (lenBig / BigInt(m)) : lenBig;
      s_i = s + (2*i*f);
      let guard=0; 
      while(guard++<128){
        const okCoprimeW = gcd(s_i,W)===1;
        const okCoprimeLen = gcdBig(BigInt(s_i), lenBig)===1n;
        const stepPerClassI = m>1 ? (BigInt(W / g) * BigInt(Math.floor(s_i / f))) : BigInt(W*s_i);
        const okClass = gcdBig(stepPerClassI, lenPerClass)===1n;
        if(okCoprimeW && okCoprimeLen && okClass) break;
        s_i += (2*f);
      }
      if(s_i > (1<<20)) s_i = s;
    }
    // Бимодальное распределение: половина воркеров сканирует от начала, половина — от конца
    const seedMode = (hugeEpoch && i >= Math.floor(W/2)) ? 'end' : 'start';
    w.postMessage({
      type:'scanEc',
      start,
      len: lenBig,
      W,
      s: s_i,
      seed,
      workerIndex: i,
      limit,
      // Более крупный минимум чанка для снижения IPC‑накладных
      chunk: chunkMin,
      throttleMs: Resource.getThrottleMs(),
      targetH160,
      format,
      order: effOrder,
      batch: batchSz,
      seedMode,
      mask,
      residue: (m>1? (i & (m-1)) : 0)
    });
  }

  // Плановый UI апдейтер, пока воркеры считают
  const uiTick=()=>{
    if(!workersRunning) return; updateStats(); setProgressBig(counters.checkedBig,totalKeysBig);
    // Периодически обновляем троттлинг воркерам
    const thr = Resource.getThrottleMs();
    for(const w of workerPool){ try{ w.postMessage({type:'throttle', throttleMs: thr}); }catch{} }
    requestAnimationFrame(uiTick);
  };
  requestAnimationFrame(uiTick);
}

// Прямой режим: параллельная верификация Δ=G на всех ядрах (для малых диапазонов)
function scanWorkersVerifyDirect({targetH160,start,stop,chunkSize, format}){
  const lenBig=stop-start+1n; let W=(navigator.hardwareConcurrency||4)>>>0; W=Math.max(2,Math.min(8,W)); if(lenBig<BigInt(W)) W=Number(lenBig); if(W<=1) return scanVerifyEC({targetH160,start,stop,format});
  cleanupWorkers(); workersRunning=true; workersFound=false; workerPool=[]; workerMeta=[];
  counters.startedAt=performance.now(); counters.lastTs=performance.now();
  log(`Стратегия: Параллельная верификация Δ=G ×${W} (interleaved=W, chunk≥${Math.max(4096, Number(chunkSize)||500)})`);
  for(let i=0;i<W;i++){
    const w=new Worker(new URL('./worker.js', import.meta.url), { type:'module' });
    const meta={checked:0, done:false}; workerMeta.push(meta); workerPool.push(w);
    // Interleaved: каждому воркеру класс по модулю W: k = start + i + t*W
    const total = stop - start + 1n;
    const first = start + BigInt(i);
    // количество ключей в классе: ceil((total - i)/W)
    const cnt = total>BigInt(i) ? ((total - BigInt(i) + BigInt(W) - 1n) / BigInt(W)) : 0n;
    const offset = (first - start); // просто i
    w.onmessage=(ev)=>{
      const msg=ev.data||{};
      if(msg.type==='progress'){
        if(typeof msg.checkedBigStr==='string'){
          const inc = BigInt(msg.checkedBigStr);
          const prev = BigInt(meta.checked);
          if(inc>prev){ const d=inc-prev; counters.checked+=Number(d<=BigInt(1<<30)?d:0n); counters.checkedBig+=d; meta.checked=Number(inc<=BigInt(0xffffffff)?inc:BigInt(0xffffffff)); }
        }
        const now=performance.now(); if(now-counters.lastTs>300){ updateStats(); setProgressBig(counters.checkedBig,lenBig); }
      }else if(msg.type==='found'){
        if(workersFound) return; workersFound=true;
        const keyHex=(msg.key||'').padStart(64,'0');
        resultEl.innerHTML=[`НАЙДЕНО ✅`,`Address: ${msg.addr}`,`Private Key (hex): ${keyHex}`,`WIF (${msg.compressed?'compressed':'uncompressed'}): ${msg.wif}`].join('\n');
        statusEl.innerHTML='<span class="ok">Успех: адрес совпал</span>';
        log(`Совпадение на ключе 0x${keyHex} (${msg.compressed?'compressed':'uncompressed'})`);
        counters.checked=Number(lenBig>BigInt(Number.MAX_SAFE_INTEGER)?Number.MAX_SAFE_INTEGER:lenBig); counters.checkedBig=lenBig; setProgressBig(lenBig,lenBig); updateStats();
        stopWorkers(); setRunningUI(false);
        try{ onScanComplete?.(true); }finally{ onScanComplete=null; }
      }else if(msg.type==='done'){
        meta.done=true; if(workerMeta.every(m=>m.done) && !workersFound){
          counters.checkedBig=lenBig; setProgressBig(lenBig,lenBig); updateStats();
          // Safety fallback: однотредовая EC‑верификация, затем линейный скан
          cleanupWorkers();
          log('Параллельная верификация не дала совпадений. Запускаю однотредовую EC‑верификацию…');
          // Подвяжем финальный фоллбек на linear, если и EC‑verify не найдёт
          const prevOnComplete = onScanComplete;
          onScanComplete = (found)=>{
            // восстановим предыдущий обработчик (для двухфазности), но нам он тут не нужен
            onScanComplete = prevOnComplete || null;
            if(!found && !abortFlag){
              log('EC‑верификация не дала совпадений. Запускаю линейный проверочный проход…');
              counters={checked:0,startedAt:performance.now(),lastTs:performance.now(),lastChecked:0,checkedBig:0n};
              setProgressBig(0n,lenBig); setRunningUI(true); statusEl.textContent='Сканирование…';
              setTimeout(()=>scanLinear({targetAddr:'',targetH160,start,stop,chunkSize: Math.max(500, Number(chunkSize)||500), format}),0);
            }
          };
          counters={checked:0,startedAt:performance.now(),lastTs:performance.now(),lastChecked:0,checkedBig:0n};
          setProgressBig(0n,lenBig); setRunningUI(true); statusEl.textContent='Сканирование…';
          setTimeout(()=>scanVerifyEC({targetH160,start,stop,format}),0);
        }
      }else if(msg.type==='error'){ log('Worker verifyEc error: '+msg.message); }
    };
    w.postMessage({ type:'verifyEc', start, offset, count: cnt, chunk: Math.max(4096, Number(chunkSize)||500), throttleMs: Resource.getThrottleMs(), targetH160, format, interleaved: true, W });
  }
  const uiTick=()=>{ if(!workersRunning) return; updateStats(); setProgressBig(counters.checkedBig,lenBig); const thr=Resource.getThrottleMs(); for(const w of workerPool){ try{ w.postMessage({type:'throttle', throttleMs: thr}); }catch{} } requestAnimationFrame(uiTick); }; requestAnimationFrame(uiTick);
}

function sanitizeHex64(s){ s=s.trim(); if(s.startsWith('0x')) s=s.slice(2); if(!/^[0-9a-fA-F]{1,64}$/.test(s)) throw new Error('Ожидался HEX (0-9a-f) длиной до 64 символов'); return s.padStart(64,'0').toLowerCase(); }
function padHex64(shortHex){ let s=shortHex.replace(/^0x/,'').toLowerCase(); if(!/^[0-9a-f]{1,64}$/.test(s)) throw new Error('Некорректный HEX для пресета'); return s.padStart(64,'0'); }
function fillPuzzle10(){ targetAddrInput.value='1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe'; startKeyInput.value=padHex64('0200'); stopKeyInput.value=padHex64('03ff'); log('Пресет #10 применён'); }
function fillPuzzle20(){ targetAddrInput.value='1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum'; startKeyInput.value=padHex64('80000'); stopKeyInput.value=padHex64('fffff'); log('Пресет #20 применён'); }
function fillPuzzle19(){
  targetAddrInput.value='1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w';
  startKeyInput.value=padHex64('40000');
  stopKeyInput.value=padHex64('7ffff');
  log('Пресет #19 применён');
}
function fillPuzzle70(){
  targetAddrInput.value='19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR';
  startKeyInput.value='0000000000000000000000000000000000000000000000200000000000000000';
  stopKeyInput.value='00000000000000000000000000000000000000000000003fffffffffffffffff';
  log('Пресет #70 применён');
}
function fillPuzzle71(){
  targetAddrInput.value='1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU';
  startKeyInput.value='0000000000000000000000000000000000000000000000400000000000000000';
  stopKeyInput.value='00000000000000000000000000000000000000000000007fffffffffffffffff';
  log('Пресет #71 применён');
}

// События UI
startBtn.addEventListener('click', async ()=>{
  try{
    const targetAddr=targetAddrInput.value.trim();
    const startHex=sanitizeHex64(startKeyInput.value);
    const stopHex=sanitizeHex64(stopKeyInput.value);
    const chunkSize=Math.max(1,Math.min(1_000_000,Number(chunkSizeInput.value)||500));
    startKeyInput.value=startHex; stopKeyInput.value=stopHex;
    statusEl.textContent='Подготовка…'; logsEl.textContent=''; resultEl.textContent='—';
  counters={checked:0,startedAt:0,lastTs:0,lastChecked:0, checkedBig:0n}; checkedEl.textContent='0'; speedEl.textContent='0'; elapsedEl.textContent='0.0 c'; currentKeyEl.textContent='—';
    await scanRange({targetAddr,startHex,stopHex,chunkSize});
  }catch(e){ statusEl.innerHTML=`<span class="danger">${e?.message||e}</span>`; log('Ошибка при запуске: '+(e?.message||e)); }
});

stopBtn.addEventListener('click',()=>{ abortFlag=true; if(workersRunning) stopWorkers(); });

preset10Btn.addEventListener('click',()=>{ try{ fillPuzzle10(); }catch(e){ log('Ошибка пресета #10: '+(e?.message||e)); } });
preset19Btn?.addEventListener('click',()=>{ try{ fillPuzzle19(); }catch(e){ log('Ошибка пресета #19: '+(e?.message||e)); } });
preset20Btn.addEventListener('click',()=>{ try{ fillPuzzle20(); }catch(e){ log('Ошибка пресета #20: '+(e?.message||e)); } });
preset70Btn.addEventListener('click',()=>{ try{ fillPuzzle70(); }catch(e){ log('Ошибка пресета #70: '+(e?.message||e)); } });
preset71Btn.addEventListener('click',()=>{ try{ fillPuzzle71(); }catch(e){ log('Ошибка пресета #71: '+(e?.message||e)); } });

// Диагностика: из HEX приватного ключа — адреса (c/u)
diagBtn?.addEventListener('click',()=>{
  try{
    let raw = (diagKeyInput.value||'').trim();
    if(!raw){
      if(lastFoundKeyHex){ raw = lastFoundKeyHex; diagKeyInput.value = raw; }
      else { throw new Error('Введите приватный ключ в HEX (до 64 символов)'); }
    }
    const hex = sanitizeHex64(raw);
    const k = BigInt('0x'+hex);
    if(k===0n) throw new Error('Ключ не может быть нулевым');
    const priv = bigIntTo32(k);
    const pubC = getPublicKey(priv, true);
    const pubU = getPublicKey(priv, false);
    const addrC = pubkeyToP2PKH(pubC);
    const addrU = pubkeyToP2PKH(pubU);
    const curStart = BigInt('0x'+(startKeyInput.value||'0'));
    const curStop = BigInt('0x'+(stopKeyInput.value||'0'));
    const inRange = (k>=curStart && k<=curStop);
    diagOut.textContent = `Compressed: ${addrC}\nUncompressed: ${addrU}\nВ диапазоне текущего выбора: ${inRange?'да':'нет'}`;
  }catch(e){ diagOut.textContent = 'Ошибка: '+(e?.message||e); }
});
