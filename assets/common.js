// Общие утилиты и константы (не зависят от DOM)
import { sha256 } from 'https://esm.sh/@noble/hashes@1.4.0/sha256';
import { ripemd160 } from 'https://esm.sh/@noble/hashes@1.4.0/ripemd160';
import { base58check } from 'https://esm.sh/@scure/base@1.1.5';

// Base58Check encoder (версия должна быть создана с sha256)
export const b58c = base58check(sha256);

// Константы secp256k1
export const EC_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// Базовые утилиты
export const u8 = (arr) => new Uint8Array(arr);

export function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  if (hex.length % 2 !== 0) throw new Error('HEX длина нечетная');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bigIntTo32(x) {
  if (x < 0n) throw new Error('Отрицательный ключ');
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  if (v !== 0n) throw new Error('Слишком большое значение для приватного ключа');
  return out;
}

export function writeBigTo32(dst, off, bi) {
  let x = bi;
  for (let i = 31; i >= 0; i--) { dst[off + i] = Number(x & 0xffn); x >>= 8n; }
}

// Хеши/адреса
export function pubkeyHash160(pub) { return ripemd160(sha256(pub)); }

export function addrFromH160(h160) {
  const payload = new Uint8Array(21);
  payload[0] = 0x00; // mainnet P2PKH
  payload.set(h160, 1);
  return b58c.encode(payload);
}

export function privToWIF(priv32, compressed) {
  const body = compressed ? u8([0x80, ...priv32, 0x01]) : u8([0x80, ...priv32]);
  return b58c.encode(body);
}

export function eqH160(a, b) {
  if (!a || !b || a.length !== 20 || b.length !== 20) return false;
  const da = new DataView(a.buffer, a.byteOffset, 20);
  const db = new DataView(b.buffer, b.byteOffset, 20);
  for (let i = 0; i < 20; i += 4) { if (da.getUint32(i, true) !== db.getUint32(i, true)) return false; }
  return true;
}

export function decodeBase58P2PKH(addr) {
  let raw;
  try { raw = b58c.decode(addr); } catch (e) { throw new Error('Некорректный Base58Check адрес'); }
  if (!(raw instanceof Uint8Array) || raw.length !== 21) throw new Error('Некорректная длина адреса');
  if (raw[0] !== 0x00) throw new Error('Ожидается только mainnet P2PKH (префикс 0x00)');
  return raw.slice(1);
}

export { sha256, ripemd160 };
