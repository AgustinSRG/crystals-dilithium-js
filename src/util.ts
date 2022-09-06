// Utils

"use strict"

import { SHAKE } from 'sha3';
import { CRHBYTES, N, POLYT0_PACKEDBYTES, POLYT1_PACKEDBYTES, Q, SEEDBYTES } from './constants';
import { DilithiumParameterSpec } from './param';
import { PolynomiumVector } from './poly-vec';

export function mergeArrays(arrays: Uint8Array[]): Uint8Array {
    let totalLength = 0;

    for (let i = 0; i < arrays.length; i++) {
        totalLength += arrays[i].length;
    }

    const merged = new Uint8Array(totalLength);

    let cp = 0;
    for (let i = 0; i < arrays.length; i++) {
        merged.set(arrays[i], cp);
        cp += arrays[i].length;
    }

    return merged;
}

export function clearBuffer(buf: Uint8Array) {
    for (let i = 0; i < buf.length; i++) {
        buf[i] = 0x00;
    }
}

export function getSHAKE256Digest(sz: number, ...arr: Uint8Array[]): Uint8Array {
    const data = mergeArrays(arr);
    const s = new SHAKE(256);
    s.update(Buffer.from(data));
    const out = Buffer.alloc(sz);
    s.digest({ buffer: out, format: "binary" });
    return new Uint8Array(out);
}

export function crh(p: Uint8Array): Uint8Array {
    return getSHAKE256Digest(CRHBYTES, p);
}

export function getPolyEtaPackedBytes(eta: number): number {
    if (eta === 2) {
        return 96;
    } else if (eta === 4) {
        return 128;
    } else {
        throw new Error("Invalid etA: " + eta);
    }
}

export function getPolyW1PackedBytes(gamma2: number): number {
    let b: number;

    if (gamma2 === Math.floor((Q - 1) / 88)) {
        b = 192;
    } else if (gamma2 === Math.floor((Q - 1) / 32)) {
        b = 128;
    } else {
        throw new Error("Error invalid gamma2: " + gamma2);
    }

    return b;
}

export function getPolyZPackedBytes(gamma1: number): number {
    if (gamma1 === (1 << 17)) {
        return 576;
    } else if (gamma1 === (1 << 19)) {
        return 640;
    } else {
        throw new Error("Invalid gamma1: " + gamma1);
    }
}

export function getSignatureByteLength(spec: DilithiumParameterSpec): number {
    return (
        SEEDBYTES +
        (spec.l * getPolyZPackedBytes(spec.gamma1)) +
        spec.omega +
        spec.k
    );
}

export function getPublicKeyByteLength(spec: DilithiumParameterSpec): number {
    return (
        SEEDBYTES +
        (spec.k * POLYT1_PACKEDBYTES)
    );
}

export function getPrivateKeyByteLength(spec: DilithiumParameterSpec): number {
    let pkbytes: number;

    switch (spec.eta) {
    case 2:
        pkbytes = 96;
        break;
    case 4:
        pkbytes = 128;
        break;
    default:
        throw new Error("Illegal eta: " + spec.eta);
    }

    return (
        (2 * SEEDBYTES) +
        CRHBYTES +
        (spec.l * pkbytes) +
        (spec.k * pkbytes) +
        (spec.k * POLYT0_PACKEDBYTES)
    );
}

export function packPubKey(rho: Uint8Array, t: PolynomiumVector): Uint8Array {
    const size = SEEDBYTES + (t.size() * POLYT1_PACKEDBYTES);

    const pk = new Uint8Array(size);

    for (let i = 0; i < SEEDBYTES; i++) {
        pk[i] = rho[i];
    }

    const tl = t.size();
    for (let i = 0; i < tl; i++) {
        t.polynomiums[i].t1pack(pk, SEEDBYTES + (i * POLYT1_PACKEDBYTES));
    }

    return pk;
}

export function packPrvKey(eta: number, rho: Uint8Array, tr: Uint8Array, K: Uint8Array, t0: PolynomiumVector, s1: PolynomiumVector, s2: PolynomiumVector): Uint8Array {
    let pkbytes: number;

    switch (eta) {
    case 2:
        pkbytes = 96;
        break;
    case 4:
        pkbytes = 128;
        break;
    default:
        throw new Error("Illegal eta: " + eta);
    }

    const keySize = (
        (2 * SEEDBYTES) +
        CRHBYTES +
        (s1.size() * pkbytes) +
        (s2.size() * pkbytes) +
        (s2.size() * POLYT0_PACKEDBYTES)
    );

    const buf = new Uint8Array(keySize);
    let off = 0;

    for (let i = 0; i < SEEDBYTES; i++) {
        buf[off + i] = rho[i];
    }
    off += SEEDBYTES;

    for (let i = 0; i < SEEDBYTES; i++) {
        buf[off + i] = K[i];
    }
    off += SEEDBYTES;

    for (let i = 0; i < CRHBYTES; i++) {
        buf[off + i] = tr[i];
    }
    off += CRHBYTES;

    for (let i = 0; i < s1.size(); i++) {
        s1.polynomiums[i].etapack(eta, buf, off);
        off += pkbytes;
    }

    for (let i = 0; i < s2.size(); i++) {
        s2.polynomiums[i].etapack(eta, buf, off);
        off += pkbytes;
    }

    for (let i = 0; i < t0.size(); i++) {
        t0.polynomiums[i].t0pack(buf, off);
        off += POLYT0_PACKEDBYTES;
    }

    return buf;
}

export function packSig(gamma1: number, omega: number, sig: Uint8Array, c: Uint8Array, z: PolynomiumVector, h: PolynomiumVector) {
    const pkBytes = getPolyZPackedBytes(gamma1);

    let off = 0;
    for (let i = 0; i < SEEDBYTES; i++) {
        sig[i] = c[i];
    }
    off += SEEDBYTES;

    const zlength = z.size();
    for (let i = 0; i < zlength; i++) {
        z.polynomiums[i].zpack(gamma1, sig, off);
        off += pkBytes;
    }

    /* Encode h */
    const hlength = h.size();
    for (let i = 0; i < omega + hlength; i++) {
        sig[off + i] = 0;
    }

    let k = 0;
    for (let i = 0; i < hlength; i++) {
        for (let j = 0; j < N; j++) {
            if (h.polynomiums[i].coef[j] !== 0) {
                sig[off + k++] = j & 0xFF;
            }
        }

        sig[off + omega + i] = k & 0xFF;
    }
}

export function packw1(gamma2: number, w: PolynomiumVector, sig: Uint8Array) {
    const pkBytes = getPolyW1PackedBytes(gamma2);
    let off = 0;
    const length = w.size();
    for (let i = 0; i < length; i++) {
        w.polynomiums[i].w1pack(gamma2, sig, off);
        off += pkBytes;
    }
}
