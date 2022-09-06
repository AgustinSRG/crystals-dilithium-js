// Utils

"use strict"

import { SHAKE } from 'sha3';
import { CRHBYTES, POLYT0_PACKEDBYTES, POLYT1_PACKEDBYTES, SEEDBYTES } from './constants';
import { DilithiumParameterSpec } from './param';

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

export function getPolyZPackedBytes(gamma1: number) {
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
