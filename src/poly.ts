// Polynomium

"use strict"

import { SHAKE } from 'sha3';
import Long from "long";
import { D, N, POLY_UNIFORM_GAMMA1_NBLOCKS, POLY_UNIFORM_NBLOCKS, Q, QINV, SEEDBYTES, SHAKE256_RATE, STREAM128_BLOCKBYTES, STREAM256_BLOCKBYTES, zetas } from './constants';

export class Polynomium {
    public static genRandom(rho: Uint8Array, eta: number, nonce: number) {
        let POLY_UNIFORM_ETA_NBLOCKS: number;
        switch (eta) {
        case 2:
            POLY_UNIFORM_ETA_NBLOCKS = Math.floor((136 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES);
            break;
        case 4:
            POLY_UNIFORM_ETA_NBLOCKS = Math.floor((227 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES);
            break;
        default:
            throw new Error("Illegal eta: " + eta);
        }

        let ctr: number;
        const s = new SHAKE(128);
        s.update(Buffer.from(rho));

        const non = new Uint8Array(2);
        non[0] = nonce & 0xFF;
        non[1] = ((nonce >> 8) & 0xFF);
        s.update(Buffer.from(non));

        const bb = Buffer.alloc(POLY_UNIFORM_ETA_NBLOCKS * STREAM128_BLOCKBYTES);
        s.digest({ buffer: bb, format: "binary" });

        const pre = new Polynomium(N);
        ctr = Polynomium.rej_eta(eta, pre.coef, 0, N, bb, bb.length);

        const bb2 = Buffer.alloc(STREAM128_BLOCKBYTES);

        while (ctr < N) {
            s.digest({ buffer: bb2, format: "binary" });
            ctr += Polynomium.rej_eta(eta, pre.coef, ctr, N - ctr, bb2, bb2.length);
        }

        return pre;
    }

    public static genUniformRandom(rho: Uint8Array, nonce: number) {
        let buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES
        const bufShake = Buffer.alloc(buflen);

        const s = new SHAKE(128);
        s.update(Buffer.from(rho));

        const non = new Uint8Array(2);
        non[0] = nonce & 0xFF;
        non[1] = ((nonce >> 8) & 0xFF);
        s.update(Buffer.from(non));

        s.digest({ buffer: bufShake, format: "binary" });

        const buf = Buffer.concat([bufShake, Buffer.alloc(2)]);

        const pre = new Polynomium(N);
        let ctr = Polynomium.rej_uniform(pre.coef, 0, N, buf, buflen);

        while (ctr < N) {
            const off = buflen % 3;
            for (let i = 0; i < off; i++) {
                buf[i] = buf[buflen - off + i];
            }

            const bb2 = Buffer.alloc(STREAM128_BLOCKBYTES);
            s.digest({ buffer: bb2, format: "binary" });

            for (let i = 0; i < bb2.length; i++) {
                buf[off + i] = bb2[i];
            }

            buflen = STREAM128_BLOCKBYTES + off;
            ctr += Polynomium.rej_uniform(pre.coef, ctr, N - ctr, buf, buflen);
        }

        return pre;
    }

    public static genRandomGamma1(seed: Uint8Array, nonce: number, n: number, gamma1: number): Polynomium {
        const pre = new Polynomium(n);

        const buf = Buffer.alloc(POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES);
        const s = new SHAKE(256);
        s.update(Buffer.from(seed));

        const non = new Uint8Array(2);
        non[0] = nonce & 0xFF;
        non[1] = ((nonce >> 8) & 0xFF);
        s.update(Buffer.from(non));


        s.digest({ buffer: buf, format: "binary" });

        if (gamma1 === (1 << 17)) {
            for (let i = 0; i < N / 4; i++) {
                pre.coef[4 * i + 0] = (buf[9 * i + 0] & 0xFF);
                pre.coef[4 * i + 0] |= (buf[9 * i + 1] & 0xFF) << 8;
                pre.coef[4 * i + 0] |= (buf[9 * i + 2] & 0xFF) << 16;
                pre.coef[4 * i + 0] &= 0x3FFFF;

                pre.coef[4 * i + 1] = (buf[9 * i + 2] & 0xFF) >> 2;
                pre.coef[4 * i + 1] |= (buf[9 * i + 3] & 0xFF) << 6;
                pre.coef[4 * i + 1] |= (buf[9 * i + 4] & 0xFF) << 14;
                pre.coef[4 * i + 1] &= 0x3FFFF;

                pre.coef[4 * i + 2] = (buf[9 * i + 4] & 0xFF) >> 4;
                pre.coef[4 * i + 2] |= (buf[9 * i + 5] & 0xFF) << 4;
                pre.coef[4 * i + 2] |= (buf[9 * i + 6] & 0xFF) << 12;
                pre.coef[4 * i + 2] &= 0x3FFFF;

                pre.coef[4 * i + 3] = (buf[9 * i + 6] & 0xFF) >> 6;
                pre.coef[4 * i + 3] |= (buf[9 * i + 7] & 0xFF) << 2;
                pre.coef[4 * i + 3] |= (buf[9 * i + 8] & 0xFF) << 10;
                pre.coef[4 * i + 3] &= 0x3FFFF;

                pre.coef[4 * i + 0] = gamma1 - pre.coef[4 * i + 0];
                pre.coef[4 * i + 1] = gamma1 - pre.coef[4 * i + 1];
                pre.coef[4 * i + 2] = gamma1 - pre.coef[4 * i + 2];
                pre.coef[4 * i + 3] = gamma1 - pre.coef[4 * i + 3];
            }

        } else if (gamma1 === (1 << 19)) {
            for (let i = 0; i < N / 2; i++) {
                pre.coef[2 * i + 0] = buf[5 * i + 0] & 0xFF;
                pre.coef[2 * i + 0] |= (buf[5 * i + 1] & 0xFF) << 8;
                pre.coef[2 * i + 0] |= (buf[5 * i + 2] & 0xFF) << 16;
                pre.coef[2 * i + 0] &= 0xFFFFF;

                pre.coef[2 * i + 1] = (buf[5 * i + 2] & 0xFF) >> 4;
                pre.coef[2 * i + 1] |= (buf[5 * i + 3] & 0xFF) << 4;
                pre.coef[2 * i + 1] |= (buf[5 * i + 4] & 0xFF) << 12;
                pre.coef[2 * i + 0] &= 0xFFFFF;

                pre.coef[2 * i + 0] = gamma1 - pre.coef[2 * i + 0];
                pre.coef[2 * i + 1] = gamma1 - pre.coef[2 * i + 1];
            }

        } else {
            throw new Error("Invalid gamma1: " + gamma1);
        }

        return pre;
    }

    public static generateChallenge(tau: number, seed: Uint8Array): Polynomium {
        const pre = new Polynomium(N);

        const s = new SHAKE(256);
        s.update(Buffer.from(seed.slice(0, SEEDBYTES)));

        const buf = Buffer.alloc(SHAKE256_RATE);
        s.digest({ buffer: buf, format: "binary" });

        let signs = BigInt(0);

        for (let i = 0; i < 8; i++) {
            signs |= BigInt(buf[i] & 0xFF) << BigInt(8 * i);
        }

        let pos = 8;

        let b: number;

        for (let i = N - tau; i < N; ++i) {
            if (pos >= SHAKE256_RATE) {
                s.digest({ buffer: buf, format: "binary" });
                pos = 0;
            }

            b = (buf[pos++] & 0xFF);

            while (b > i) {
                if (pos >= SHAKE256_RATE) {
                    s.digest({ buffer: buf, format: "binary" });
                    pos = 0;
                }
    
                b = (buf[pos++] & 0xFF);
            }

            pre.coef[i] = pre.coef[b];
            pre.coef[b] = (1 - 2 * Number(signs & BigInt(1)));

            signs = signs >> BigInt(1);
        }

        return pre;
    }

    public static etaunpack(eta: number, bytes: Uint8Array, off: number): Polynomium {
        const p = new Polynomium(N);
        if (eta === 2) {
            for (let i = 0; i < N / 8; i++) {
                p.coef[8 * i + 0] = ((bytes[off + 3 * i + 0] & 0xFF) >> 0) & 7;
                p.coef[8 * i + 1] = ((bytes[off + 3 * i + 0] & 0xFF) >> 3) & 7;
                p.coef[8 * i + 2] = (((bytes[off + 3 * i + 0] & 0xFF) >> 6) | ((bytes[off + 3 * i + 1] & 0xFF) << 2)) & 7;
                p.coef[8 * i + 3] = ((bytes[off + 3 * i + 1] & 0xFF) >> 1) & 7;
                p.coef[8 * i + 4] = ((bytes[off + 3 * i + 1] & 0xFF) >> 4) & 7;
                p.coef[8 * i + 5] = (((bytes[off + 3 * i + 1] & 0xFF) >> 7) | ((bytes[off + 3 * i + 2] & 0xFF) << 1)) & 7;
                p.coef[8 * i + 6] = ((bytes[off + 3 * i + 2] & 0xFF) >> 2) & 7;
                p.coef[8 * i + 7] = ((bytes[off + 3 * i + 2] & 0xFF) >> 5) & 7;

                p.coef[8 * i + 0] = eta - p.coef[8 * i + 0];
                p.coef[8 * i + 1] = eta - p.coef[8 * i + 1];
                p.coef[8 * i + 2] = eta - p.coef[8 * i + 2];
                p.coef[8 * i + 3] = eta - p.coef[8 * i + 3];
                p.coef[8 * i + 4] = eta - p.coef[8 * i + 4];
                p.coef[8 * i + 5] = eta - p.coef[8 * i + 5];
                p.coef[8 * i + 6] = eta - p.coef[8 * i + 6];
                p.coef[8 * i + 7] = eta - p.coef[8 * i + 7];
            }

        } else if (eta === 4) {
            for (let i = 0; i < N / 2; i++) {
                p.coef[2 * i + 0] = (bytes[off + i] & 0xFF) & 0x0F;
                p.coef[2 * i + 1] = (bytes[off + i] & 0xFF) >> 4;
                p.coef[2 * i + 0] = eta - p.coef[2 * i + 0];
                p.coef[2 * i + 1] = eta - p.coef[2 * i + 1];
            }
        } else {
            throw new Error("Unknown eta: " + eta);
        }
        return p;
    }

    public static t0unpack(bytes: Uint8Array, off: number): Polynomium {
        const p = new Polynomium(N);
        for (let i = 0; i < N / 8; i++) {
            p.coef[8 * i + 0] = (bytes[off + 13 * i + 0] & 0xFF);
            p.coef[8 * i + 0] |= (bytes[off + 13 * i + 1] & 0xFF) << 8;
            p.coef[8 * i + 0] &= 0x1FFF;

            p.coef[8 * i + 1] = (bytes[off + 13 * i + 1] & 0xFF) >> 5;
            p.coef[8 * i + 1] |= (bytes[off + 13 * i + 2] & 0xFF) << 3;
            p.coef[8 * i + 1] |= (bytes[off + 13 * i + 3] & 0xFF) << 11;
            p.coef[8 * i + 1] &= 0x1FFF;

            p.coef[8 * i + 2] = (bytes[off + 13 * i + 3] & 0xFF) >> 2;
            p.coef[8 * i + 2] |= (bytes[off + 13 * i + 4] & 0xFF) << 6;
            p.coef[8 * i + 2] &= 0x1FFF;

            p.coef[8 * i + 3] = (bytes[off + 13 * i + 4] & 0xFF) >> 7;
            p.coef[8 * i + 3] |= (bytes[off + 13 * i + 5] & 0xFF) << 1;
            p.coef[8 * i + 3] |= (bytes[off + 13 * i + 6] & 0xFF) << 9;
            p.coef[8 * i + 3] &= 0x1FFF;

            p.coef[8 * i + 4] = (bytes[off + 13 * i + 6] & 0xFF) >> 4;
            p.coef[8 * i + 4] |= (bytes[off + 13 * i + 7] & 0xFF) << 4;
            p.coef[8 * i + 4] |= (bytes[off + 13 * i + 8] & 0xFF) << 12;
            p.coef[8 * i + 4] &= 0x1FFF;

            p.coef[8 * i + 5] = (bytes[off + 13 * i + 8] & 0xFF) >> 1;
            p.coef[8 * i + 5] |= (bytes[off + 13 * i + 9] & 0xFF) << 7;
            p.coef[8 * i + 5] &= 0x1FFF;

            p.coef[8 * i + 6] = (bytes[off + 13 * i + 9] & 0xFF) >> 6;
            p.coef[8 * i + 6] |= (bytes[off + 13 * i + 10] & 0xFF) << 2;
            p.coef[8 * i + 6] |= (bytes[off + 13 * i + 11] & 0xFF) << 10;
            p.coef[8 * i + 6] &= 0x1FFF;

            p.coef[8 * i + 7] = (bytes[off + 13 * i + 11] & 0xFF) >> 3;
            p.coef[8 * i + 7] |= (bytes[off + 13 * i + 12] & 0xFF) << 5;
            p.coef[8 * i + 7] &= 0x1FFF;

            p.coef[8 * i + 0] = (1 << (D - 1)) - p.coef[8 * i + 0];
            p.coef[8 * i + 1] = (1 << (D - 1)) - p.coef[8 * i + 1];
            p.coef[8 * i + 2] = (1 << (D - 1)) - p.coef[8 * i + 2];
            p.coef[8 * i + 3] = (1 << (D - 1)) - p.coef[8 * i + 3];
            p.coef[8 * i + 4] = (1 << (D - 1)) - p.coef[8 * i + 4];
            p.coef[8 * i + 5] = (1 << (D - 1)) - p.coef[8 * i + 5];
            p.coef[8 * i + 6] = (1 << (D - 1)) - p.coef[8 * i + 6];
            p.coef[8 * i + 7] = (1 << (D - 1)) - p.coef[8 * i + 7];
        }
        return p;
    }

    public static t1unpack(bytes: Uint8Array, off: number): Polynomium {
        const p = new Polynomium(N);
        for (let i = 0; i < N / 4; i++) {
            p.coef[4 * i + 0] = (((bytes[off + 5 * i + 0] & 0xFF) >> 0) | ((bytes[off + 5 * i + 1] & 0xFF) << 8)) & 0x3FF;
            p.coef[4 * i + 1] = (((bytes[off + 5 * i + 1] & 0xFF) >> 2) | ((bytes[off + 5 * i + 2] & 0xFF) << 6)) & 0x3FF;
            p.coef[4 * i + 2] = (((bytes[off + 5 * i + 2] & 0xFF) >> 4) | ((bytes[off + 5 * i + 3] & 0xFF) << 4)) & 0x3FF;
            p.coef[4 * i + 3] = (((bytes[off + 5 * i + 3] & 0xFF) >> 6) | ((bytes[off + 5 * i + 4] & 0xFF) << 2)) & 0x3FF;
        }
        return p;
    }

    public static zunpack(gamma1: number, sig: Uint8Array, off: number) {
        const pre = new Polynomium(N);
	
        if (gamma1 === (1 << 17)) {
            for (let i = 0; i < N / 4; i++) {
                pre.coef[4 * i + 0] = sig[off + 9 * i + 0] & 0xFF;
                pre.coef[4 * i + 0] |= (sig[off + 9 * i + 1] & 0xFF) << 8;
                pre.coef[4 * i + 0] |= (sig[off + 9 * i + 2] & 0xFF) << 16;
                pre.coef[4 * i + 0] &= 0x3FFFF;
	
                pre.coef[4 * i + 1] = (sig[off + 9 * i + 2] & 0xFF) >> 2;
                pre.coef[4 * i + 1] |= (sig[off + 9 * i + 3] & 0xFF) << 6;
                pre.coef[4 * i + 1] |= (sig[off + 9 * i + 4] & 0xFF) << 14;
                pre.coef[4 * i + 1] &= 0x3FFFF;
	
                pre.coef[4 * i + 2] = (sig[off + 9 * i + 4] & 0xFF) >> 4;
                pre.coef[4 * i + 2] |= (sig[off + 9 * i + 5] & 0xFF) << 4;
                pre.coef[4 * i + 2] |= (sig[off + 9 * i + 6] & 0xFF) << 12;
                pre.coef[4 * i + 2] &= 0x3FFFF;
	
                pre.coef[4 * i + 3] = (sig[off + 9 * i + 6] & 0xFF) >> 6;
                pre.coef[4 * i + 3] |= (sig[off + 9 * i + 7] & 0xFF) << 2;
                pre.coef[4 * i + 3] |= (sig[off + 9 * i + 8] & 0xFF) << 10;
                pre.coef[4 * i + 3] &= 0x3FFFF;
	
                pre.coef[4 * i + 0] = gamma1 - pre.coef[4 * i + 0];
                pre.coef[4 * i + 1] = gamma1 - pre.coef[4 * i + 1];
                pre.coef[4 * i + 2] = gamma1 - pre.coef[4 * i + 2];
                pre.coef[4 * i + 3] = gamma1 - pre.coef[4 * i + 3];
            }
        } else if (gamma1 === (1 << 19)) {
            for (let i = 0; i < N / 2; ++i) {
                pre.coef[2 * i + 0] = (sig[off + 5 * i + 0] & 0xFF);
                pre.coef[2 * i + 0] |= (sig[off + 5 * i + 1] & 0xFF) << 8;
                pre.coef[2 * i + 0] |= (sig[off + 5 * i + 2] & 0xFF) << 16;
                pre.coef[2 * i + 0] &= 0xFFFFF;
	
                pre.coef[2 * i + 1] = (sig[off + 5 * i + 2] & 0xFF) >> 4;
                pre.coef[2 * i + 1] |= (sig[off + 5 * i + 3] & 0xFF) << 4;
                pre.coef[2 * i + 1] |= (sig[off + 5 * i + 4] & 0xFF) << 12;
                pre.coef[2 * i + 0] &= 0xFFFFF;
	
                pre.coef[2 * i + 0] = gamma1 - pre.coef[2 * i + 0];
                pre.coef[2 * i + 1] = gamma1 - pre.coef[2 * i + 1];
            }
        }
	
        return pre;
    }

    private static rej_eta(eta: number, coef: number[], off: number, len: number, buf: Buffer, buflen: number): number {
        let ctr = 0;
        let pos = 0;

        let t0: number;
        let t1: number;

        if (eta === 2) {
            while (ctr < len && pos < buflen) {
                t0 = buf[pos] & 0x0F;
                t1 = (buf[pos++] >> 4) & 0x0F;
                if (t0 < 15) {
                    t0 = t0 - ((205 * t0) >>> 10) * 5;
                    coef[off + ctr++] = 2 - t0;
                }
                if (t1 < 15 && ctr < len) {
                    t1 = t1 - ((205 * t1) >>> 10) * 5;
                    coef[off + ctr++] = 2 - t1;
                }
            }
        } else {
            while (ctr < len && pos < buflen) {
                t0 = buf[pos] & 0x0F;
                t1 = (buf[pos++] >> 4) & 0x0F;
                if (t0 < 9) {
                    coef[off + ctr++] = 4 - t0;
                }
                if (t1 < 9 && ctr < len) {
                    coef[off + ctr++] = 4 - t1;
                }
            }
        }

        return ctr;
    }

    private static rej_uniform(coef: number[], off: number, len: number, buf: Buffer, buflen: number): number {
        let ctr = 0;
        let pos = 0;

        while (ctr < len && pos + 3 <= buflen) {
            let t = (buf[pos++] & 0xFF);
            t |= (buf[pos++] & 0xFF) << 8;
            t |= (buf[pos++] & 0xFF) << 16;
            t &= 0x7FFFFF;

            if (t < Q) {
                coef[off + ctr++] = t;
            }
        }

        return ctr;
    }

    private static montgomery_reduce(a: Long): number {
        let t: number;
        t = a.mul(QINV).toInt();      
        t = a.sub((Long.fromNumber(t)).mul(Q)).shiftRight(32).and(0xFFFFFFFF).toInt();
        return t;
    }

    public coef: number[];

    constructor(length: number) {
        const coef: number[] = [];
        for (let i = 0; i < length; i++) {
            coef.push(0);
        }
        this.coef = coef;
    }

    public add(other: Polynomium): Polynomium {
        const res = new Polynomium(this.coef.length)
        for (let i = 0; i < this.coef.length; i++) {
            res.coef[i] = (this.coef[i] + other.coef[i]) % Q;
        }
        return res;
    }

    public sub(other: Polynomium): Polynomium {
        const res = new Polynomium(this.coef.length)
        for (let i = 0; i < this.coef.length; i++) {
            res.coef[i] = (this.coef[i] - other.coef[i]) % Q;
        }
        return res;
    }

    public toString(): string {
        return "[" + this.coef.join(", ") + "]";
    }

    public ntt(): Polynomium {
        const ret = new Polynomium(this.coef.length);
        for (let i = 0; i < this.coef.length; i++) {
            ret.coef[i] = this.coef[i];
        }

        let k = 0;
        let j: number;

        for (let len = 128; len > 0; len = (len >> 1)) {
            for (let start = 0; start < N; start = j + len) {
                const zeta = zetas[++k];
                for (j = start; j < start + len; ++j) {
                    const t = Polynomium.montgomery_reduce((Long.fromNumber(zeta)).mul(ret.coef[j + len]));
                    ret.coef[j + len] = (ret.coef[j] - t) | 0;
                    ret.coef[j] = (ret.coef[j] + t) | 0;
                }
            }
        }

        return ret;
    }

    public pointwiseMontgomery(other: Polynomium): Polynomium {
        const c = new Polynomium(this.coef.length);
        for (let i = 0; i < this.coef.length; i++) {
            c.coef[i] = Polynomium.montgomery_reduce((Long.fromNumber(this.coef[i])).mul(other.coef[i]));
        }
        return c;
    }

    public reduce() {
        for (let i = 0; i < this.coef.length; i++) {
            this.coef[i] = Polynomium.reduce32(this.coef[i]);
        }
    }

    private static reduce32(a: number): number {
        let t = (a + (1 << 22)) >> 23;
        t = a - ((t * Q) | 0);
        return t | 0;
    }

    public invnttTomont() {
        const f = 41978;
        let k = 256;
        let j = 0;

        for (let len = 1; len < N; len = (len << 1)) {
            for (let start = 0; start < N; start = j + len) {
                const zeta = (-1) * zetas[--k];
                for (j = start; j < start + len; ++j) {
                    const t = this.coef[j];
                    this.coef[j] = (t + this.coef[j + len]) | 0;
                    this.coef[j + len] = (t - this.coef[j + len]) | 0;
                    this.coef[j + len] = Polynomium.montgomery_reduce((Long.fromNumber(zeta)).mul(this.coef[j + len]));
                }
            }
        }

        for (j = 0; j < N; ++j) {
            this.coef[j] = Polynomium.montgomery_reduce((Long.fromNumber(f)).mul(this.coef[j]));
        }
    }

    public caddq() {
        for (let i = 0; i < this.coef.length; i++) {
            this.coef[i] = (this.coef[i] + ((this.coef[i] >> 31) & Q)) | 0;
        }
    }


    public powerRound(): Polynomium[] {
        const pr: Polynomium[] = [
            new Polynomium(N),
            new Polynomium(N),
        ];

        for (let i = 0; i < this.coef.length; i++) {
            const a = this.coef[i];
            pr[1].coef[i] = ((a + (1 << (D - 1)) - 1) >> D) | 0;
            pr[0].coef[i] = (a - (pr[1].coef[i] << D)) | 0;
        }

        return pr;
    }

    public t1pack(r: Uint8Array, off: number) {
        for (let i = 0; i < N / 4; i++) {
            r[5 * i + 0 + off] = ((this.coef[4 * i + 0] >>> 0)) & 0xFF;
            r[5 * i + 1 + off] = ((this.coef[4 * i + 0] >>> 8) | (this.coef[4 * i + 1] << 2)) & 0xFF;
            r[5 * i + 2 + off] = ((this.coef[4 * i + 1] >>> 6) | (this.coef[4 * i + 2] << 4)) & 0xFF;
            r[5 * i + 3 + off] = ((this.coef[4 * i + 2] >>> 4) | (this.coef[4 * i + 3] << 6)) & 0xFF;
            r[5 * i + 4 + off] = ((this.coef[4 * i + 3] >>> 2)) & 0xFF;
        }
    }

    public etapack(eta: number, buf: Uint8Array, off: number) {
        const t = new Uint8Array(8);
        if (eta === 2) {
            for (let i = 0; i < N / 8; i++) {
                t[0] = (eta - this.coef[8 * i + 0]) & 0xFF;
                t[1] = (eta - this.coef[8 * i + 1]) & 0xFF;
                t[2] = (eta - this.coef[8 * i + 2]) & 0xFF;
                t[3] = (eta - this.coef[8 * i + 3]) & 0xFF;
                t[4] = (eta - this.coef[8 * i + 4]) & 0xFF;
                t[5] = (eta - this.coef[8 * i + 5]) & 0xFF;
                t[6] = (eta - this.coef[8 * i + 6]) & 0xFF;
                t[7] = (eta - this.coef[8 * i + 7]) & 0xFF;

                buf[off + 3 * i + 0] = ((t[0] >> 0) | (t[1] << 3) | (t[2] << 6)) & 0xFF;
                buf[off + 3 * i + 1] = ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) & 0xFF;
                buf[off + 3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF;
            }

        } else if (eta === 4) {
            for (let i = 0; i < N / 2; i++) {
                t[0] = (eta - this.coef[2 * i + 0]) & 0xFF;
                t[1] = (eta - this.coef[2 * i + 1]) & 0xFF;
                buf[off + i] = (t[0] | (t[1] << 4)) & 0xFF;
            }
        } else {
            throw new Error("Illegal eta: " + eta);
        }
    }

    public t0pack(buf: Uint8Array, off: number) {
        const t = new Uint8Array(8);

        for (let i = 0; i < N / 8; i++) {
            t[0] = (1 << (D - 1)) - this.coef[8 * i + 0];
            t[1] = (1 << (D - 1)) - this.coef[8 * i + 1];
            t[2] = (1 << (D - 1)) - this.coef[8 * i + 2];
            t[3] = (1 << (D - 1)) - this.coef[8 * i + 3];
            t[4] = (1 << (D - 1)) - this.coef[8 * i + 4];
            t[5] = (1 << (D - 1)) - this.coef[8 * i + 5];
            t[6] = (1 << (D - 1)) - this.coef[8 * i + 6];
            t[7] = (1 << (D - 1)) - this.coef[8 * i + 7];

            buf[off + 13 * i + 0] = (t[0]) & 0xFF;
            buf[off + 13 * i + 1] = (t[0] >> 8) & 0xFF;
            buf[off + 13 * i + 1] |= (t[1] << 5) & 0xFF;
            buf[off + 13 * i + 2] = (t[1] >> 3) & 0xFF;
            buf[off + 13 * i + 3] = (t[1] >> 11) & 0xFF;
            buf[off + 13 * i + 3] |= (t[2] << 2) & 0xFF;
            buf[off + 13 * i + 4] = (t[2] >> 6) & 0xFF;
            buf[off + 13 * i + 4] |= (t[3] << 7) & 0xFF;
            buf[off + 13 * i + 5] = (t[3] >> 1) & 0xFF;
            buf[off + 13 * i + 6] = (t[3] >> 9) & 0xFF;
            buf[off + 13 * i + 6] |= (t[4] << 4) & 0xFF;
            buf[off + 13 * i + 7] = (t[4] >> 4) & 0xFF;
            buf[off + 13 * i + 8] = (t[4] >> 12) & 0xFF;
            buf[off + 13 * i + 8] |= (t[5] << 1) & 0xFF;
            buf[off + 13 * i + 9] = (t[5] >> 7) & 0xFF;
            buf[off + 13 * i + 9] |= (t[6] << 6) & 0xFF;
            buf[off + 13 * i + 10] = (t[6] >> 2) & 0xFF;
            buf[off + 13 * i + 11] = (t[6] >> 10) & 0xFF;
            buf[off + 13 * i + 11] |= (t[7] << 3) & 0xFF;
            buf[off + 13 * i + 12] = (t[7] >> 5) & 0xFF;
        }
    }

    public decompose(gamma2: number): Polynomium[] {
        const pr: Polynomium[] = [
            new Polynomium(N),
            new Polynomium(N),
        ];

        for (let i = 0; i < this.coef.length; i++) {
            const a = this.coef[i];

            let a1 = (a + 127) >> 7;
            if (gamma2 === Math.floor((Q - 1) / 32)) {
                a1 = (a1 * 1025 + (1 << 21)) >> 22;
                a1 &= 15;

            } else if (gamma2 === Math.floor((Q - 1) / 88)) {
                a1 = (a1 * 11275 + (1 << 23)) >> 24;
                a1 ^= ((43 - a1) >> 31) & a1;
            } else {
                throw new Error("Invalid gamma2: " + gamma2);
            }
            pr[0].coef[i] = (a - a1 * 2 * gamma2) | 0;
            pr[0].coef[i] -= (((Q - 1) / 2 - pr[0].coef[i]) >> 31) & Q;
            pr[1].coef[i] = a1 | 0;
        }

        return pr;
    }

    public w1pack(gamma2: number, buf: Uint8Array, off: number) {
        if (gamma2 === (Q - 1) / 88) {
            for (let i = 0; i < N / 4; i++) {
                buf[off + 3 * i + 0] = this.coef[4 * i + 0] & 0xFF;
                buf[off + 3 * i + 0] |= (this.coef[4 * i + 1] << 6) & 0xFF;
                buf[off + 3 * i + 1] = (this.coef[4 * i + 1] >> 2) & 0xFF;
                buf[off + 3 * i + 1] |= (this.coef[4 * i + 2] << 4) & 0xFF;
                buf[off + 3 * i + 2] = (this.coef[4 * i + 2] >> 4) & 0xFF;
                buf[off + 3 * i + 2] |= (this.coef[4 * i + 3] << 2) & 0xFF;
            }

        } else if (gamma2 === (Q - 1) / 32) {
            for (let i = 0; i < N / 2; i++)
                buf[off + i] = (this.coef[2 * i + 0] | (this.coef[2 * i + 1] << 4)) & 0xFF;
        } else {
            throw new Error("Invalid gamma2: " + gamma2);
        }
    }

    public chknorm(B: number): boolean {
        let t: number;

        if (B > Math.floor((Q - 1) / 8)) {
            return true;
        }

        /*
         * It is ok to leak which coefficient violates the bound since the probability
         * for each coefficient is independent of secret data but we must not leak the
         * sign of the centralized representative.
         */
        for (let i = 0; i < N; i++) {
            /* Absolute value */
            t = this.coef[i] >> 31;
            t = this.coef[i] - (t & 2 * this.coef[i]);

            if (t >= B) {
                return true;
            }
        }

        return false;
    }

    public zpack(gamma1: number, sign: Uint8Array, off: number) {
        const t: bigint[] = [BigInt(0), BigInt(0), BigInt(0), BigInt(0)];

        if (gamma1 === (1 << 17)) {
            for (let i = 0; i < N / 4; i++) {
                t[0] = ((BigInt(gamma1) - BigInt(this.coef[4 * i + 0]))) & BigInt(0xFFFFFFFF);
                t[1] = ((BigInt(gamma1) - BigInt(this.coef[4 * i + 1]))) & BigInt(0xFFFFFFFF);
                t[2] = (BigInt(gamma1) - BigInt(this.coef[4 * i + 2])) & BigInt(0xFFFFFFFF);
                t[3] = (BigInt(gamma1) - BigInt(this.coef[4 * i + 3])) & BigInt(0xFFFFFFFF);

                sign[off + 9 * i + 0] = Number(t[0] & BigInt(0xFF));
                sign[off + 9 * i + 1] = Number((t[0] >> BigInt(8)) & BigInt(0xFF));
                sign[off + 9 * i + 2] = Number((t[0] >> BigInt(16)) & BigInt(0xFF));
                sign[off + 9 * i + 2] |= Number((t[1] << BigInt(2)) & BigInt(0xFF));
                sign[off + 9 * i + 3] = Number((t[1] >> BigInt(6)) & BigInt(0xFF));
                sign[off + 9 * i + 4] = Number((t[1] >> BigInt(14)) & BigInt(0xFF));
                sign[off + 9 * i + 4] |= Number((t[2] << BigInt(4)) & BigInt(0xFF));
                sign[off + 9 * i + 5] = Number((t[2] >> BigInt(4)) & BigInt(0xFF));
                sign[off + 9 * i + 6] = Number((t[2] >> BigInt(12)) & BigInt(0xFF));
                sign[off + 9 * i + 6] |= Number((t[3] << BigInt(6)) & BigInt(0xFF));
                sign[off + 9 * i + 7] = Number((t[3] >> BigInt(2)) & BigInt(0xFF));
                sign[off + 9 * i + 8] = Number((t[3] >> BigInt(10)) & BigInt(0xFF));
            }

        } else if (gamma1 === (1 << 19)) {
            for (let i = 0; i < N / 2; i++) {
                t[0] = BigInt(gamma1) - BigInt(this.coef[2 * i + 0]);
                t[1] = BigInt(gamma1) - BigInt(this.coef[2 * i + 1]);

                sign[off + 5 * i + 0] = Number((t[0]) & BigInt(0xFF));
                sign[off + 5 * i + 1] = Number((t[0] >> BigInt(8)) & BigInt(0xFF));
                sign[off + 5 * i + 2] = Number((t[0] >> BigInt(16)) & BigInt(0xFF));
                sign[off + 5 * i + 2] |= Number((t[1] << BigInt(4)) & BigInt(0xFF));
                sign[off + 5 * i + 3] = Number((t[1] >> BigInt(4)) & BigInt(0xFF));
                sign[off + 5 * i + 4] = Number((t[1] >> BigInt(12)) & BigInt(0xFF));
            }

        } else {
            throw new Error("Invalid gamma1: " + gamma1);
        }
    }

    public shiftl(): Polynomium {
        const pr = new Polynomium(N);
        for (let i = 0; i < N; i++) {
            pr.coef[i] = (this.coef[i] << D);
        }
        return pr;
    }
}
