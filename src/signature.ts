// Signature algorithm

"use strict";

import { SHAKE } from "sha3";
import { CRHBYTES, N, SEEDBYTES } from "./constants";
import { makeHints, useHints } from "./hints";
import { DilithiumPrivateKey, DilithiumPublicKey } from "./key";
import { DilithiumLevel, DilithiumParameterSpec } from "./param";
import { Polynomium } from "./poly";
import { PolynomiumVector } from "./poly-vec";
import { crh, getPolyW1PackedBytes, getPolyZPackedBytes, getSHAKE256Digest, getSignatureByteLength, mergeArrays, packSig, packw1 } from "./util";

/**
 * Signature
 */
export class DilithiumSignature {
    public spec: DilithiumParameterSpec;

    public bytes: Uint8Array;

    /**
     * Generates a signature
     * @param message The message to sign
     * @param privateKey The private key to use for the signature
     * @returns The signature
     */
    public static generate(message: Uint8Array, privateKey: DilithiumPrivateKey): DilithiumSignature {
        const spec = privateKey.spec;
        const signatureLength = getSignatureByteLength(spec);

        const sig = new Uint8Array(signatureLength);

        const A = privateKey.A;

        let conc = mergeArrays([privateKey.tr, message]);
        const mu = crh(conc);
        conc = mergeArrays([privateKey.K, mu]);
        const rhoprime = crh(conc);

        const s1 = privateKey.s1Hat;
        const s2 = privateKey.s2Hat;
        const t0 = privateKey.t0Hat;

        let kappa = 0;
        let finish = false;

        while (!finish) {
            const y = PolynomiumVector.randomVecGamma1(rhoprime, spec.l, spec.gamma1, kappa++);
            let z = y.ntt();
            const w = z.mulMatrixPointwiseMontgomery(A);
            w.reduce();
            w.invnttTomont();
            w.caddq();
            const res = w.decompose(spec.gamma2);
            packw1(spec.gamma2, res[1], sig);

            const s = new SHAKE(256);
            s.update(Buffer.from(mu));
            s.update(Buffer.from(sig.slice(0, res[1].size() * getPolyW1PackedBytes(spec.gamma2))));

            const bb = Buffer.alloc(SEEDBYTES);
            s.digest({ buffer: bb, format: "binary" });
            sig.set(new Uint8Array(bb), 0);

            let cp = Polynomium.generateChallenge(spec.tau, sig);
            cp = cp.ntt();
            z = s1.pointwiseMontgomery(cp);
            z.invnttTomont();
            z = z.add(y);
            z.reduce();
            if (z.chknorm(spec.gamma1 - spec.beta)) {
                continue;
            }
            let h = s2.pointwiseMontgomery(cp);
            h.invnttTomont();
            let w0 = res[0].sub(h);
            w0.reduce();
            if (w0.chknorm(spec.gamma2 - spec.beta)) {
                continue;
            }

            h = t0.pointwiseMontgomery(cp);
            h.invnttTomont();
            h.reduce();
            if (h.chknorm(spec.gamma2)) {
                continue;
            }

            w0 = w0.add(h);
            w0.caddq();

            const hints = makeHints(spec.gamma2, w0, res[1]);
            if (hints.cnt > spec.omega) {
                continue;
            }

            packSig(spec.gamma1, spec.omega, sig, sig, z, hints.v);

            finish = true;
        }

        return new DilithiumSignature(spec, sig);
    }

    /**
     * Parses signature from byte array
     * @param bytes The byte array
     * @param level The level specification 
     * @returns The signature
     */
    public static fromBytes(bytes: Uint8Array, level: DilithiumLevel): DilithiumSignature {
        if (level.spec.signatureLength !== bytes.length) {
            throw new Error(`Invalid signature size. Expected ${level.spec.publicKeyLength} bytes, but found ${bytes.length} bytes`);
        }
        return new DilithiumSignature(level.spec.rawParams, bytes);
    }

    /**
     * Parses signature from hex string
     * @param hex The string
     * @param level The level specification 
     * @returns The signature
     */
    public static fromHex(hex: string, level: DilithiumLevel): DilithiumSignature {
        return DilithiumSignature.fromBytes(new Uint8Array(Buffer.from(hex, "hex")), level);
    }

    /**
     * Parses signature from base 64 string
     * @param base64 The string
     * @param level The level specification 
     * @returns The signature
     */
    public static fromBase64(base64: string, level: DilithiumLevel): DilithiumSignature {
        return DilithiumSignature.fromBytes(new Uint8Array(Buffer.from(base64, "base64")), level);
    }

    constructor(spec: DilithiumParameterSpec, bytes: Uint8Array) {
        this.spec = spec;
        this.bytes = bytes;
    }

    /**
     * @returns The private key as a byte array 
     */
    public getBytes(): Uint8Array {
        return this.bytes;
    }

    /**
     * Verifies the signature against a message + public key
     * @param message The message
     * @param publicKey The public key
     * @returns True only if the signature is valid
     */
    public verify(message: Uint8Array, publicKey: DilithiumPublicKey): boolean {
        const spec = publicKey.spec;
        const signatureLength = getSignatureByteLength(spec);

        const sig = this.bytes;

        if (sig.length !== signatureLength) {
            return false; // Bad signature
        }

        let t1 = publicKey.t1;

        let off = 0;
        const c = sig.slice(0, SEEDBYTES);

        off += SEEDBYTES;

        let z = new PolynomiumVector(spec.l);		
        for (let i = 0; i < spec.l; i++) {
            z.polynomiums[i] = Polynomium.zunpack(spec.gamma1, sig, off);
            off += getPolyZPackedBytes(spec.gamma1);
        }

        const h = new PolynomiumVector(spec.k);
        let k = 0;
        for (let i = 0; i < h.size(); i++) {
            h.polynomiums[i] = new Polynomium(N);

            if ((sig[off + spec.omega + i] & 0xFF) < k || (sig[off + spec.omega + i] & 0xFF) > spec.omega) {
                return false;
            }

            for (let j = k; j < (sig[off + spec.omega + i] & 0xFF); j++) {
                /* Coefficients are ordered for strong unforgeability */
                if (j > k && (sig[off + j] & 0xFF) <= (sig[off + j - 1] & 0xFF)) {
                    return false;
                }
					
                h.polynomiums[i].coef[sig[off + j] & 0xFF] = 1;
            }

            k = (sig[off + spec.omega + i] & 0xFF);
        }

		
        for (let j = k; j < spec.omega; j++) {
            if (sig[off + j] !== 0) {
                return false;
            }
        }
		
        if (z.chknorm(spec.gamma1 - spec.beta)) {
            return false;
        }

        let mu = crh(publicKey.bytes);
        mu = getSHAKE256Digest(CRHBYTES,  mu, message);

        let cp = Polynomium.generateChallenge(spec.tau, c);

        const A = publicKey.A;
		
        z = z.ntt();
        let w = z.mulMatrixPointwiseMontgomery(A);

        cp = cp.ntt();
        t1 = t1.shift();
        t1 = t1.ntt();

        t1 = t1.pointwiseMontgomery(cp);
        w = w.sub(t1);
        w.reduce();
        w.invnttTomont();		
        w.caddq();
		
        w = useHints(spec.gamma2, w, h);

        const buf = new Uint8Array(getPolyW1PackedBytes(spec.gamma2) * w.size());
        packw1(spec.gamma2, w, buf);
		
        const c2 = getSHAKE256Digest(SEEDBYTES,  mu, buf);
        for (let i = 0; i < SEEDBYTES; i++) {
            if (c[i] !== c2[i]) {
                return false;
            }
        }
        return true;
    }
}
