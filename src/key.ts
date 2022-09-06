// Dilithium key-pair

"use strict"

import { CRHBYTES, POLYT0_PACKEDBYTES, POLYT1_PACKEDBYTES, SEEDBYTES } from "./constants";
import { DilithiumLevel, DilithiumParameterSpec } from "./param";
import { Polynomium } from "./poly";
import { PolynomiumVector } from "./poly-vec";
import { getPolyEtaPackedBytes, packPubKey } from "./util";

/**
 * Private key parameters
 */
export interface DilithiumPrivateKeyParams {
    rho: Uint8Array;
    tr: Uint8Array;
    K: Uint8Array;

    s1: PolynomiumVector;
    s2: PolynomiumVector;
    t0: PolynomiumVector;

    s1Hat: PolynomiumVector;
    s2Hat: PolynomiumVector;
    t0Hat: PolynomiumVector;

    A: PolynomiumVector[];
}

/**
 * Private key
 */
export class DilithiumPrivateKey implements DilithiumPrivateKeyParams {
    public rho: Uint8Array;
    public tr: Uint8Array;
    public K: Uint8Array;

    public s1: PolynomiumVector;
    public s2: PolynomiumVector;
    public t0: PolynomiumVector;

    public s1Hat: PolynomiumVector;
    public s2Hat: PolynomiumVector;
    public t0Hat: PolynomiumVector;

    public A: PolynomiumVector[];

    public spec: DilithiumParameterSpec;

    public bytes: Uint8Array;

    /**
     * Parses a private key from a byte array
     * @param bytes The byte array
     * @param level The level specification
     * @returns The private key
     */
    public static fromBytes(bytes: Uint8Array, level: DilithiumLevel): DilithiumPrivateKey {
        const parameterSpec = level.spec.rawParams;
        const POLYETA_PACKEDBYTES = getPolyEtaPackedBytes(parameterSpec.eta);

        let off = 0;
        const rho = new Uint8Array(SEEDBYTES);
        for (let i = 0; i < SEEDBYTES; i++) {
            rho[i] = bytes[i];
        }
        off += SEEDBYTES;

        const key = new Uint8Array(SEEDBYTES);
        for (let i = 0; i < SEEDBYTES; i++) {
            key[i] = bytes[off + i];
        }
        off += SEEDBYTES;

        const tr = new Uint8Array(CRHBYTES);
        for (let i = 0; i < CRHBYTES; i++) {
            tr[i] = bytes[off + i];
        }
        off += CRHBYTES;

        const s1 = new PolynomiumVector(parameterSpec.l);
        for (let i = 0; i < parameterSpec.l; i++) {
            s1.polynomiums[i] = Polynomium.etaunpack(parameterSpec.eta, bytes, off);
            off += POLYETA_PACKEDBYTES;
        }

        const s2 = new PolynomiumVector(parameterSpec.k);
        for (let i = 0; i < parameterSpec.k; i++) {
            s2.polynomiums[i] = Polynomium.etaunpack(parameterSpec.eta, bytes, off);
            off += POLYETA_PACKEDBYTES;

        }

        const t0 = new PolynomiumVector(parameterSpec.k);
        for (let i = 0; i < parameterSpec.k; i++) {
            t0.polynomiums[i] = Polynomium.t0unpack(bytes, off);
            off += POLYT0_PACKEDBYTES;
        }

        // Precompute A, s0, s1 & t0hat
        const A = PolynomiumVector.expandA(rho, parameterSpec.k, parameterSpec.l);
        const s1Hat = s1.ntt();
        const s2Hat = s2.ntt();
        const t0Hat = t0.ntt();

        return new DilithiumPrivateKey(parameterSpec, bytes, {
            rho,
            K: key,
            tr,
            s1,
            s2,
            t0,
            A,
            s1Hat,
            s2Hat,
            t0Hat,
        });
    }

    constructor(spec: DilithiumParameterSpec, bytes: Uint8Array, params: DilithiumPrivateKeyParams) {
        this.spec = spec;
        this.bytes = bytes;

        this.rho = params.rho;
        this.tr = params.tr;
        this.K = params.K;

        this.s1 = params.s1;
        this.s2 = params.s2;
        this.t0 = params.t0;

        this.s1Hat = params.s1Hat;
        this.s2Hat = params.s2Hat;
        this.t0Hat = params.t0Hat;

        this.A = params.A;
    }

    /**
     * Derives the public key from this private key
     * @returns The public key
     */
    public derivePublicKey(): DilithiumPublicKey {
        const s1hat = this.s1.ntt();
        let t1 = s1hat.mulMatrixPointwiseMontgomery(this.A);
        t1.reduce();
        t1.invnttTomont();

        t1 = t1.add(this.s2);
        t1.caddq();

        const res = t1.powerRound();
        const pubbytes = packPubKey(this.rho, res[1]);

        return new DilithiumPublicKey(this.spec, pubbytes, this.rho, res[1], this.A);
    }

    /**
     * Creates a key pair from this key
     * @returns The key pair
     */
    public toKeyPair(): DilithiumKeyPair {
        return new DilithiumKeyPair(this);
    }
}

/**
 * Public key
 */
export class DilithiumPublicKey {
    public rho: Uint8Array;
    public t1: PolynomiumVector;
    public A: PolynomiumVector[];

    public spec: DilithiumParameterSpec;

    public bytes: Uint8Array;

    /**
     * Parses a public key from a byte array
     * @param bytes The byte array
     * @param level The level specification
     * @returns The public key
     */
    public static fromBytes(bytes: Uint8Array, level: DilithiumLevel) {
        const parameterSpec = level.spec.rawParams;
        let off = 0;
        const rho = new Uint8Array(SEEDBYTES);
        for (let i = 0; i < SEEDBYTES; i++) {
            rho[i] = bytes[i];
        }
        off += SEEDBYTES;

        const p = new PolynomiumVector(parameterSpec.k);
        for (let i = 0; i < parameterSpec.k; i++) {
            p.polynomiums[i] = Polynomium.t1unpack(bytes, off);
            off += POLYT1_PACKEDBYTES;
        }

        // Precompute A
        const A = PolynomiumVector.expandA(rho, parameterSpec.k, parameterSpec.l);
        return new DilithiumPublicKey(parameterSpec, bytes, rho, p, A);
    }

    constructor(spec: DilithiumParameterSpec, bytes: Uint8Array, rho: Uint8Array, t1: PolynomiumVector, A: PolynomiumVector[]) {
        this.spec = spec;
        this.bytes = bytes;

        this.rho = rho;
        this.t1 = t1;
        this.A = A;
    }
}

/**
 * Key pair (private + public)
 */
export class DilithiumKeyPair {
    private pub: DilithiumPublicKey;
    private secret: DilithiumPrivateKey;

    /**
     * Creates a key pair from a private key
     * @param secret Private key
     * @returns The key pair
     */
    public static fromPrivateKey(secret: DilithiumPrivateKey): DilithiumKeyPair {
        return new DilithiumKeyPair(secret);
    }

    /**
     * Packs keys into a key pair
     * @param secret The private key
     * @param pub The public key
     * @returns 
     */
    public static fromKeys(secret: DilithiumPrivateKey, pub: DilithiumPublicKey): DilithiumKeyPair {
        return new DilithiumKeyPair(secret, pub);
    }

    constructor(secret: DilithiumPrivateKey, pub?: DilithiumPublicKey) {
        this.secret = secret;
        this.pub = pub || secret.derivePublicKey();
    }

    /**
     * @returns The private key
     */
    public getPrivateKey(): DilithiumPrivateKey {
        return this.secret;
    }

    /**
     * @returns The public key
     */
    public getPublicKey(): DilithiumPublicKey {
        return this.pub;
    }
}