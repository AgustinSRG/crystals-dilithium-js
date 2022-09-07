// Dilithium key-pair

"use strict"

import { CRHBYTES, POLYT0_PACKEDBYTES, POLYT1_PACKEDBYTES, SEEDBYTES } from "./constants";
import { DilithiumLevel, DilithiumParameterSpec } from "./param";
import randomBytes from "randombytes";
import { Polynomium } from "./poly";
import { PolynomiumVector } from "./poly-vec";
import { crh, getPolyEtaPackedBytes, getSHAKE256Digest, packPrvKey, packPubKey } from "./util";

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

    /**
     * Parses private key from hex string
     * @param hex The string
     * @param level The level specification 
     * @returns The private key
     */
    public static fromHex(hex: string, level: DilithiumLevel): DilithiumPrivateKey {
        return DilithiumPrivateKey.fromBytes(new Uint8Array(Buffer.from(hex, "hex")), level);
    }

    /**
     * Parses private key from base 64 string
     * @param base64 The string
     * @param level The level specification 
     * @returns The private key
     */
    public static fromBase64(base64: string, level: DilithiumLevel): DilithiumPrivateKey {
        return DilithiumPrivateKey.fromBytes(new Uint8Array(Buffer.from(base64, "base64")), level);
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

    /**
     * @returns The private key as a byte array 
     */
    public getBytes(): Uint8Array {
        return this.bytes;
    }

    /**
     * @returns The private key as a hex string
     */
    public toHex(): string {
        return Buffer.from(this.bytes).toString("hex");
    }

    /**
     * @returns The private key as a base 64 string
     */
    public toBase64(): string {
        return Buffer.from(this.bytes).toString("base64");
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

    /**
     * Parses public key from hex string
     * @param hex The string
     * @param level The level specification 
     * @returns The public key
     */
    public static fromHex(hex: string, level: DilithiumLevel): DilithiumPublicKey {
        return DilithiumPublicKey.fromBytes(new Uint8Array(Buffer.from(hex, "hex")), level);
    }

    /**
     * Parses public key from base 64 string
     * @param base64 The string
     * @param level The level specification 
     * @returns The public key
     */
    public static fromBase64(base64: string, level: DilithiumLevel): DilithiumPublicKey {
        return DilithiumPublicKey.fromBytes(new Uint8Array(Buffer.from(base64, "base64")), level);
    }

    constructor(spec: DilithiumParameterSpec, bytes: Uint8Array, rho: Uint8Array, t1: PolynomiumVector, A: PolynomiumVector[]) {
        this.spec = spec;
        this.bytes = bytes;

        this.rho = rho;
        this.t1 = t1;
        this.A = A;
    }

    /**
     * @returns The public key as a hex string
     */
    public toHex(): string {
        return Buffer.from(this.bytes).toString("hex");
    }

    /**
     * @returns The public key as a base 64 string
     */
    public toBase64(): string {
        return Buffer.from(this.bytes).toString("base64");
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

    /**
     * Generates a random keypair
     * @param level The algorithm level
     * @param seed The seed for the generation of the key pair (if not prodiced, a random seed is generated)
     */
    public static generate(level: DilithiumLevel, seed?: Uint8Array) {
        const spec = level.spec.rawParams;

        let zeta: Uint8Array;
        if (seed) {
            zeta = seed;
        } else {
            zeta = new Uint8Array(randomBytes(32));
        }

        const o = getSHAKE256Digest(3 * 32, zeta);
        const rho = o.slice(0, 32);
        const sigma = o.slice(32, 64);
        const K = o.slice(64, 96);

        const s1 = PolynomiumVector.randomVec(sigma, spec.eta, spec.l, 0);
        const s2 = PolynomiumVector.randomVec(sigma, spec.eta, spec.k, spec.l);

        const A = PolynomiumVector.expandA(rho, spec.k, spec.l);

        const s1Hat = s1.ntt();
        let t1 = s1Hat.mulMatrixPointwiseMontgomery(A);
        t1.reduce();
        t1.invnttTomont();

        t1 = t1.add(s2);
        t1.caddq();

        const res = t1.powerRound();
        const pubbytes = packPubKey(rho, res[1]);

        const tr = crh(pubbytes);

        const prvbytes = packPrvKey(spec.eta, rho, tr, K, res[0], s1, s2);

        const s2Hat = s2.ntt();
        const t0Hat = res[0].ntt();

        const privateKey = new DilithiumPrivateKey(spec, prvbytes, {
            rho,
            K,
            tr,
            s1,
            s2,
            t0: res[0],
            A,
            s1Hat,
            s2Hat,
            t0Hat,
        });

        const publicKey = new DilithiumPublicKey(spec, pubbytes, rho, res[1], A);


        return new DilithiumKeyPair(privateKey, publicKey);
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
