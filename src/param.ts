// Parameter specs

"use strict";

import { Q } from "./constants";
import { getPrivateKeyByteLength, getPublicKeyByteLength, getSignatureByteLength } from "./util";

/**
 * Dilithium algorithm params
 */
export interface DilithiumParameterSpec {
    k: number;
    l: number;
    gamma1: number;
    gamma2: number;
    tau: number;
    d: number;
    chalentropy: number;
    eta: number;
    beta: number;
    omega: number;
}

/**
 * Dilithium security level (numeric)
 */
export type DilithiumLevelNumber = 2 | 3 | 5;

/**
 * Dilithium security level
 */
export class DilithiumLevel {
    /**
     * Get the definition for a security level of Dilithium
     * Level can be:
     *  - LEVEL 2
     *  - LEVEL 3
     *  - LEVEL 5
     * @param level The security level 
     * @returns The specification and parameters for that level
     */
    public static get(level: DilithiumLevelNumber): DilithiumLevel {
        let p: DilithiumParameterSpec;
        switch (level) {
        case 2:
            p = DILITHIUM_LEVEL2_P;
            break;
        case 3:
            p = DILITHIUM_LEVEL3_P;
            break;
        case 5:
            p = DILITHIUM_LEVEL5_P;
            break;
        default:
            throw new Error("Invalid security level: " + level);
        }

        return new DilithiumLevel({
            level: level,
            rawParams: p,
            publicKeyLength: getPublicKeyByteLength(p),
            privateKeyLength: getPrivateKeyByteLength(p),
            signatureLength: getSignatureByteLength(p),
        });
    }

    public spec: DilithiumLevelSpec;

    constructor(spec: DilithiumLevelSpec) {
        this.spec = spec;
    }
}

/**
 * Dilithium level specification
 */
export interface DilithiumLevelSpec {
    /**
     * Level
     */
    level: DilithiumLevelNumber,

    /**
     * Raw algorithm parameters
     */
    rawParams: DilithiumParameterSpec;

    /**
     * Public key length in bytes
     */
    publicKeyLength: number;

    /**
     * Private key length in bytes
     */
    privateKeyLength: number;

    /**
     * Signature length in bytes
     */
    signatureLength: number;
}

export const DILITHIUM_LEVEL2_P: DilithiumParameterSpec = {
    k: 4,
    l: 4,
    gamma1: 1 << 17,
    gamma2: Math.floor((Q - 1) / 88),
    tau: 39,
    d: 13,
    chalentropy: 192,
    eta: 2,
    beta: 78,
    omega: 80,
};

export const DILITHIUM_LEVEL3_P: DilithiumParameterSpec = {
    k: 6,
    l: 5,
    gamma1: 1 << 19,
    gamma2: Math.floor((Q - 1) / 32),
    tau: 49,
    d: 13,
    chalentropy: 225,
    eta: 4,
    beta: 196,
    omega: 55,
};

export const DILITHIUM_LEVEL5_P: DilithiumParameterSpec = {
    k: 8,
    l: 7,
    gamma1: 1 << 19,
    gamma2: Math.floor((Q - 1) / 32),
    tau: 60,
    d: 13,
    chalentropy: 257,
    eta: 2,
    beta: 120,
    omega: 75,
};

