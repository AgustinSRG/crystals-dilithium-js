// Parameter specs

"use strict";

import { Q } from "./constants";

/**
 * Dilithium algorithm params
 */
export interface DilithiumParameterSpec {
    name: string;
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

export type DilithiumLevel = 2 | 3 | 5;

/**
 * Dilithium level specification
 */
export interface DilithiumLevelSpec {
    /**
     * Level
     */
    level: DilithiumLevel,

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
    name: "Dilithium Level 2",
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
    name: "Dilithium Level 3",
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
    name: "Dilithium Level 5",
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

