// Dilithium signature algorithm

"use strict"

import { DilithiumLevel, DilithiumLevelSpec, DilithiumParameterSpec, DILITHIUM_LEVEL2_P, DILITHIUM_LEVEL3_P, DILITHIUM_LEVEL5_P } from "./param";
import { getPrivateKeyByteLength, getPublicKeyByteLength, getSignatureByteLength } from "./util";

/**
 * Dilithium signature algorithm
 */
export class Dilithium {

    /**
     * Get the definition for a level of Dilithium
     * Level can be:
     *  - LEVEL 2
     *  - LEVEL 3
     *  - LEVEL 5
     * @param level The level 
     * @returns The specification and parameters for that level
     */
    public static level(level: DilithiumLevel): DilithiumLevelSpec {
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
            throw new Error("Invalid level: " + level);
        }

        return {
            level: level,
            rawParams: p,
            publicKeyLength: getPublicKeyByteLength(p),
            privateKeyLength: getPrivateKeyByteLength(p),
            signatureLength: getSignatureByteLength(p),
        };
    }
}
