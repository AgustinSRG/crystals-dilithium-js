// Dilithium algorithm testing

"use strict";

import { expect } from 'chai';

import { DilithiumKeyPair, DilithiumLevel, DilithiumLevelNumber, DilithiumSignature } from "../src/index";

const levels: DilithiumLevelNumber[] = [2, 3, 5]

for (let level of levels) {
    const levelSpec = DilithiumLevel.get(level);
    describe("Dilithium algorithm testing (Level " + level + ")", () => {

        let keyPair: DilithiumKeyPair;
        const seed = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

        it('Should generate a key pair without errors', () => {
            keyPair = DilithiumKeyPair.generate(levelSpec, seed);
        });

        it('Should derive the same public key as generated', () => {
            const pubKeyGenerated = keyPair.getPublicKey();
            const derivedPublicKey = keyPair.getPrivateKey().derivePublicKey();

            expect(pubKeyGenerated.getBytes()).to.be.eql(derivedPublicKey.getBytes());
        });

        const message = new Uint8Array(Buffer.from("Joy!", "utf8"));
        let signature: DilithiumSignature;

        it('Should be able to sign a message without errors', () => {
            signature = keyPair.sign(message);
        });

        it('Should be able to verify the signature', () => {
            expect(keyPair.verifySignature(message, signature)).to.be.true;
        });
    });
}
