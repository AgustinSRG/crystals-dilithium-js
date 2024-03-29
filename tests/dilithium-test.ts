// Dilithium algorithm testing

"use strict";

import { expect } from 'chai';

import { DilithiumKeyPair, DilithiumLevel, DilithiumLevelNumber, DilithiumPrivateKey, DilithiumPublicKey, DilithiumSignature } from "../src/index";

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

        let pkHex: string;
        let pubHex: string;
        let sigHex: string;

        it('Should be able to export key and signature to bytes', () => {
            pkHex = Buffer.from(keyPair.getPrivateKey().getBytes()).toString("hex");
            pubHex = Buffer.from(keyPair.getPublicKey().getBytes()).toString("hex");
            sigHex = Buffer.from(signature.getBytes()).toString("hex");
        });

        let pk: DilithiumPrivateKey;
        let pub: DilithiumPublicKey;
        let sig: DilithiumSignature;

        it('Should be able to import key and signature from bytes', () => {
            pk = DilithiumPrivateKey.fromBytes(Buffer.from(pkHex, "hex"), levelSpec);

            expect(pk.K).to.be.eql(keyPair.getPrivateKey().K);
            expect(pk.rho).to.be.eql(keyPair.getPrivateKey().rho);
            expect(pk.tr).to.be.eql(keyPair.getPrivateKey().tr);

            expect(pk.s1.toString()).to.be.eql(keyPair.getPrivateKey().s1.toString());
            expect(pk.s2.toString()).to.be.eql(keyPair.getPrivateKey().s2.toString());
            expect(pk.t0.toString()).to.be.eql(keyPair.getPrivateKey().t0.toString());

            expect(pk.s1Hat.toString()).to.be.eql(keyPair.getPrivateKey().s1Hat.toString());
            expect(pk.s2Hat.toString()).to.be.eql(keyPair.getPrivateKey().s2Hat.toString());
            expect(pk.t0Hat.toString()).to.be.eql(keyPair.getPrivateKey().t0Hat.toString());

            expect(pk.A.toString()).to.be.eql(keyPair.getPrivateKey().A.toString());

            pub = DilithiumPublicKey.fromBytes(Buffer.from(pubHex, "hex"), levelSpec);

            expect(pub.rho).to.be.eql(keyPair.getPublicKey().rho);

            expect(pub.t1.toString()).to.be.eql(keyPair.getPublicKey().t1.toString());

            expect(pub.A.toString()).to.be.eql(keyPair.getPublicKey().A.toString());

            sig = DilithiumSignature.fromBytes(Buffer.from(sigHex, "hex"), levelSpec);

            expect(pub.getBytes()).to.be.eql(pk.derivePublicKey().getBytes());
        });

        it('Should be able to verify the signature', () => {
            expect(pub.verifySignature(message, sig)).to.be.true;
        });
    });
}
