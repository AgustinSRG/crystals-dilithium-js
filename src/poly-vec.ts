// Vector of Polynomiums

"use strict";

import { N } from "./constants";
import { Polynomium } from "./poly";

export class PolynomiumVector {
    public polynomiums: Polynomium[];

    public static randomVec(rho: Uint8Array, eta: number, length: number, nonce: number): PolynomiumVector {
        const pv = new PolynomiumVector(length);
        for (let i = 0; i < length; i++) {
            pv.polynomiums[i] = Polynomium.genRandom(rho, eta, nonce++);
        }
        return pv;
    }

    public static randomVecGamma1(seed: Uint8Array, length: number, gamma1: number, nonce: number): PolynomiumVector {
        const pv = new PolynomiumVector(length);
        for (let i = 0; i < length; i++) {
            pv.polynomiums[i] = Polynomium.genRandomGamma1(seed, length * nonce + i, N, gamma1);
        }
        return pv;
    }

    public static expandA(rho: Uint8Array, k: number, l: number): PolynomiumVector[] {
        const A: PolynomiumVector[] = [];
        for (let i = 0; i < k; i++) {
            const pv = new PolynomiumVector(l);
            for (let j = 0; j < l; j++) {
                pv.polynomiums[j] = Polynomium.genUniformRandom(rho, (i << 8) + j);
            }
            A.push(pv);
        }

        return A;
    }

    constructor(size: number) {
        this.polynomiums = [];
        for (let i = 0; i < size; i++) {
            this.polynomiums.push(null);
        }
    }

    public ntt(): PolynomiumVector {
        const length = this.polynomiums.length;
        const pv = new PolynomiumVector(length);
        for (let i = 0; i < length; i++) {
            pv.polynomiums[i] = this.polynomiums[i].ntt();
        }
        return pv;
    }

    public reduce() {
        const length = this.polynomiums.length;
        for (let i = 0; i < length; i++) {
            this.polynomiums[i].reduce();
        }
    }

    public decompose(gamma2: number): PolynomiumVector[] {
        const length = this.polynomiums.length;
        const res = [
            new PolynomiumVector(length),
            new PolynomiumVector(length),
        ];

        for (let i = 0; i < length; i++) {
            const r = this.polynomiums[i].decompose(gamma2);
            res[0].polynomiums[i] = r[0];
            res[1].polynomiums[i] = r[1];
        }

        return res;
    }

    public invnttTomont() {
        const length = this.polynomiums.length;
        for (let i = 0; i < length; i++) {
            this.polynomiums[i].invnttTomont();
        }
    }

    public add(other: PolynomiumVector): PolynomiumVector {
        const length = this.polynomiums.length;
        const pv = new PolynomiumVector(length);
        for (let i = 0; i < length; i++) {
            if (!other.polynomiums[i]) {
                continue;
            }
            pv.polynomiums[i] = this.polynomiums[i].add(other.polynomiums[i]);
        }
        return pv;
    }

    public sub(other: PolynomiumVector): PolynomiumVector {
        const length = this.polynomiums.length;
        const pv = new PolynomiumVector(length);
        for (let i = 0; i < length; i++) {
            if (!other.polynomiums[i]) {
                continue;
            }
            pv.polynomiums[i] = this.polynomiums[i].sub(other.polynomiums[i]);
        }
        return pv;
    }

    public caddq() {
        const length = this.polynomiums.length;
        for (let i = 0; i < length; i++) {
            this.polynomiums[i].caddq();
        }
    }

    public shift(): PolynomiumVector {
        const length = this.polynomiums.length;
        const pv = new PolynomiumVector(length);
        for (let i = 0; i < length; i++) {
            pv.polynomiums[i] = this.polynomiums[i].shiftl();
        }
        return pv;
    }

    public powerRound(): PolynomiumVector[] {
        const length = this.polynomiums.length;
        const res = [
            new PolynomiumVector(length),
            new PolynomiumVector(length),
        ];

        for (let i = 0; i < length; i++) {
            const r = this.polynomiums[i].powerRound();
            res[0].polynomiums[i] = r[0];
            res[1].polynomiums[i] = r[1];
        }

        return res;
    }

    public pointwiseMontgomery(u: Polynomium): PolynomiumVector {
        const length = this.polynomiums.length;
        const pv = new PolynomiumVector(length);
        for (let i = 0; i < length; i++) {
            pv.polynomiums[i] = u.pointwiseMontgomery(this.polynomiums[i]);
        }
        return pv;
    }

    private static pointwiseAccMontgomery(u: PolynomiumVector, v: PolynomiumVector): Polynomium {
        let w = u.polynomiums[0].pointwiseMontgomery(v.polynomiums[0]);
        const length = v.size();
        for (let i = 1; i < length; i++) {
            const t = u.polynomiums[i].pointwiseMontgomery(v.polynomiums[i]);
            w = w.add(t);
        }
        return w;
    }

    public mulMatrixPointwiseMontgomery(M: PolynomiumVector[]): PolynomiumVector {
        const pv = new PolynomiumVector(M.length);
        for (let i = 0; i < M.length; i++) {
            pv.polynomiums[i] = PolynomiumVector.pointwiseAccMontgomery(M[i], this);
        }
        return pv;
    }

    public size(): number {
        return this.polynomiums.length;
    }

    public chknorm(bound: number): boolean {
        for (const poly of this.polynomiums) {
            if (poly.chknorm(bound)) {
                return true;
            }
        }
        return false;
    }

    public toString(): string {
        return "{" + this.polynomiums.map(a => a.toString()).join(", ") + "}";
    }
}
