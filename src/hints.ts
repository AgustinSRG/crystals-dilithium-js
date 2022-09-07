// Hints

"use strict";

import { N, Q } from "./constants";
import { Polynomium } from "./poly";
import { PolynomiumVector } from "./poly-vec";


export interface Hints {
    v: PolynomiumVector;
    cnt: number;
}

export interface Hint {
    v: Polynomium;
    cnt: number;
}

export function makeHints(gamma2: number, v0: PolynomiumVector, v1: PolynomiumVector) {
    const hints: Hints = {
        v: new PolynomiumVector(v0.size()),
        cnt: 0,
    };

    for (let i = 0; i < v0.size(); i++) {
        const hint = polyMakeHint(gamma2, v0.polynomiums[i], v1.polynomiums[i]);
        hints.cnt += hint.cnt;
        hints.v.polynomiums[i] = hint.v;
    }

    return hints;
}

function polyMakeHint(gamma2: number, a: Polynomium, b: Polynomium): Hint {
    const hint: Hint = {
        v: new Polynomium(N),
        cnt: 0,
    };
    for (let i = 0; i < N; i++) {
        hint.v.coef[i] = makeHint(gamma2, a.coef[i], b.coef[i]);
        hint.cnt += hint.v.coef[i];
    }
    return hint;
}

function makeHint(gamma2: number, a0: number, a1: number): number {
    if (a0 <= gamma2 || a0 > Q - gamma2 || (a0 === Q - gamma2 && a1 === 0)) {
        return 0;
    }

    return 1;
}

export function useHints(gamma2: number, u: PolynomiumVector, h: PolynomiumVector): PolynomiumVector {
    const res = new PolynomiumVector(u.size());
    for (let i = 0; i < res.size(); i++) {
        res.polynomiums[i] = polyUseHint(gamma2, u.polynomiums[i], h.polynomiums[i]);
    }
    return res;
}

function polyUseHint(gamma2: number, u: Polynomium, h: Polynomium): Polynomium {
    const res = new Polynomium(N);
    for (let i = 0; i < N; i++) {
        res.coef[i] = useHint(gamma2, u.coef[i], h.coef[i]);
    }
    return res;
}

function useHint(gamma2: number, a: number, hint: number): number {
    let a0: number;
    let a1: number;

    a1 = (a + 127) >> 7;
    if (gamma2 === (Q - 1) / 32) {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;

    } else if (gamma2 === (Q - 1) / 88) {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    } else {
        throw new Error("Invalid gamma2: " + gamma2);
    }
    a0 = a - a1 * 2 * gamma2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;

    if (hint === 0) {
        return a1;
    }

    if (gamma2 === (Q - 1) / 32) {
        if (a0 > 0)
            return (a1 + 1) & 15;
        else
            return (a1 - 1) & 15;
    } else if (gamma2 === (Q - 1) / 88) {
        if (a0 > 0)
            return (a1 === 43) ? 0 : a1 + 1;
        else
            return (a1 === 0) ? 43 : a1 - 1;

    } else {
        throw new Error("Invalid gamma2: " + gamma2);
    }
}
