// Implementation of kyber-1024
// Adapted from https://github.com/antontutoveanu/crystals-kyber-javascript
import { sha3_256, sha3_512, shake128, shake256 } from '@noble/hashes/sha3';
import { webcrypto } from 'node:crypto';
import _ from 'lodash';

const ZETAS = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
    1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
    478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
];

const ZETAS_INV = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
    1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
    1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
    1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
    3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
    1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
    2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
    829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
    3127, 3042, 1907, 1836, 1517, 359, 758, 1441
];

const K = 4;
const N = 256;
const Q = 3_329;
const Q_INVERSE = 6_2209;
const ETA = 2;

/**
 *
 * @returns
 */
export function keyGenerator(): [number[], number[]] {
    // IND-CPA keypair
    const [pk, sk] = indcpaKeyGenerator();
    const pkh = Buffer.from(sha3_256(Buffer.from(pk)));
    const rnd = webcrypto.getRandomValues(new Uint8Array(32));
    // concatenate to form IND-CCA2 private key: sk + pk + h(pk) + rnd
    return [pk, [...sk, ...pk, ...pkh, ...rnd]];
}

/**
 *
 * @param pk
 * @returns (c, ss)
 */
// TODO: error is probably in this function as tests test decrypt.
export function encrypt(pk: number[]): [number[], Buffer] {
    const m = webcrypto.getRandomValues(new Uint8Array(32));
    const mHash = sha3_256(Buffer.from(m));
    const pkHash = sha3_256(Buffer.from(pk));

    const buffer1 = Buffer.concat([Buffer.from(mHash), Buffer.from(pkHash)]);
    const kr = sha3_512(buffer1);
    const kr1 = kr.slice(0, 32);
    const kr2 = kr.slice(32, 64);

    const ciphertext = indcpaEncrypt(pk, mHash, kr2);
    const ciphertextHash = sha3_256(Buffer.from(ciphertext));

    const buffer2 = Buffer.concat([Buffer.from(kr1), Buffer.from(ciphertextHash)]);
    const ss = Buffer.from(shake256(buffer2));

    return [ciphertext, ss];
}

/**
 *
 * @param ciphertext
 * @param pk
 * @returns
 */
export function decrypt(ciphertext: number[], pk: number[]): Buffer {
    const secretKey = pk.slice(0, 1536);
    const publicKey1 = pk.slice(1536, 3104);
    const publicKeyHash = pk.slice(3104, 3136);
    const z = pk.slice(3136, 3168);

    const m = indcpaDecrypt(ciphertext, secretKey);

    const buffer1 = Buffer.concat([Buffer.from(m), Buffer.from(publicKeyHash)]);
    const kr = sha3_512(buffer1);
    const kr1 = kr.slice(0, 32);
    const kr2 = kr.slice(32, 64);

    const cmp = indcpaEncrypt(publicKey1, m, kr2);
    const cHash = sha3_256(Buffer.from(ciphertext));

    const buffer2 = Buffer.concat([
        Buffer.from(compareArrays(ciphertext, cmp) ? z : kr1),
        Buffer.from(cHash)
    ]);
    return Buffer.from(shake256(buffer2));
}

/**
 * Generates public and private keys for the CPA-scure public-key encryption
 * scheme underlying Kyber.
 * @returns A tuple containing the public and prvate keys.
 */
function indcpaKeyGenerator(): [number[], number[]] {
    const random = webcrypto.getRandomValues(new Uint8Array(32));
    const seed = sha3_512(random);
    const publicSeed = seed.slice(0, 32);
    const noiseSeed = seed.slice(32, 64);

    // generate public matrix A (already in NTT form)
    const a = matrixA(publicSeed, false);
    const s = new Array(K).fill(undefined).map((_, i) => reduce(ntt(sample(noiseSeed, i))));
    const e = new Array(K).fill(undefined).map((_, i) => ntt(sample(noiseSeed, i + K)));

    // Key computation
    // A.s + e = pk
    const pk = a.flatMap((a_i, i) => _.flow(
        _.partial(multiply, _, s),
        polynomialToMontgomery,
        _.partial(add, _, e[i]),
        reduce,
        polynomialToBytes
    )(a_i));

    const publicKey = [...pk, ...publicSeed];
    const privateKey = s.flatMap((x) => polynomialToBytes(x));

    return [publicKey, privateKey];
}


/**
 * The encryption function of the CPA-secure public-key encryption scheme
 * underlying Kyber.
 * @param pk1
 * @param msg
 * @param coins
 * @returns
 */
function indcpaEncrypt(pk1: number[], msg: Uint8Array, coins: Uint8Array): number[] {
    const publicKey = _.chunk(pk1, 384)
        .slice(0, K)
        .map(chunk => polynomialFromBytes(chunk));
    const seed = pk1.slice(1536, 1568);

    // u = A.r + e1
    const a = matrixA(seed, true);
    const r = new Array(K).fill(undefined).map((_, i) => reduce(ntt(sample(coins, i))));
    const e1 = new Array(K).fill(undefined).map((_, i) => sample(coins, i + K));
    const u = a.map((a_i, i) =>
        _.flow(
            _.partial(multiply, _, r),
            nttInverse,
            _.partial(add, e1[i]),
            reduce,
            compress1
        )(a_i)
    );

    // v = pk.r + e2 + m
    const m = polynomialFromMessage(msg);
    const e2 = sample(coins, 2 * K);
    const v = _.flow(
        _.partial(multiply, publicKey),
        nttInverse,
        _.partial(add, e2),
        _.partial(add, m),
        reduce,
        compress2
    )(r);

    return [...u, ...v];
}

/**
 * The decryption function of the CPA-secure public-key encryption scheme
 * underlying Kyber.
 * @param ciphertext
 * @param privateKey
 * @returns
 */
function indcpaDecrypt(ciphertext: number[], privateKey: number[]): Uint8Array {
    const u = decompress1(ciphertext.slice(0, 1408)).map((u_i) => ntt(u_i));
    const v = decompress2(ciphertext.slice(1408, 1568));

    return _.flow(
        polynomialVectorFromBytes,
        _.partial(multiply, _, u),
        nttInverse,
        _.partial(subtract, v),
        reduce,
        polynomialToMessage
    )(privateKey);
}

/**
 * Deserializes a vector of polynomials.
 * @param a
 * @returns
 */
function polynomialVectorFromBytes(a: number[]): number[][] {
    return _.chunk(a, 384).map(chunk => polynomialFromBytes(chunk));
}

/**
 * Serializes a polynomial into an array of bytes.
 * @param a
 * @returns
 */
function polynomialToBytes(a: number[]): number[] {
    let t0: number, t1: number;
    let r = new Array(384);
    const a2 = subtract_q(a);

    for (let i = 0; i < N / 2; i++) {
        t0 = uint16(a2[2 * i]);
        t1 = uint16(a2[2 * i + 1]);

        r[3 * i + 0] = byte(t0 >> 0);
        r[3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4);
        r[3 * i + 2] = byte(t1 >> 4);
    }
    return r;
}

/**
 * Deserializes an array of bytes into a polynomial.
 * @param a
 * @returns
 */
function polynomialFromBytes(a: number[]): number[] {
    return new Array(N / 2).fill(undefined).flatMap((_, i) => [
        int16(((uint16(a[3 * i + 0]) >> 0) | (uint16(a[3 * i + 1]) << 8)) & 0xFFF),
        int16(((uint16(a[3 * i + 1]) >> 4) | (uint16(a[3 * i + 2]) << 4)) & 0xFFF),
    ]);
}

/**
 * Converts a polynomial to a 32-byte message.
 * @param a
 * @returns
 */
function polynomialToMessage(a: number[]): Uint8Array {
    let msg = new Uint8Array(N / 8);
    let t: number;
    let a2 = subtract_q(a);
    for (let i = 0; i < N / 8; i++) {
        msg[i] = 0;
        for (let j = 0; j < 8; j++) {
            t = (((uint16(a2[8 * i + j]) << 1) + uint16(Q / 2)) / uint16(Q)) & 1;
            msg[i] |= byte(t << j);
        }
    }
    return msg;
}

/**
 * Converts a 32-byte message to a polynomial.
 * @param msg
 * @returns
 */
function polynomialFromMessage(msg: Uint8Array): number[] {
    // All numbers are `int16`s.
    let r: number[] = new Array(384).fill(0);
    for (let i = 0; i < N / 8; i++) {
        for (let j = 0; j < 8; j++) {
            const mask = -1 * int16((msg[i] >> j) & 1);
            r[8 * i + j] = mask & int16((Q + 1) / 2);
        }
    }
    return r;
}

/**
 * Deterministically generates a matrix `A` (or the transpose of `A`) from a
 * seed. Entries of the matrix are polynomials that look uniformly random.
 * Performs rejection sampling on the output of an extendable-output function
 * (XOF).
 * @param seed
 * @param transposed
 * @returns The matrix `A`.
 */
function matrixA(seed: number[] | Uint8Array, transposed: boolean): number[][][] {
    let a: number[][][] = new Array(K);
    let ctr = 0;
    for (let i = 0; i < K; i++) {
        a[i] = new Array(K);
        for (let j = 0; j < K; j++) {
            const transpose = transposed ? [i, j] : [j, i];

            // obtain xof of (seed+i+j) or (seed+j+i) depending on above code
            const buffer = Buffer.concat([
                Buffer.from(seed),
                Buffer.from(transpose)
            ]);
            const output = shake128(buffer, { dkLen: 672 });

            // run rejection sampling on the output from above
            // a[i][j] is a NTT-representation
            // ctr keeps track of index of output array from sampling function
            [a[i][j], ctr] = indcpaRejUniform(output.slice(0, 504), 504, N);

            while (ctr < N) { // if the polynomial hasnt been filled yet with mod q entries
                const outputn = output.slice(504, 672);
                // ctrn: starting at last position of output array from first sampling function until 256 is reached
                const [missing, ctrn] = indcpaRejUniform(outputn, 168, N - ctr); // run sampling function again
                for (let k = ctr; k < N; k++) {
                    // fill rest of array with the additional coefficients until full
                    a[i][j][k] = missing[k - ctr];
                }
                ctr += ctrn;
            }
        }
    }
    return a;
}

/**
 * Runs rejection sampling on uniform random bytes to generates uniform random
 * integers modulo `Q`.
 * @param buf
 * @param bufl
 * @param len
 * @returns
 */
function indcpaRejUniform(buf: Uint8Array, bufl: number, len: number): [number[], number] {
    let r: number[] = new Array(384).fill(0);
    let val0: number, val1: number; // d1, d2 in Kyber documentation
    let pos = 0;
    let ctr = 0;

    while (ctr < len && pos + 3 <= bufl) {
        val0 = (uint16((buf[pos + 0]) >> 0) | (uint16(buf[pos + 1]) << 8)) & 0xFFF;
        val1 = (uint16((buf[pos + 1]) >> 4) | (uint16(buf[pos + 2]) << 4)) & 0xFFF;
        pos += 3;

        if (val0 < Q) {
            r[ctr] = val0;
            ctr++;
        }
        if (ctr < len && val1 < Q) {
            r[ctr] = val1;
            ctr++;
        }
    }

    return [r, ctr];
}

/**
 * Samples a polynomial deterministically from a `seed` and `nonce`, with the
 * output polynomial being close to a centered binomial distribution with
 * parameter ETA = 2.
 * @param seed
 * @param nonce
 * @returns
 */
function sample(seed: Uint8Array, nonce: number): number[] {
    const LENGTH = ETA * N / 4;
    const p = pseudoRandomFunction(LENGTH, seed, nonce);
    return cbd(p);
}

/**
 * Pseudo-random function.
 * @param length Length of byte array.
 * @param key
 * @param nonce
 * @returns Pseudo-random byte array.
 */
function pseudoRandomFunction(length: number, key: Uint8Array, nonce: number): Uint8Array {
    return shake256(
        Buffer.concat([
            Buffer.from(key),
            Buffer.from([nonce])
        ]),
        { dkLen: length },
    );
}

/**
 * Computes a polynomial with coefficients distributed according to a centered
 * binomial distribution with parameter `ETA`, given an array of uniformly
 * random bytes.
 * @param buf
 * @returns
 */
function cbd(buf: Uint8Array): number[] {
    let t: number, d: number;
    let a: number, b: number;
    let r = new Array(384).fill(0);
    for (let i = 0; i < N / 8; i++) {
        t = (load32(buf.slice(4 * i, buf.length)));
        d = ((t & 0x55555555));
        d = (d + ((((t >> 1)) & 0x55555555)));
        for (let j = 0; j < 8; j++) {
            a = int16((((d >> (4 * j + 0))) & 0x3));
            b = int16((((d >> (4 * j + ETA))) & 0x3));
            r[8 * i + j] = a - b;
        }
    }
    return r;
}

/**
 * Loads 32-bit unsigned integer from byte `x`.
 * @param x
 * @returns 32-bit unsigned integer from byte `x`.
 */
function load32(x: Uint8Array): number {
    return uint16(uint32(x[0])
        | (uint32(x[1]) << 8)
        | (uint32(x[2]) << 16)
        | (uint32(x[3]) << 24));
}

/**
 * Performs an in-place number-theoretic transform (NTT) in `Rq`.
 * @param r In standard order.
 * @returns In bit-reversed order.
 */
function ntt(r: number[]): number[] {
    let j = 0;
    let k = 1;
    // 128, 64, 32, 16, 8, 4, 2
    for (let l = 128; l >= 2; l >>= 1) {
        for (let start = 0; start < 256; start = j + l) {
            const zeta = ZETAS[k];
            k++;
            // for each element in the subsections (128, 64, 32, 16, 8, 4, 2) starting at an offset
            for (j = start; j < start + l; j++) {
                // compute the modular multiplication of the zeta and each element in the subsection
                const t = fqMul(zeta, r[j + l]); // t is mod q
                // overwrite each element in the subsection as the opposite subsection element minus t
                r[j + l] = r[j] - t;
                // add t back again to the opposite subsection
                r[j] += t;
            }
        }
    }
    return r;
}

/**
 * Multiplication followed by Montgomery reduction.
 * @param a
 * @param b
 * @returns A 16-bit integer congruent to `a*b*R^{-1} mod Q`.
 */
function fqMul(a: number, b: number): number {
    return montgomeryReduce(a * b);
}

/**
 * Applies a Barrett reduction to all coefficients of a polynomial.
 * @param r
 * @returns
 */
function reduce(r: number[]): number[] {
    return r.map((r_i) => barrett(r_i));
}

/**
 * Computes a Barrett reduction.
 * @param x
 * @returns `a mod Q`
 */
function barrett(x: number): number {
    const v = ((1 << 24) + Q / 2) / Q;
    const t = (v * x >> 24) * Q;
    return x - t;
}

/**
 * Computes a Montgomery reduction.
 * @param x
 * @returns `a * R^-1 mod Q` where `R = 2^16`.
 */
function montgomeryReduce(x: number): number {
    const u = int16(int32(x) * Q_INVERSE);
    return int16(((x - (u * Q)) >> 16));
}

/**
 * In-place conversion of all coefficient of a polynomial from the normal domain
 * to the Montgomery domain.
 * @param r
 * @returns
 */
function polynomialToMontgomery(r: number[]): number[] {
    // let f = int16(((uint64(1) << 32)) % uint64(Q));
    let f = 1353; // if Q changes then this needs to be updated
    r = r.map((r_i) => montgomeryReduce(int32(r_i) * f));
    return r;
}

/**
 * Pointwise multiplies elements of polynomial-vectors `a` and `b` and then
 * multiplies by `2^-16`.
 * @param a
 * @param b
 * @returns
 */
function multiply(a: number[][], b: number[][]): number[] {
    let r = polyBaseMulMontgomery(a[0], b[0]);
    let t: number[];
    for (let i = 1; i < K; i++) {
        t = polyBaseMulMontgomery(a[i], b[i]);
        r = add(r, t);
    }
    return reduce(r);
}

/**
 * Multiplication of two polynomials in the number-theoretic transform domain.
 * @param a
 * @param b
 * @returns
 */
function polyBaseMulMontgomery(a: number[], b: number[]): number[] {
    let rx: number[], ry: number[];
    for (let i = 0; i < N / 4; i++) {
        rx = nttBaseMul(
            a[4 * i + 0], a[4 * i + 1],
            b[4 * i + 0], b[4 * i + 1],
            ZETAS[64 + i]
        );
        ry = nttBaseMul(
            a[4 * i + 2], a[4 * i + 3],
            b[4 * i + 2], b[4 * i + 3],
            -ZETAS[64 + i]
        );
        a[4 * i + 0] = rx[0];
        a[4 * i + 1] = rx[1];
        a[4 * i + 2] = ry[0];
        a[4 * i + 3] = ry[1];
    }
    return a;
}

/**
 * Multiplies polynomials in `Zq[X]/(X^2-zeta)`. Used for multiplication of
 * elements in `Rq` in the number-theoretic transformation domain.
 * @param a0
 * @param a1
 * @param b0
 * @param b1
 * @param zeta
 * @returns
 */
function nttBaseMul(a0: number, a1: number, b0: number, b1: number, zeta: number): [number, number] {
    return [
        fqMul(fqMul(a1, b1), zeta) + fqMul(a0, b0),
        fqMul(a0, b1) + fqMul(a1, b0)
    ];
}

/**
 * Adds two polynomials.
 * @param a
 * @param b
 * @returns The sum of the polynomials.
 */
function add(a: number[], b: number[]): number[] {
    return a.map((_, i) => a[i] + b[i]);
}

/**
 * Subtracts the polynomial `b` from the polynomial `a`.
 * @param a
 * @param b
 * @returns
 */
function subtract(a: number[], b: number[]): number[] {
    return a.map((_, i) => a[i] - b[i]);
}

/**
 * Performs an in-place inverse number-theoretic transform in `Rq` and
 * multiplication by Montgomery factor 2^16.
 * @param r In bit-reversed order.
 * @returns In standard order.
 */
function nttInverse(r: number[]): number[] {
    let j = 0;
    let k = 0;
    let zeta: number;
    let t: number;
    for (let l = 2; l <= 128; l <<= 1) {
        for (let start = 0; start < 256; start = j + l) {
            zeta = ZETAS_INV[k];
            k++;
            for (j = start; j < start + l; j++) {
                t = r[j];
                r[j] = barrett(t + r[j + l]);
                r[j + l] = fqMul(zeta, t - r[j + l]);
            }
        }
    }
    for (j = 0; j < 256; j++) {
        r[j] = fqMul(r[j], ZETAS_INV[127]);
    }
    return r;
}

/**
 * Lossily compresses and serializes a vector of polynomials.
 * @param u
 * @returns The compressed vector of polynomials.
 */
function compress1(u: number[][]): number[] {
    let rr = 0;
    let r: number[] = new Array(1408); // 4 * 352
    let t = new Array(8);
    for (let i = 0; i < K; i++) {
        for (let j = 0; j < N / 8; j++) {
            for (let k = 0; k < 8; k++) {
                t[k] = uint16((((uint32(u[i][8 * j + k]) << 11) + uint32(Q / 2)) / uint32(Q)) & 0x7ff);
            }
            r[rr + 0] = byte((t[0] >> 0));
            r[rr + 1] = byte((t[0] >> 8) | (t[1] << 3));
            r[rr + 2] = byte((t[1] >> 5) | (t[2] << 6));
            r[rr + 3] = byte((t[2] >> 2));
            r[rr + 4] = byte((t[2] >> 10) | (t[3] << 1));
            r[rr + 5] = byte((t[3] >> 7) | (t[4] << 4));
            r[rr + 6] = byte((t[4] >> 4) | (t[5] << 7));
            r[rr + 7] = byte((t[5] >> 1));
            r[rr + 8] = byte((t[5] >> 9) | (t[6] << 2));
            r[rr + 9] = byte((t[6] >> 6) | (t[7] << 5));
            r[rr + 10] = byte(t[7] >> 3);
            rr += 11;
        }
    }
    return r;
}

/**
 * Lossily compresses and serializes a polynomial.
 * @param v
 * @returns The compressed and serialized polynomial.
 */
function compress2(v: number[]): number[] {
    let rr = 0;
    let r: number[] = new Array(160);
    let t: number[] = new Array(8);
    for (let i = 0; i < N / 8; i++) {
        for (let j = 0; j < 8; j++) {
            t[j] = byte(((uint32(v[8 * i + j]) << 5) + uint32(Q / 2)) / uint32(Q)) & 31;
        }
        r[rr + 0] = byte((t[0] >> 0) | (t[1] << 5));
        r[rr + 1] = byte((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
        r[rr + 2] = byte((t[3] >> 1) | (t[4] << 4));
        r[rr + 3] = byte((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
        r[rr + 4] = byte((t[6] >> 2) | (t[7] << 3));
        rr = rr + 5;
    }
    return r;
}

/**
 * Deserializes and decompresses a vector of polynomials and represents the
 * approximate inverse of compress1. Since compression is lossy, the results of
 * decompression may not match the original vector of polynomials.
 * @param a
 * @returns The decompressed vector of polynomials.
 */
function decompress1(a: number[]): number[][] {
    let r: number[][] = new Array(K);
    for (let i = 0; i < K; i++) {
        r[i] = new Array(384);
    }
    let aa = 0;
    let t: number[] = new Array(8);
    for (let i = 0; i < K; i++) {
        for (let j = 0; j < N / 8; j++) {
            t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
            t[1] = (uint16(a[aa + 1]) >> 3) | (uint16(a[aa + 2]) << 5);
            t[2] = (uint16(a[aa + 2]) >> 6) | (uint16(a[aa + 3]) << 2) | (uint16(a[aa + 4]) << 10);
            t[3] = (uint16(a[aa + 4]) >> 1) | (uint16(a[aa + 5]) << 7);
            t[4] = (uint16(a[aa + 5]) >> 4) | (uint16(a[aa + 6]) << 4);
            t[5] = (uint16(a[aa + 6]) >> 7) | (uint16(a[aa + 7]) << 1) | (uint16(a[aa + 8]) << 9);
            t[6] = (uint16(a[aa + 8]) >> 2) | (uint16(a[aa + 9]) << 6);
            t[7] = (uint16(a[aa + 9]) >> 5) | (uint16(a[aa + 10]) << 3);
            aa += 11;
            for (let k = 0; k < 8; k++) {
                r[i][8 * j + k] = (uint32(t[k] & 0x7FF) * Q + 1024) >> 11;
            }
        }
    }
    return r;
}

/**
 * Applies the conditional subtraction of q to each coefficient of a polynomial.
 * If a is 3329 then convert to 0.
 * @param r The polynomial.
 * @returns `a - q` if `a >= q`, else `a`.
 */
function subtract_q(r: number[]): number[] {
    for (let i = 0; i < N; i++) {
        r[i] -= Q;
        r[i] += ((r[i] >> 31) & Q);
    }
    return r;
}

/**
 * Deserializes and then decompresses a polynomial, representive the
 * approximate inverse of compress2. Note that compression is lossy so
 * so decompression will not match the original input.
 * @param a
 * @returns The decompressed polynomial.
 */
function decompress2(a: number[]): number[] {
    let r = new Array(384);
    let t = new Array(8);
    let aa = 0;
    for (let i = 0; i < N / 8; i++) {
        t[0] = a[aa + 0] >> 0;
        t[1] = (a[aa + 0] >> 5) | (a[aa + 1] << 3);
        t[2] = (a[aa + 1] >> 2);
        t[3] = (a[aa + 1] >> 7) | (a[aa + 2] << 1);
        t[4] = (a[aa + 2] >> 4) | (a[aa + 3] << 4);
        t[5] = (a[aa + 3] >> 1);
        t[6] = (a[aa + 3] >> 6) | (a[aa + 4] << 2);
        t[7] = a[aa + 4] >> 3;
        aa = aa + 5;
        for (let j = 0; j < 8; j++) {
            r[8 * i + j] = int16(((uint32(t[j] & 31) * uint32(Q)) + 16) >> 5);
        }
    }
    return r;
}

////////////////////////////////////////////////////////////////////////////////
// Conversion functions

function byte(n: number): number {
    return n % 256;
}

function int16(n: number): number {
    const LOWER_BOUND = -32_768;
    const UPPER_BOUND = 32_767;

    if (n >= LOWER_BOUND && n <= UPPER_BOUND) {
        return n;
    } else if (n < LOWER_BOUND) {
        return UPPER_BOUND + ((n + 32_769) % 65_536);
    } else {
        return LOWER_BOUND + ((n - 32_769) % 65_536);
    }
}

function uint16(n: number): number {
    return n % 65_536;
}


function int32(n: number): number {
    const LOWER_BOUND = -2_147_483_648;
    const UPPER_BOUND = 2_147_483_647;

    if (n >= LOWER_BOUND && n <= UPPER_BOUND) {
        return n;
    } else if (n < LOWER_BOUND) {
        return UPPER_BOUND + ((n + 2_147_483_649) % 4_294_967_296);
    } else {
        return LOWER_BOUND + ((n - 2_147_483_649) % 4_294_967_296);
    }
}

function uint32(n: number): number {
    return n % 4_294_967_296;
}

////////////////////////////////////////////////////////////////////////////////
// Testing

/**
 * Checks if two array are equal.
 * @param a
 * @param b
 * @returns
 */
function compareArrays(a: any[] | Uint8Array, b: any[] | Uint8Array): boolean {
    // check array lengths
    if (a.length != b.length) {
        return false;
    }
    // check contents
    for (let i = 0; i < a.length; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

function hexToDec(hexString: string): number {
    return parseInt(hexString, 16);
}

export function test(): void {
    let fs = require('fs');
    let textByLine = fs.readFileSync('./PQCkemKAT_3168.rsp').toString().split("\n");

    let sk100: number[][] = [];
    let ct100: number[][] = [];
    let ss100: number[][] = [];
    let counter = 0;
    while (counter < textByLine.length) {
        if (textByLine[counter][0] == 'c' && textByLine[counter][1] == 't') {
            let tmp: number[] = [];
            for (let j = 0; j < 1568; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            ct100.push(tmp);
        } else if (textByLine[counter][0] == 's' && textByLine[counter][1] == 's') {
            let tmp: number[] = [];
            for (let j = 0; j < 32; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            ss100.push(tmp);
        } else if (textByLine[counter][0] == 's' && textByLine[counter][1] == 'k') {
            let tmp: number[] = [];
            for (let j = 0; j < 3168; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            sk100.push(tmp);
        }
        counter++;
    }

    let failures = 0;

    // for each case (100 total)
    // test if ss equals Decrypt1024(c,sk)
    for (let i = 0; i < 100; i++) {
        let ss2 = decrypt(ct100[i], sk100[i]);

        // success if both symmetric keys are the same
        if (compareArrays(ss100[i], ss2)) {
            console.log("Test run [", i, "] success");
        } else {
            console.log("Test run [", i, "] fail");
            failures++;
        }
    }

    console.log();
    if (!failures) {
        console.log("All test runs successful.")
    } else {
        console.log(failures, " test cases have failed.")
    }

    const [pk, sk] = keyGenerator();
    // To generate a random 256 bit symmetric key (ss) and its encapsulation (c)
    let [c, ss1] = encrypt(pk);
    // To decapsulate and obtain the same symmetric key
    let ss2 = decrypt(c, sk);

    console.log();
    console.log("ss1", ss1);
    console.log("ss2", ss2);

    // returns 1 if both symmetric keys are the same
    console.log(compareArrays(ss1, ss2));
}
