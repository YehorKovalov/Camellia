/* camellia.c ver 1.2.0
 *
 * Copyright (c) 2006,2007
 * NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer as
 *   the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NTT ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NTT BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Algorithm Specification 
 *  http://info.isl.ntt.co.jp/crypt/eng/camellia/specifications.html
 */


#include <string.h>
#include <stdlib.h>

#include "camellia.h"

/* u32 must be 32bit word */



/**
 * Stuff related to the Camellia key schedule
 */

void camellia_setup128(const unsigned char *key, u32 *subkey)
{
    u32 kll, klr, krl, krr;
    u32 il, ir, t0, t1, w0, w1;
    u32 kw4l, kw4r, dw, tl, tr;
    u32 subL[26];
    u32 subR[26];

    /**
     *  k == kll || klr || krl || krr (|| is concatination)
     */
    kll = GETU32(key     );
    klr = GETU32(key +  4);
    krl = GETU32(key +  8);
    krr = GETU32(key + 12);
    /**
     * generate KL dependent subkeys
     */
    subl(0) = kll; subr(0) = klr;
    subl(1) = krl; subr(1) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(4) = kll; subr(4) = klr;
    subl(5) = krl; subr(5) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 30);
    subl(10) = kll; subr(10) = klr;
    subl(11) = krl; subr(11) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(13) = krl; subr(13) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(16) = kll; subr(16) = klr;
    subl(17) = krl; subr(17) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(18) = kll; subr(18) = klr;
    subl(19) = krl; subr(19) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(22) = kll; subr(22) = klr;
    subl(23) = krl; subr(23) = krr;

    /* generate KA */
    kll = subl(0); klr = subr(0);
    krl = subl(1); krr = subr(1);
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA1L, CAMELLIA_SIGMA1R,
	       w0, w1, il, ir, t0, t1);
    krl ^= w0; krr ^= w1;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA2L, CAMELLIA_SIGMA2R,
	       kll, klr, il, ir, t0, t1);
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA3L, CAMELLIA_SIGMA3R,
	       krl, krr, il, ir, t0, t1);
    krl ^= w0; krr ^= w1;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA4L, CAMELLIA_SIGMA4R,
	       w0, w1, il, ir, t0, t1);
    kll ^= w0; klr ^= w1;

    /* generate KA dependent subkeys */
    subl(2) = kll; subr(2) = klr;
    subl(3) = krl; subr(3) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(6) = kll; subr(6) = klr;
    subl(7) = krl; subr(7) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(8) = kll; subr(8) = klr;
    subl(9) = krl; subr(9) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(12) = kll; subr(12) = klr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(14) = kll; subr(14) = klr;
    subl(15) = krl; subr(15) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 34);
    subl(20) = kll; subr(20) = klr;
    subl(21) = krl; subr(21) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(24) = kll; subr(24) = klr;
    subl(25) = krl; subr(25) = krr;


    /* absorb kw2 to other subkeys */
    subl(3) ^= subl(1); subr(3) ^= subr(1);
    subl(5) ^= subl(1); subr(5) ^= subr(1);
    subl(7) ^= subl(1); subr(7) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(9);
    dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    subl(11) ^= subl(1); subr(11) ^= subr(1);
    subl(13) ^= subl(1); subr(13) ^= subr(1);
    subl(15) ^= subl(1); subr(15) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(17);
    dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    subl(19) ^= subl(1); subr(19) ^= subr(1);
    subl(21) ^= subl(1); subr(21) ^= subr(1);
    subl(23) ^= subl(1); subr(23) ^= subr(1);
    subl(24) ^= subl(1); subr(24) ^= subr(1);

    /* absorb kw4 to other subkeys */
    kw4l = subl(25); kw4r = subr(25);
    subl(22) ^= kw4l; subr(22) ^= kw4r;
    subl(20) ^= kw4l; subr(20) ^= kw4r;
    subl(18) ^= kw4l; subr(18) ^= kw4r;
    kw4l ^= kw4r & ~subr(16);
    dw = kw4l & subl(16), kw4r ^= CAMELLIA_RL1(dw);
    subl(14) ^= kw4l; subr(14) ^= kw4r;
    subl(12) ^= kw4l; subr(12) ^= kw4r;
    subl(10) ^= kw4l; subr(10) ^= kw4r;
    kw4l ^= kw4r & ~subr(8);
    dw = kw4l & subl(8), kw4r ^= CAMELLIA_RL1(dw);
    subl(6) ^= kw4l; subr(6) ^= kw4r;
    subl(4) ^= kw4l; subr(4) ^= kw4r;
    subl(2) ^= kw4l; subr(2) ^= kw4r;
    subl(0) ^= kw4l; subr(0) ^= kw4r;

    /* key XOR is end of F-function */
    CamelliaSubkeyL(0) = subl(0) ^ subl(2);
    CamelliaSubkeyR(0) = subr(0) ^ subr(2);
    CamelliaSubkeyL(2) = subl(3);
    CamelliaSubkeyR(2) = subr(3);
    CamelliaSubkeyL(3) = subl(2) ^ subl(4);
    CamelliaSubkeyR(3) = subr(2) ^ subr(4);
    CamelliaSubkeyL(4) = subl(3) ^ subl(5);
    CamelliaSubkeyR(4) = subr(3) ^ subr(5);
    CamelliaSubkeyL(5) = subl(4) ^ subl(6);
    CamelliaSubkeyR(5) = subr(4) ^ subr(6);
    CamelliaSubkeyL(6) = subl(5) ^ subl(7);
    CamelliaSubkeyR(6) = subr(5) ^ subr(7);
    tl = subl(10) ^ (subr(10) & ~subr(8));
    dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(7) = subl(6) ^ tl;
    CamelliaSubkeyR(7) = subr(6) ^ tr;
    CamelliaSubkeyL(8) = subl(8);
    CamelliaSubkeyR(8) = subr(8);
    CamelliaSubkeyL(9) = subl(9);
    CamelliaSubkeyR(9) = subr(9);
    tl = subl(7) ^ (subr(7) & ~subr(9));
    dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(10) = tl ^ subl(11);
    CamelliaSubkeyR(10) = tr ^ subr(11);
    CamelliaSubkeyL(11) = subl(10) ^ subl(12);
    CamelliaSubkeyR(11) = subr(10) ^ subr(12);
    CamelliaSubkeyL(12) = subl(11) ^ subl(13);
    CamelliaSubkeyR(12) = subr(11) ^ subr(13);
    CamelliaSubkeyL(13) = subl(12) ^ subl(14);
    CamelliaSubkeyR(13) = subr(12) ^ subr(14);
    CamelliaSubkeyL(14) = subl(13) ^ subl(15);
    CamelliaSubkeyR(14) = subr(13) ^ subr(15);
    tl = subl(18) ^ (subr(18) & ~subr(16));
    dw = tl & subl(16),	tr = subr(18) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(15) = subl(14) ^ tl;
    CamelliaSubkeyR(15) = subr(14) ^ tr;
    CamelliaSubkeyL(16) = subl(16);
    CamelliaSubkeyR(16) = subr(16);
    CamelliaSubkeyL(17) = subl(17);
    CamelliaSubkeyR(17) = subr(17);
    tl = subl(15) ^ (subr(15) & ~subr(17));
    dw = tl & subl(17),	tr = subr(15) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(18) = tl ^ subl(19);
    CamelliaSubkeyR(18) = tr ^ subr(19);
    CamelliaSubkeyL(19) = subl(18) ^ subl(20);
    CamelliaSubkeyR(19) = subr(18) ^ subr(20);
    CamelliaSubkeyL(20) = subl(19) ^ subl(21);
    CamelliaSubkeyR(20) = subr(19) ^ subr(21);
    CamelliaSubkeyL(21) = subl(20) ^ subl(22);
    CamelliaSubkeyR(21) = subr(20) ^ subr(22);
    CamelliaSubkeyL(22) = subl(21) ^ subl(23);
    CamelliaSubkeyR(22) = subr(21) ^ subr(23);
    CamelliaSubkeyL(23) = subl(22);
    CamelliaSubkeyR(23) = subr(22);
    CamelliaSubkeyL(24) = subl(24) ^ subl(23);
    CamelliaSubkeyR(24) = subr(24) ^ subr(23);

    /* apply the inverse of the last half of P-function */
    dw = CamelliaSubkeyL(2) ^ CamelliaSubkeyR(2), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(2) = CamelliaSubkeyL(2) ^ dw, CamelliaSubkeyL(2) = dw;
    dw = CamelliaSubkeyL(3) ^ CamelliaSubkeyR(3), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(3) = CamelliaSubkeyL(3) ^ dw, CamelliaSubkeyL(3) = dw;
    dw = CamelliaSubkeyL(4) ^ CamelliaSubkeyR(4), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(4) = CamelliaSubkeyL(4) ^ dw, CamelliaSubkeyL(4) = dw;
    dw = CamelliaSubkeyL(5) ^ CamelliaSubkeyR(5), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(5) = CamelliaSubkeyL(5) ^ dw, CamelliaSubkeyL(5) = dw;
    dw = CamelliaSubkeyL(6) ^ CamelliaSubkeyR(6), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(6) = CamelliaSubkeyL(6) ^ dw, CamelliaSubkeyL(6) = dw;
    dw = CamelliaSubkeyL(7) ^ CamelliaSubkeyR(7), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(7) = CamelliaSubkeyL(7) ^ dw, CamelliaSubkeyL(7) = dw;
    dw = CamelliaSubkeyL(10) ^ CamelliaSubkeyR(10), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(10) = CamelliaSubkeyL(10) ^ dw, CamelliaSubkeyL(10) = dw;
    dw = CamelliaSubkeyL(11) ^ CamelliaSubkeyR(11), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(11) = CamelliaSubkeyL(11) ^ dw, CamelliaSubkeyL(11) = dw;
    dw = CamelliaSubkeyL(12) ^ CamelliaSubkeyR(12), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(12) = CamelliaSubkeyL(12) ^ dw, CamelliaSubkeyL(12) = dw;
    dw = CamelliaSubkeyL(13) ^ CamelliaSubkeyR(13), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(13) = CamelliaSubkeyL(13) ^ dw, CamelliaSubkeyL(13) = dw;
    dw = CamelliaSubkeyL(14) ^ CamelliaSubkeyR(14), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(14) = CamelliaSubkeyL(14) ^ dw, CamelliaSubkeyL(14) = dw;
    dw = CamelliaSubkeyL(15) ^ CamelliaSubkeyR(15), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(15) = CamelliaSubkeyL(15) ^ dw, CamelliaSubkeyL(15) = dw;
    dw = CamelliaSubkeyL(18) ^ CamelliaSubkeyR(18), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(18) = CamelliaSubkeyL(18) ^ dw, CamelliaSubkeyL(18) = dw;
    dw = CamelliaSubkeyL(19) ^ CamelliaSubkeyR(19), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(19) = CamelliaSubkeyL(19) ^ dw, CamelliaSubkeyL(19) = dw;
    dw = CamelliaSubkeyL(20) ^ CamelliaSubkeyR(20), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(20) = CamelliaSubkeyL(20) ^ dw, CamelliaSubkeyL(20) = dw;
    dw = CamelliaSubkeyL(21) ^ CamelliaSubkeyR(21), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(21) = CamelliaSubkeyL(21) ^ dw, CamelliaSubkeyL(21) = dw;
    dw = CamelliaSubkeyL(22) ^ CamelliaSubkeyR(22), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(22) = CamelliaSubkeyL(22) ^ dw, CamelliaSubkeyL(22) = dw;
    dw = CamelliaSubkeyL(23) ^ CamelliaSubkeyR(23), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(23) = CamelliaSubkeyL(23) ^ dw, CamelliaSubkeyL(23) = dw;

    return;
}



    /* generate KA dependent subkeys */
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(6) = kll; subr(6) = klr;
    subl(7) = krl; subr(7) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 30);
    subl(14) = kll; subr(14) = klr;
    subl(15) = krl; subr(15) = krr;
    subl(24) = klr; subr(24) = krl;
    subl(25) = krr; subr(25) = kll;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 49);
    subl(28) = kll; subr(28) = klr;
    subl(29) = krl; subr(29) = krr;

    /* generate KB dependent subkeys */
    subl(2) = krll; subr(2) = krlr;
    subl(3) = krrl; subr(3) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(10) = krll; subr(10) = krlr;
    subl(11) = krrl; subr(11) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(20) = krll; subr(20) = krlr;
    subl(21) = krrl; subr(21) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 51);
    subl(32) = krll; subr(32) = krlr;
    subl(33) = krrl; subr(33) = krrr;

    /* absorb kw2 to other subkeys */
    subl(3) ^= subl(1); subr(3) ^= subr(1);
    subl(5) ^= subl(1); subr(5) ^= subr(1);
    subl(7) ^= subl(1); subr(7) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(9);
    dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    subl(11) ^= subl(1); subr(11) ^= subr(1);
    subl(13) ^= subl(1); subr(13) ^= subr(1);
    subl(15) ^= subl(1); subr(15) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(17);
    dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    subl(19) ^= subl(1); subr(19) ^= subr(1);
    subl(21) ^= subl(1); subr(21) ^= subr(1);
    subl(23) ^= subl(1); subr(23) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(25);
    dw = subl(1) & subl(25), subr(1) ^= CAMELLIA_RL1(dw);
    subl(27) ^= subl(1); subr(27) ^= subr(1);
    subl(29) ^= subl(1); subr(29) ^= subr(1);
    subl(31) ^= subl(1); subr(31) ^= subr(1);
    subl(32) ^= subl(1); subr(32) ^= subr(1);

    /* absorb kw4 to other subkeys */
    kw4l = subl(33); kw4r = subr(33);
    subl(30) ^= kw4l; subr(30) ^= kw4r;
    subl(28) ^= kw4l; subr(28) ^= kw4r;
    subl(26) ^= kw4l; subr(26) ^= kw4r;
    kw4l ^= kw4r & ~subr(24);
    dw = kw4l & subl(24), kw4r ^= CAMELLIA_RL1(dw);
    subl(22) ^= kw4l; subr(22) ^= kw4r;
    subl(20) ^= kw4l; subr(20) ^= kw4r;
    subl(18) ^= kw4l; subr(18) ^= kw4r;
    kw4l ^= kw4r & ~subr(16);
    dw = kw4l & subl(16), kw4r ^= CAMELLIA_RL1(dw);
    subl(14) ^= kw4l; subr(14) ^= kw4r;
    subl(12) ^= kw4l; subr(12) ^= kw4r;
    subl(10) ^= kw4l; subr(10) ^= kw4r;
    kw4l ^= kw4r & ~subr(8);
    dw = kw4l & subl(8), kw4r ^= CAMELLIA_RL1(dw);
    subl(6) ^= kw4l; subr(6) ^= kw4r;
    subl(4) ^= kw4l; subr(4) ^= kw4r;
    subl(2) ^= kw4l; subr(2) ^= kw4r;
    subl(0) ^= kw4l; subr(0) ^= kw4r;

    /* key XOR is end of F-function */
    CamelliaSubkeyL(0) = subl(0) ^ subl(2);
    CamelliaSubkeyR(0) = subr(0) ^ subr(2);
    CamelliaSubkeyL(2) = subl(3);
    CamelliaSubkeyR(2) = subr(3);
    CamelliaSubkeyL(3) = subl(2) ^ subl(4);
    CamelliaSubkeyR(3) = subr(2) ^ subr(4);
    CamelliaSubkeyL(4) = subl(3) ^ subl(5);
    CamelliaSubkeyR(4) = subr(3) ^ subr(5);
    CamelliaSubkeyL(5) = subl(4) ^ subl(6);
    CamelliaSubkeyR(5) = subr(4) ^ subr(6);
    CamelliaSubkeyL(6) = subl(5) ^ subl(7);
    CamelliaSubkeyR(6) = subr(5) ^ subr(7);
    tl = subl(10) ^ (subr(10) & ~subr(8));
    dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(7) = subl(6) ^ tl;
    CamelliaSubkeyR(7) = subr(6) ^ tr;
    CamelliaSubkeyL(8) = subl(8);
    CamelliaSubkeyR(8) = subr(8);
    CamelliaSubkeyL(9) = subl(9);
    CamelliaSubkeyR(9) = subr(9);
    tl = subl(7) ^ (subr(7) & ~subr(9));
    dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(10) = tl ^ subl(11);
    CamelliaSubkeyR(10) = tr ^ subr(11);
    CamelliaSubkeyL(11) = subl(10) ^ subl(12);
    CamelliaSubkeyR(11) = subr(10) ^ subr(12);
    CamelliaSubkeyL(12) = subl(11) ^ subl(13);
    CamelliaSubkeyR(12) = subr(11) ^ subr(13);
    CamelliaSubkeyL(13) = subl(12) ^ subl(14);
    CamelliaSubkeyR(13) = subr(12) ^ subr(14);
    CamelliaSubkeyL(14) = subl(13) ^ subl(15);
    CamelliaSubkeyR(14) = subr(13) ^ subr(15);
    tl = subl(18) ^ (subr(18) & ~subr(16));
    dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(15) = subl(14) ^ tl;
    CamelliaSubkeyR(15) = subr(14) ^ tr;
    CamelliaSubkeyL(16) = subl(16);
    CamelliaSubkeyR(16) = subr(16);
    CamelliaSubkeyL(17) = subl(17);
    CamelliaSubkeyR(17) = subr(17);
    tl = subl(15) ^ (subr(15) & ~subr(17));
    dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(18) = tl ^ subl(19);
    CamelliaSubkeyR(18) = tr ^ subr(19);
    CamelliaSubkeyL(19) = subl(18) ^ subl(20);
    CamelliaSubkeyR(19) = subr(18) ^ subr(20);
    CamelliaSubkeyL(20) = subl(19) ^ subl(21);
    CamelliaSubkeyR(20) = subr(19) ^ subr(21);
    CamelliaSubkeyL(21) = subl(20) ^ subl(22);
    CamelliaSubkeyR(21) = subr(20) ^ subr(22);
    CamelliaSubkeyL(22) = subl(21) ^ subl(23);
    CamelliaSubkeyR(22) = subr(21) ^ subr(23);
    tl = subl(26) ^ (subr(26) & ~subr(24));
    dw = tl & subl(24), tr = subr(26) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(23) = subl(22) ^ tl;
    CamelliaSubkeyR(23) = subr(22) ^ tr;
    CamelliaSubkeyL(24) = subl(24);
    CamelliaSubkeyR(24) = subr(24);
    CamelliaSubkeyL(25) = subl(25);
    CamelliaSubkeyR(25) = subr(25);
    tl = subl(23) ^ (subr(23) &  ~subr(25));
    dw = tl & subl(25), tr = subr(23) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(26) = tl ^ subl(27);
    CamelliaSubkeyR(26) = tr ^ subr(27);
    CamelliaSubkeyL(27) = subl(26) ^ subl(28);
    CamelliaSubkeyR(27) = subr(26) ^ subr(28);
    CamelliaSubkeyL(28) = subl(27) ^ subl(29);
    CamelliaSubkeyR(28) = subr(27) ^ subr(29);
    CamelliaSubkeyL(29) = subl(28) ^ subl(30);
    CamelliaSubkeyR(29) = subr(28) ^ subr(30);
    CamelliaSubkeyL(30) = subl(29) ^ subl(31);
    CamelliaSubkeyR(30) = subr(29) ^ subr(31);
    CamelliaSubkeyL(31) = subl(30);
    CamelliaSubkeyR(31) = subr(30);
    CamelliaSubkeyL(32) = subl(32) ^ subl(31);
    CamelliaSubkeyR(32) = subr(32) ^ subr(31);

    /* apply the inverse of the last half of P-function */
    dw = CamelliaSubkeyL(2) ^ CamelliaSubkeyR(2), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(2) = CamelliaSubkeyL(2) ^ dw, CamelliaSubkeyL(2) = dw;
    dw = CamelliaSubkeyL(3) ^ CamelliaSubkeyR(3), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(3) = CamelliaSubkeyL(3) ^ dw, CamelliaSubkeyL(3) = dw;
    dw = CamelliaSubkeyL(4) ^ CamelliaSubkeyR(4), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(4) = CamelliaSubkeyL(4) ^ dw, CamelliaSubkeyL(4) = dw;
    dw = CamelliaSubkeyL(5) ^ CamelliaSubkeyR(5), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(5) = CamelliaSubkeyL(5) ^ dw, CamelliaSubkeyL(5) = dw;
    dw = CamelliaSubkeyL(6) ^ CamelliaSubkeyR(6), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(6) = CamelliaSubkeyL(6) ^ dw, CamelliaSubkeyL(6) = dw;
    dw = CamelliaSubkeyL(7) ^ CamelliaSubkeyR(7), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(7) = CamelliaSubkeyL(7) ^ dw, CamelliaSubkeyL(7) = dw;
    dw = CamelliaSubkeyL(10) ^ CamelliaSubkeyR(10), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(10) = CamelliaSubkeyL(10) ^ dw, CamelliaSubkeyL(10) = dw;
    dw = CamelliaSubkeyL(11) ^ CamelliaSubkeyR(11), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(11) = CamelliaSubkeyL(11) ^ dw, CamelliaSubkeyL(11) = dw;
    dw = CamelliaSubkeyL(12) ^ CamelliaSubkeyR(12), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(12) = CamelliaSubkeyL(12) ^ dw, CamelliaSubkeyL(12) = dw;
    dw = CamelliaSubkeyL(13) ^ CamelliaSubkeyR(13), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(13) = CamelliaSubkeyL(13) ^ dw, CamelliaSubkeyL(13) = dw;
    dw = CamelliaSubkeyL(14) ^ CamelliaSubkeyR(14), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(14) = CamelliaSubkeyL(14) ^ dw, CamelliaSubkeyL(14) = dw;
    dw = CamelliaSubkeyL(15) ^ CamelliaSubkeyR(15), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(15) = CamelliaSubkeyL(15) ^ dw, CamelliaSubkeyL(15) = dw;
    dw = CamelliaSubkeyL(18) ^ CamelliaSubkeyR(18), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(18) = CamelliaSubkeyL(18) ^ dw, CamelliaSubkeyL(18) = dw;
    dw = CamelliaSubkeyL(19) ^ CamelliaSubkeyR(19), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(19) = CamelliaSubkeyL(19) ^ dw, CamelliaSubkeyL(19) = dw;
    dw = CamelliaSubkeyL(20) ^ CamelliaSubkeyR(20), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(20) = CamelliaSubkeyL(20) ^ dw, CamelliaSubkeyL(20) = dw;
    dw = CamelliaSubkeyL(21) ^ CamelliaSubkeyR(21), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(21) = CamelliaSubkeyL(21) ^ dw, CamelliaSubkeyL(21) = dw;
    dw = CamelliaSubkeyL(22) ^ CamelliaSubkeyR(22), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(22) = CamelliaSubkeyL(22) ^ dw, CamelliaSubkeyL(22) = dw;
    dw = CamelliaSubkeyL(23) ^ CamelliaSubkeyR(23), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(23) = CamelliaSubkeyL(23) ^ dw, CamelliaSubkeyL(23) = dw;
    dw = CamelliaSubkeyL(26) ^ CamelliaSubkeyR(26), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(26) = CamelliaSubkeyL(26) ^ dw, CamelliaSubkeyL(26) = dw;
    dw = CamelliaSubkeyL(27) ^ CamelliaSubkeyR(27), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(27) = CamelliaSubkeyL(27) ^ dw, CamelliaSubkeyL(27) = dw;
    dw = CamelliaSubkeyL(28) ^ CamelliaSubkeyR(28), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(28) = CamelliaSubkeyL(28) ^ dw, CamelliaSubkeyL(28) = dw;
    dw = CamelliaSubkeyL(29) ^ CamelliaSubkeyR(29), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(29) = CamelliaSubkeyL(29) ^ dw, CamelliaSubkeyL(29) = dw;
    dw = CamelliaSubkeyL(30) ^ CamelliaSubkeyR(30), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(30) = CamelliaSubkeyL(30) ^ dw, CamelliaSubkeyL(30) = dw;
    dw = CamelliaSubkeyL(31) ^ CamelliaSubkeyR(31), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(31) = CamelliaSubkeyL(31) ^ dw,CamelliaSubkeyL(31) = dw;
    
    return;
}



/**
 * Stuff related to camellia encryption/decryption
 *
 * "io" must be 4byte aligned and big-endian data.
 */
void camellia_encrypt128(const u32 *subkey, u32 *io)
{
    u32 il, ir, t0, t1;

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(0);
    io[1] ^= CamelliaSubkeyR(0);
    /* main iteration */

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(24);
    io[3] ^= CamelliaSubkeyR(24);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;
	
    return;
}

void camellia_decrypt128(const u32 *subkey, u32 *io)
{
    u32 il,ir,t0,t1;               /* temporary valiables */
    
    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(24);
    io[1] ^= CamelliaSubkeyR(24);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(0);
    io[3] ^= CamelliaSubkeyR(0);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

/**
 * stuff for 192 and 256bit encryption/decryption
 */
void camellia_encrypt256(const u32 *subkey, u32 *io)
{
    u32 il,ir,t0,t1;           /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(0);
    io[1] ^= CamelliaSubkeyR(0);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(24),CamelliaSubkeyR(24),
		 CamelliaSubkeyL(25),CamelliaSubkeyR(25),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(26),CamelliaSubkeyR(26),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(27),CamelliaSubkeyR(27),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(28),CamelliaSubkeyR(28),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(29),CamelliaSubkeyR(29),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(30),CamelliaSubkeyR(30),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(31),CamelliaSubkeyR(31),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(32);
    io[3] ^= CamelliaSubkeyR(32);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

void camellia_decrypt256(const u32 *subkey, u32 *io)
{
    u32 il,ir,t0,t1;           /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(32);
    io[1] ^= CamelliaSubkeyR(32);
	
    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(31),CamelliaSubkeyR(31),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(30),CamelliaSubkeyR(30),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(29),CamelliaSubkeyR(29),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(28),CamelliaSubkeyR(28),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(27),CamelliaSubkeyR(27),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(26),CamelliaSubkeyR(26),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(25),CamelliaSubkeyR(25),
		 CamelliaSubkeyL(24),CamelliaSubkeyR(24),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(0);
    io[3] ^= CamelliaSubkeyR(0);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

/***
 *
 * API for compatibility
 */

void Camellia_Ekeygen(const int keyBitLength, 
		      const unsigned char *rawKey, 
		      KEY_TABLE_TYPE keyTable)
{
    switch(keyBitLength) {
    case 128:
	camellia_setup128(rawKey, keyTable);
	break;
    case 192:
	camellia_setup192(rawKey, keyTable);
	break;
    case 256:
	camellia_setup256(rawKey, keyTable);
	break;
    default:
	break;
    }
}


void Camellia_EncryptBlock(const int keyBitLength, 
			   const unsigned char *plaintext, 
			   const KEY_TABLE_TYPE keyTable, 
			   unsigned char *ciphertext)
{
    u32 tmp[4];

    tmp[0] = GETU32(plaintext);
    tmp[1] = GETU32(plaintext + 4);
    tmp[2] = GETU32(plaintext + 8);
    tmp[3] = GETU32(plaintext + 12);

    switch (keyBitLength) {
    case 128:
	camellia_encrypt128(keyTable, tmp);
	break;
    case 192:
	/* fall through */
    case 256:
	camellia_encrypt256(keyTable, tmp);
	break;
    default:
	break;
    }

    PUTU32(ciphertext, tmp[0]);
    PUTU32(ciphertext + 4, tmp[1]);
    PUTU32(ciphertext + 8, tmp[2]);
    PUTU32(ciphertext + 12, tmp[3]);
}

void Camellia_DecryptBlock(const int keyBitLength, 
			   const unsigned char *ciphertext, 
			   const KEY_TABLE_TYPE keyTable, 
			   unsigned char *plaintext)
{
    u32 tmp[4];

    tmp[0] = GETU32(ciphertext);
    tmp[1] = GETU32(ciphertext + 4);
    tmp[2] = GETU32(ciphertext + 8);
    tmp[3] = GETU32(ciphertext + 12);

    switch (keyBitLength) {
    case 128:
	camellia_decrypt128(keyTable, tmp);
	break;
    case 192:
	/* fall through */
    case 256:
	camellia_decrypt256(keyTable, tmp);
	break;
    default:
	break;
    }
    PUTU32(plaintext, tmp[0]);
    PUTU32(plaintext + 4, tmp[1]);
    PUTU32(plaintext + 8, tmp[2]);
    PUTU32(plaintext + 12, tmp[3]);
}
