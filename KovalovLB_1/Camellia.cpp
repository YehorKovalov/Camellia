#include "CamelliaSBOX.h"
#include <iostream>
using namespace std;

#define TEST_VECTOR 0
#define BLOCK_128_BIT 16
#define KEY_128_BIT 16
#define KEY_192_BIT 24
#define KEY_256_BIT 32

int KEY_MODE;

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char* u8;
typedef u32 u128[5];
typedef u32 u192[7];
typedef u32 u256[9];

#define ROTL32(x, n) ((x) << (n)) | ((x) >> (32 - (n)))
#define ROTL64(x, n) (x << n) | (x >> (64 - n))
#define MaskLeft(x) ((u64)x[0] << 32) | x[1]
#define MaskRight(x) ((u64)x[2] << 32) | x[3]
#define ByteToBit(x) (u64)(((u64)x[0] << 56) | ((u64)x[1] << 48) | ((u64)x[2] << 40) | ((u64)x[3] << 32) | ((u64)x[4] << 24) | ((u64)x[5] << 16)| ((u64)x[6] << 8) | ((u64)x[7] << 0))

void ROTL128(u128& x, int n) {

    u32 t = x[0] >> (32 - n);
    x[0] = (x[0] << n) | (x[1] >> (32 - n));
    x[1] = (x[1] << n) | (x[2] >> (32 - n));
    x[2] = (x[2] << n) | (x[3] >> (32 - n));
    x[3] = (x[3] << n) | t;
}
void U8strncpy(u8 to, u8 from, int howMany) {
    for (size_t i = 0; i < howMany; i++)
        to[i] = from[i];
    to[howMany] = '\0';
}
void ConsoleHexOutput(u8 string, const char* stringName) {
    cout << stringName;
    int length = strlen((char*)string);
#if TEST_VECTOR
    length = 16;
#endif
    for (size_t i = 0; i < length; i++)
        cout << hex << (int)string[i] << " ";
    cout << endl;
}
u8 BitToByte(u64 left, u64 right)
{
    u8 result = new unsigned char[17];
    int i = 0;
    for (; i < 8; i++)
        result[i] = (unsigned char)(left >> ((7 - i) << 3) & 0xff);
    for (; i < 16; i++)
        result[i] = (unsigned char)(right >> ((15 - i) << 3) & 0xff);
    return result;
}
class Camellia {
private:

    u64 kw[4] = {}, ke[6] = {}, k[24] = {};
    u128 KA = {}, KL = {}, KR = {}, KB = {};
    u128 key128 = {};
    u192 key192 = {};
    u256 key256 = {};

#define MASK8	0xff
#define MASK32	0xffffffff
#define MASK64	0xffffffffffffffff
#define MASK128	0xffffffffffffffffffffffffffffffff
#define C1	0xA09E667F3BCC908B
#define C2	0xB67AE8584CAA73B2
#define C3	0xC6EF372FE94F82BE
#define C4	0x54FF53A5F1D36F1C
#define C5	0x10E527FADE682D1D
#define C6	0xB05688C2B3E6C1FD
    void KeyGen128();
    void KeyGen192_256();
    void FormKA();
    void FormKB();
    void KeyInit(u8 key, int length);
    u64 F_Func(u64 F_IN, u64 KE);
    u64 FL_Func(u64 FL_IN, u64 KE);
    u64 FLINV_Func(u64 FLINV_IN, u64 KE);
    u8 OneBlockCamelliaEncrypt(u64 left, u64 right);
    u8 OneBlockCamelliaDecrypt(u64 left, u64 right);
    u8 Camellia_ECB(int length, u8 text);
public:
    u8 CamelliaEncrypt(u8 text, u8 key);
    u8 CamelliaDecrypt(u8 cipherText, u8 key);
};
u64 Camellia::F_Func(u64 F_IN, u64 KE) {
    u64 x = F_IN ^ KE;

    u32 t[8], y[8];
    int shiftBit = 56;
    t[0] = x >> shiftBit;
    for (size_t i = 1; i < 8; i++)
    {
        shiftBit -= 8;
        t[i] = (x >> shiftBit) & MASK8;
    }

    t[0] = SBOX[0][t[0]];
    t[1] = SBOX[1][t[1]];
    t[2] = SBOX[2][t[2]];
    t[3] = SBOX[3][t[3]];
    t[4] = SBOX[1][t[4]];
    t[5] = SBOX[2][t[5]];
    t[6] = SBOX[3][t[6]];
    t[7] = SBOX[0][t[7]];

    u32 temp = t[0] ^ t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6] ^ t[7];
    y[0] = temp ^ t[1] ^ t[4];
    y[1] = temp ^ t[2] ^ t[5];
    y[2] = temp ^ t[3] ^ t[6];
    y[3] = temp ^ t[0] ^ t[7];
    y[4] = temp ^ t[2] ^ t[3] ^ t[4];
    y[5] = temp ^ t[0] ^ t[3] ^ t[5];
    y[6] = temp ^ t[0] ^ t[1] ^ t[6];
    y[7] = temp ^ t[1] ^ t[2] ^ t[7];

    return ((u64)y[0] << 56) | ((u64)y[1] << 48) | ((u64)y[2] << 40) |
        ((u64)y[3] << 32) | ((u64)y[4] << 24) | ((u64)y[5] << 16) |
        ((u64)y[6] << 8) | (u64)y[7];
}
u64 Camellia::FL_Func(u64 FL_IN, u64 KE) {
    u32 x1, x2, k1, k2;

    x1 = FL_IN >> 32;
    x2 = FL_IN & MASK32;
    k1 = KE >> 32;
    k2 = KE & MASK32;

    x2 = x2 ^ (ROTL32(x1 & k1, 1));
    x1 = x1 ^ (x2 | k2);
    return ((u64)x1 << 32) | x2;
}
u64 Camellia::FLINV_Func(u64 FLINV_IN, u64 KE) {
    u32 y1, y2;
    u32 k1, k2;
    y1 = FLINV_IN >> 32;
    y2 = FLINV_IN & MASK32;
    k1 = KE >> 32;
    k2 = KE & MASK32;
    y1 = y1 ^ (y2 | k2);
    y2 = y2 ^ ROTL32(y1 & k1, 1);
    return ((u64)y1 << 32) | y2;
}
void Camellia::FormKA() {
    u64 L = MaskLeft(KL),
        R = MaskRight(KL);
    R = R ^ F_Func(L, C1);
    L = L ^ F_Func(R, C2);
    L = L ^ MaskLeft(KL);
    R = R ^ MaskRight(KL);
    R = R ^ F_Func(L, C3);
    L = L ^ F_Func(R, C4);
    KA[0] = L >> 32;
    KA[1] = L & 0xffffffff;
    KA[2] = R >> 32;
    KA[3] = R & 0xffffffff;
}
void Camellia::FormKB() {
    u64 L = ((u64(KA[0] ^ KR[0]) << 32) | (KA[1] ^ KA[1])),
        R = ((u64(KA[3] ^ KR[3]) << 32) | (KA[4] ^ KA[4]));
    R = R ^ F_Func(L, C5);
    L = L ^ F_Func(R, C6);
    KB[0] = L >> 32;
    KB[1] = L & 0xffffffff;
    KB[2] = R >> 32;
    KB[3] = R & 0xffffffff;
}
void Camellia::KeyGen128() {

    FormKA();
    //0
    k[0] = MaskLeft(KA);
    k[1] = MaskRight(KA);
    ROTL128(KA, 15);//15
    k[4] = MaskLeft(KA);
    k[5] = MaskRight(KA);
    ROTL128(KA, 15);//30
    ke[0] = MaskLeft(KA);
    ke[1] = MaskRight(KA);
    ROTL128(KA, 15);//45
    k[8] = MaskLeft(KA);
    ROTL128(KA, 15);//60
    k[10] = MaskLeft(KA);
    k[11] = MaskRight(KA);
    ROTL128(KA, 17);//77
    ROTL128(KA, 17);//94
    k[14] = MaskLeft(KA);
    k[15] = MaskRight(KA);
    ROTL128(KA, 17);//111
    kw[2] = MaskLeft(KA);
    kw[3] = MaskRight(KA);
    //0
    u128 tempKL = { KL[0], KL[1], KL[2], KL[3] };
    kw[0] = MaskLeft(tempKL);
    kw[1] = MaskRight(tempKL);
    ROTL128(tempKL, 15);//15
    k[2] = MaskLeft(tempKL);
    k[3] = MaskRight(tempKL);
    ROTL128(tempKL, 30);//45
    k[6] = MaskLeft(tempKL);
    k[7] = MaskRight(tempKL);
    ROTL128(tempKL, 15);//60
    k[9] = MaskRight(tempKL);
    ROTL128(tempKL, 17);//77
    ke[2] = MaskLeft(tempKL);
    ke[3] = MaskRight(tempKL);
    ROTL128(tempKL, 17);//94
    k[12] = MaskLeft(tempKL);
    k[13] = MaskRight(tempKL);
    ROTL128(tempKL, 17);//111
    k[16] = MaskLeft(tempKL);
    k[17] = MaskRight(tempKL);
}
void Camellia::KeyGen192_256() {

    FormKA();
    FormKB();

    k[0] = MaskLeft(KB);
    k[1] = MaskRight(KB);
    ROTL128(KB, 30);
    k[6] = MaskLeft(KB);
    k[7] = MaskRight(KB);
    ROTL128(KB, 30);
    k[14] = MaskLeft(KB);
    k[15] = MaskRight(KB);
    ROTL128(KB, 25);
    ROTL128(KB, 26);
    kw[2] = MaskLeft(KB);
    kw[3] = MaskRight(KB);

    
    ROTL128(KR, 15);
    k[2] = MaskLeft(KR);
    k[3] = MaskRight(KR);
    ROTL128(KR, 15);
    ke[0] = MaskLeft(KR);
    ke[1] = MaskRight(KR);
    ROTL128(KR, 30);
    k[12] = MaskLeft(KR);
    k[13] = MaskRight(KR);
    ROTL128(KR, 17);
    ROTL128(KR, 17);
    k[18] = MaskLeft(KR);
    k[19] = MaskRight(KR);

    kw[0] = MaskLeft(KL);
    kw[1] = MaskRight(KL);
    ROTL128(KL, 30);
    ROTL128(KL, 15);
    k[8] = MaskLeft(KL);
    k[9] = MaskRight(KL);
    ROTL128(KL, 15);
    ke[2] = MaskLeft(KL);
    ke[3] = MaskRight(KL);
    ROTL128(KL, 17);
    k[16] = MaskLeft(KL);
    k[17] = MaskRight(KL);
    ROTL128(KL, 17);
    ROTL128(KL, 17);
    k[22] = MaskLeft(KL);
    k[23] = MaskRight(KL);

    ROTL128(KA, 15);
    k[4] = MaskLeft(KA);
    k[5] = MaskRight(KA);
    ROTL128(KA, 30);
    k[10] = MaskLeft(KA);
    k[11] = MaskRight(KA);
    ROTL128(KA, 16);
    ROTL128(KA, 16);
    ke[4] = MaskLeft(KA);
    ke[5] = MaskRight(KA);
    ROTL128(KA, 17);
    k[20] = MaskLeft(KA);
    k[21] = MaskRight(KA);
}
u8 Camellia::OneBlockCamelliaEncrypt(u64 L, u64 R) {

    L ^= kw[0]; // Попереднє забілювання
    R ^= kw[1];
    int j = 0;
    for (size_t i = 0; i < 3; i++)
    {
        R ^= F_Func(L, k[j++]);
        L ^= F_Func(R, k[j++]);
    }

    L = FL_Func(L, ke[0]); // FL
    R = FLINV_Func(R, ke[1]); // FLINV

    for (size_t i = 0; i < 3; i++)
    {
        R ^= F_Func(L, k[j++]);
        L ^= F_Func(R, k[j++]);
    }
    L = FL_Func(L, ke[2]); // FL
    R = FLINV_Func(R, ke[3]); // FLINV

    for (size_t i = 0; i < 3; i++)
    {
        R ^= F_Func(L, k[j++]);
        L ^= F_Func(R, k[j++]);
    }
    
    if (KEY_MODE == 192 || KEY_MODE == 256) {
        L = FL_Func(L, ke[4]); // FL
        R = FLINV_Func(R, ke[5]); // FLINV
        for (size_t i = 0; i < 3; i++)
        {
            R ^= F_Func(L, k[j++]);
            L ^= F_Func(R, k[j++]);
        }
    }
    
    R ^= kw[2];
    L ^= kw[3];
    return BitToByte(R, L);
}
u8 Camellia::Camellia_ECB(int length, u8 text) {
    u8 encryptedText = new unsigned char[length + 1];
    int shift = 0;
    u8 left = new unsigned char[9],
        right = new unsigned char[9];

    bool isOneMoreBlock = length % BLOCK_128_BIT != 0;
    int blocksAmount = (length / BLOCK_128_BIT);

    for (size_t i = 0; i < blocksAmount; i++)
    {
        U8strncpy(left, text + shift, 8);
        shift += 8;
        U8strncpy(right, text + shift, 8);
        shift += 8;
        U8strncpy(encryptedText + shift - BLOCK_128_BIT, 
            OneBlockCamelliaEncrypt(ByteToBit(left), ByteToBit(right)), BLOCK_128_BIT);
    }
    if (isOneMoreBlock) {
        int lastBlockLength = length - BLOCK_128_BIT * blocksAmount;
        u64 leftU64 = 0, rightU64 = 0;
        if (lastBlockLength > 8) {
            U8strncpy(left, text + shift, 8);
            shift += 8;
            U8strncpy(right, text + shift, lastBlockLength - 8);
            shift += lastBlockLength - 8;
            rightU64 = ByteToBit(right);
            leftU64 = ByteToBit(left);
        }
        else {
            U8strncpy(left, text + shift, lastBlockLength);
            shift += lastBlockLength;
            rightU64 = 0;
            leftU64 = ByteToBit(left);
            leftU64 = leftU64 & (0xFFFFffffFFFFffff << (64 - lastBlockLength*8));
        }
        U8strncpy(encryptedText + shift - lastBlockLength,
            OneBlockCamelliaDecrypt(leftU64,rightU64), lastBlockLength);
    }

    encryptedText[length] = '\0';
    delete[] left, right;
    return encryptedText;
}
void Camellia::KeyInit(u8 key, int length)
{
    switch (length)
    {
    case KEY_128_BIT:
        for (size_t i = 0, j = 0; i < 4; i++, j = 4 * i)
            this->key128[i] = KL[i] = key[j] << 24 | key[j + 1] << 16 | key[j + 2] << 8 | key[j + 3];
        KeyGen128();
        return;
    case KEY_192_BIT:
        for (size_t i = 0, j = 0; i < 6; i++, j = 4 * i)
            this->key192[i] = key[j] << 24 | key[j + 1] << 16 | key[j + 2] << 8 | key[j + 3];
        cout << endl;
        KR[0] = key192[4];
        KR[1] = key192[5];
        KR[2] = ~key192[4];
        KR[3] = ~key192[5];
        for (size_t i = 0; i < 4; i++)
            this->KL[i] = key192[i];
        KeyGen192_256();
        KEY_MODE = 192;

        break;
    case KEY_256_BIT:
        for (size_t i = 0, j = 0; i < 8; i++, j = 4 * i)
            this->key256[i] = key[j] << 24 | key[j + 1] << 16 | key[j + 2] << 8 | key[j + 3];
        for (size_t i = 0; i < 4; i++)
            this->KL[i] = key256[i];

        KeyGen192_256();
        KEY_MODE = 256;
        break;
    }
 }
u8 Camellia::CamelliaEncrypt(u8 text, u8 key) {
    KeyInit(key, strlen((char*)key));
    int length = strlen((char*)text);
#if TEST_VECTOR
    length = 16;
#endif
    return Camellia_ECB(length, text);
}
u8 Camellia::OneBlockCamelliaDecrypt(u64 L, u64 R) {

    L ^= kw[2]; // Попереднє забілювання
    R ^= kw[3];
    int j = 17;
    if (KEY_MODE == 192 || KEY_MODE == 256) {
        j = 23;
        for (size_t i = 0; i < 3; i++)
        {
            R ^= F_Func(L, k[j--]);
            L ^= F_Func(R, k[j--]);
        }
        R = FLINV_Func(R, ke[4]); // FLINV
        L = FL_Func(L, ke[5]); // FL
    }

    for (size_t i = 0; i < 3; i++){
        R ^= F_Func(L, k[j--]);
        L ^= F_Func(R, k[j--]);
    }
    L = FL_Func(L, ke[3]); // FL
    R = FLINV_Func(R, ke[2]); // FLINV
    for (size_t i = 0; i < 3; i++) {
        R ^= F_Func(L, k[j--]);
        L ^= F_Func(R, k[j--]);
    }
    L = FL_Func(L, ke[1]); // FL
    R = FLINV_Func(R, ke[0]); // FLINV
    for (size_t i = 0; i < 3; i++) {
        R ^= F_Func(L, k[j--]);
        L ^= F_Func(R, k[j--]);
    }

    R ^= kw[0]; // Фінальне забілювання
    L ^= kw[1];
    return BitToByte(R, L);
}
u8 Camellia::CamelliaDecrypt(u8 cipherText, u8 key) {
    KeyInit(key, strlen((char*)key));
    int length = strlen((char*)cipherText);
#if TEST_VECTOR
    length = 16;
#endif
    int shift = 0;

    u8 left = new unsigned char[9],
        right = new unsigned char[9];
    u8 decryptedText = new unsigned char[length + 1];
    bool isOneMoreBlock = length % 16 != 0;
    int blocksAmount = length / BLOCK_128_BIT;
    blocksAmount += isOneMoreBlock;
    for (size_t i = 0; i < blocksAmount; i++)
    {
        U8strncpy(left, cipherText + shift, 8);
        shift += 8;
        U8strncpy(right, cipherText + shift, 8);
        shift += 8;
        U8strncpy(decryptedText + shift - BLOCK_128_BIT,
            OneBlockCamelliaDecrypt(ByteToBit(left), ByteToBit(right)), BLOCK_128_BIT);
    }
    decryptedText[length] = '\0';
    return decryptedText;
}

void main() {
    Camellia* cipher = new Camellia(),
        *cipher2 = new Camellia();
    u8 initialText, encryptedText, decryptedText;
#if TEST_VECTOR
    uint8_t testTextVector[16] = { 0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00, 
                                    0x00,0x00,0x00,0x00
    };
    uint8_t testKeyVector[16] = { 0x80,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00
    };
    ConsoleHexOutput(testTextVector, "Initial text: ");
    encryptedText = cipher->CamelliaEncrypt(testTextVector, testKeyVector);
    ConsoleHexOutput(encryptedText, "Encrypted text: ");
    decryptedText = cipher2->CamelliaDecrypt(encryptedText, testKeyVector);
    ConsoleHexOutput(decryptedText, "Decrypted  text: ");
    delete cipher, cipher2;
    return;
#endif

    initialText = (u8)"yehorkovalov2001";
    ConsoleHexOutput(initialText, "Initial text: ");
    
    encryptedText = cipher->CamelliaEncrypt(initialText, (u8)"555544443333222211110000");
    ConsoleHexOutput(encryptedText, "Encrypted text: ");
    
    decryptedText = cipher2->CamelliaDecrypt(encryptedText, (u8)"555544443333222211110000");
    ConsoleHexOutput(decryptedText, "Decrypted  text: ");
    delete cipher, cipher2;
}


