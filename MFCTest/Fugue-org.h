
#pragma once

#pragma warning(disable : 4244)
#pragma warning(disable : 4005)

namespace FugueOrg
{
    #ifdef __unix__
#define INLINE inline
#else
#define INLINE __inline
#endif

#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && BYTE_ORDER == BIG_ENDIAN
#define HO2BE_8(_x)  (_x)
#define HO2BE_4(_x)  (_x)
#else
#define HO2BE_8(_x)  ((_x<<56)|((_x<<40)&0xff000000000000ull)|((_x<<24)&0xff0000000000ull)|((_x<<8)&0xff00000000ull)|\
                     ((_x>>8)&0xff000000ull)|((_x>>24)&0xff0000ull)|((_x>>40)&0xff00ull)|(_x>>56))
#define HO2BE_4(_x)  ((_x<<24)|((_x<<8)&0xff0000)|((_x>>8)&0xff00)|(_x>>24))
#endif

#if defined(__WORDSIZE) && __WORDSIZE == 64
typedef unsigned long       ulong;
typedef unsigned int        uint32;
#else
typedef unsigned long long  ulong;
typedef unsigned long       uint32;
#endif
typedef unsigned short      uint16;
typedef unsigned char       uint8;

typedef union {
    uint32    d;
    uint8     b[4];
    }         hash32_s;
typedef hash32_s* hash32_p;

typedef struct {
    int        n;   /* columns in output */
    int        s;   /* columns in state */
    int        k;   /* number of smix's per TIX or round */
    int        r;   /* number of G1 rounds in final part */
    int        t;   /* number of G2 rounds in final part */
    }          hashCfg;

typedef struct {
    int        hashbitlen;
    hashCfg*   Cfg;
    int        Base;
    hash32_s   State[36];
    uint32     Partial[1];
    ulong     TotalBits;
    }          hashState;

typedef uint8  BitSequence;
typedef ulong DataLength;
typedef enum   { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

#if defined(__WORDSIZE) && __WORDSIZE == 64
typedef unsigned int uint_32t;
typedef unsigned long uint_64t;
#else
typedef unsigned long uint_32t;
typedef unsigned long long uint_64t;
#endif
typedef unsigned char uint_8t;

//#define ODD_PARITY

#define brot(x,n)   (((uint_32t)(x) <<  n) | ((uint_32t)(x) >> ((32 - n) & 31)))
#define brot64(x,n)   (((uint_64t)(x) <<  ((64 - n) & 63)) | ((uint_64t)(x) >> n))
#define shift_right64(x,n) ((uint_64t)(x) >> n)
#define shift_left64(x,n) ((uint_64t)(x) << n)

#define to_byte(x) ((x) & 0xff)
//#define to_byte(x) ((unsigned char) (x))

#define to_nib(x)  ((x) & 0xfc)
#define bval(x,n)   to_byte((x) >> (8 * (n)))

#define bval0(x) ((x) &0xff)
#define bval1(x) (((x) & 0xff00) >>8)
#define bval2(x) to_byte((x) >> 16)
#define bval3(x) to_byte((x) >>24)

//#define bval(x,n) bval##n(x)

#define bval4(x,n)  (n==0 ? ((x<<2) & 0x3fc): n==1? ((x>>6) & 0x3fc) : n==2 ? ((x>>14)& 0x3fc) : ((x>>22)&0x3fc))
#define nibval(x,n)     to_nib((x) >> (8 * (n)))
#define bytes2word(b0, b1, b2, b3)  \
        (((uint_32t)(b3) << 24) | ((uint_32t)(b2) << 16) | ((uint_32t)(b1) << 8) | (b0))

#define words2dword(d0,d1) \
  (((uint_64t) (d1)<<32) | (d0))

//#define SIXTEEN_TABLES

#define sbox(w) \
    w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),\
    w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76),\
    w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0),\
    w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0),\
    w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc),\
    w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15),\
    w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a),\
    w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75),\
    w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0),\
    w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84),\
    w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b),\
    w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf),\
    w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85),\
    w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8),\
    w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5),\
    w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2),\
    w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17),\
    w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73),\
    w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88),\
    w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb),\
    w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c),\
    w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79),\
    w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9),\
    w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08),\
    w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6),\
    w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a),\
    w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e),\
    w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e),\
    w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94),\
    w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf),\
    w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68),\
    w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16)

#define h0(x)   (x)

//this is the new mix for the hash funciton , replacing AES 2113 by new 1174 -CSJ
#define u0(p)   bytes2word(p, p, f7(p), f4(p))
#define u1(p)   bytes2word(f4(p),  p, p, f7(p))
#define u2(p)   bytes2word(f7(p), f4(p), p, p)
#define u3(p)   bytes2word(p, f7(p), f4(p), p)

#define u02(p)  words2dword(u0(p),u2(p))
#define u13(p)  words2dword(u1(p),u3(p))
#define u20(p)  words2dword(u2(p),u0(p))
#define u31(p)  words2dword(u3(p),u1(p))


//note rotations are in the proper direction -CSJ
#define u01(p)  words2dword(u0(p),u3(p))
#define u12(p)  words2dword(u1(p),u0(p))
#define u23(p)  words2dword(u2(p),u1(p))
#define u30(p)  words2dword(u3(p),u2(p))

#define WPOLY   0x011b

#define f2(x)   ((x<<1) ^ (((x>>7) & 1) * WPOLY))
#define f4(x)   ((x<<2) ^ (((x>>6) & 1) * WPOLY) ^ (((x>>6) & 2) * WPOLY))
#define f8(x)   ((x<<3) ^ (((x>>5) & 1) * WPOLY) ^ (((x>>5) & 2) * WPOLY) \
                        ^ (((x>>5) & 4) * WPOLY))
#define f3(x)   (f2(x) ^ x)
#define f7(x)   (f4(x)^ f2(x) ^x)   //this is new -CSJ

#define d_16(tab,b,e,f,g,h) static const uint_32t tab[4][256*4] =\
{ {sbox(e), sbox(f),sbox(g),sbox(h)},\
  {sbox(f), sbox(g),sbox(h), sbox(e)},\
  {sbox(h), sbox(g),sbox(h), sbox(e)},\
  {sbox(e), sbox(f),sbox(g), sbox(h)}}


#if defined(SIXTEEN_TABLES)
d_16(aes_style_table, u0, u1, u2, u3);
#else
#ifdef ODD_PARITY
static const uint_64t aes_style_table[4][256] = {{sbox(u01)}, {sbox(u12)}, {sbox(u23)}, {sbox(u30)} };
#else
static const uint_64t aes_style_table[4][256] = {{sbox(u02)}, {sbox(u13)}, {sbox(u20)}, {sbox(u31)} };
#endif
#endif

HashReturn Init (hashState *state, int hashbitlen);
HashReturn Update (hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Final (hashState *state, BitSequence *hashval);
HashReturn Hash (int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

uint32 Init_Fugue (hashState *state, int hashbitlen);
uint32 Load_Fugue (hashState *state, int hashbitlen, const uint32 *iv_key, int ivwordlen);
uint32 Next_Fugue (hashState *state, const uint32 *data, ulong datawordlen);
uint32 Done_Fugue (hashState *state, uint32 *hashval, int *hashwordlen);

int fugue_update_256 (hashState *hs, const char *in, uint_64t len);
int fugue_final_256  (hashState *hs, char *out);
int fugue_update_384 (hashState *hs, const char *in, uint_64t len);
int fugue_final_384  (hashState *hs, char *out);
int fugue_update_512 (hashState *hs, const char *in, uint_64t len);
int fugue_final_512  (hashState *hs, char *out);
}
