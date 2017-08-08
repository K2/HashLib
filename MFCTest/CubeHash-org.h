
#pragma once

namespace CubeHashOrg
{
typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

typedef unsigned int myuint32; /* must be exactly 32 bits */

typedef struct {
  int hashbitlen;
  int pos; /* number of bits read into x from current block */
  myuint32 x[32];
} hashState;

HashReturn Init(hashState *state, int hashbitlen);

HashReturn Update(hashState *state, const BitSequence *data,
                  DataLength databitlen);

HashReturn Final(hashState *state, BitSequence *hashval);

HashReturn Hash(int hashbitlen, const BitSequence *data,
                DataLength databitlen, BitSequence *hashval);
}
