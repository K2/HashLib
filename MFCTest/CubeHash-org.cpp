
#include "stdafx.h"
#include "CubeHash-org.h"

#pragma warning(disable : 4101)
#pragma warning(disable : 4244)

namespace CubeHashOrg
{

#define CUBEHASH_ROUNDS 16
#define CUBEHASH_BLOCKBYTES 32

#define ROTATE(a,b) (((a) << (b)) | ((a) >> (32 - b)))

static void transform(hashState *state)
{
  int i;
  int r;
  myuint32 y[16];

  for (r = 0;r < CUBEHASH_ROUNDS;++r) {
    for (i = 0;i < 16;++i) state->x[i + 16] += state->x[i];
    for (i = 0;i < 16;++i) y[i ^ 8] = state->x[i];
    for (i = 0;i < 16;++i) state->x[i] = ROTATE(y[i],7);
    for (i = 0;i < 16;++i) state->x[i] ^= state->x[i + 16];
    for (i = 0;i < 16;++i) y[i ^ 2] = state->x[i + 16];
    for (i = 0;i < 16;++i) state->x[i + 16] = y[i];
    for (i = 0;i < 16;++i) state->x[i + 16] += state->x[i];
    for (i = 0;i < 16;++i) y[i ^ 4] = state->x[i];
    for (i = 0;i < 16;++i) state->x[i] = ROTATE(y[i],11);
    for (i = 0;i < 16;++i) state->x[i] ^= state->x[i + 16];
    for (i = 0;i < 16;++i) y[i ^ 1] = state->x[i + 16];
    for (i = 0;i < 16;++i) state->x[i + 16] = y[i];
  }
}

HashReturn Init(hashState *state, int hashbitlen)
{
  int i;
  int j;

  if (hashbitlen < 8) return BAD_HASHBITLEN;
  if (hashbitlen > 512) return BAD_HASHBITLEN;
  if (hashbitlen != 8 * (hashbitlen / 8)) return BAD_HASHBITLEN;

  state->hashbitlen = hashbitlen;
  for (i = 0;i < 32;++i) state->x[i] = 0;
  state->x[0] = hashbitlen / 8;
  state->x[1] = CUBEHASH_BLOCKBYTES;
  state->x[2] = CUBEHASH_ROUNDS;
  for (i = 0;i < 10;++i) transform(state);
  state->pos = 0;
  return SUCCESS;
}

HashReturn Update(hashState *state, const BitSequence *data,
                  DataLength databitlen)
{
  /* caller promises us that previous data had integral number of bytes */
  /* so state->pos is a multiple of 8 */

  while (databitlen >= 8) {
    myuint32 u = *data;
    u <<= 8 * ((state->pos / 8) % 4);
    state->x[state->pos / 32] ^= u;
    data += 1;
    databitlen -= 8;
    state->pos += 8;
    if (state->pos == 8 * CUBEHASH_BLOCKBYTES) {
      transform(state);
      state->pos = 0;
    }
  }
  if (databitlen > 0) {
    myuint32 u = *data;
    u <<= 8 * ((state->pos / 8) % 4);
    state->x[state->pos / 32] ^= u;
    state->pos += databitlen;
  }
  return SUCCESS;
}

HashReturn Final(hashState *state, BitSequence *hashval)
{
  int i;
  myuint32 u;

  u = (128 >> (state->pos % 8));
  u <<= 8 * ((state->pos / 8) % 4);
  state->x[state->pos / 32] ^= u;
  transform(state);
  state->x[31] ^= 1;
  for (i = 0;i < 10;++i) transform(state);
  for (i = 0;i < state->hashbitlen / 8;++i) hashval[i] = state->x[i / 4] >> (8 * (i % 4));

  return SUCCESS;
}

HashReturn Hash(int hashbitlen, const BitSequence *data,
                DataLength databitlen, BitSequence *hashval)
{
  hashState state;
  if (Init(&state,hashbitlen) != SUCCESS) return BAD_HASHBITLEN;
  Update(&state,data,databitlen);
  return Final(&state,hashval);
}
}