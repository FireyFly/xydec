#include <stdint.h>
#include <stdlib.h>

#include "pkx.h"

struct pokemon *decode_pokemon(struct pokemon_raw *data) {
  struct pokemon *res = malloc(sizeof(struct pokemon));
  struct pokemon_raw *res_ = (void *) res;

  res->enc_key  = data->enc_key;
  res->un1      = data->un1;
  res->checksum = data->checksum;

  /* Prepare block permutation */
  int perm,
      shift_value = ((data->enc_key & 0x3E000) >> 0xD) % 24;
  switch (shift_value) {
    case 0x00: perm = 0xABCD; break;
    case 0x01: perm = 0xABDC; break;
    case 0x02: perm = 0xACBD; break;
    case 0x03: perm = 0xACDB; break;
    case 0x04: perm = 0xADBC; break;
    case 0x05: perm = 0xADCB; break;
    case 0x06: perm = 0xBACD; break;
    case 0x07: perm = 0xBADC; break;
    case 0x08: perm = 0xBCAD; break;
    case 0x09: perm = 0xBCDA; break;
    case 0x0A: perm = 0xBDAC; break;
    case 0x0B: perm = 0xBDCA; break;
    case 0x0C: perm = 0xCABD; break;
    case 0x0D: perm = 0xCADB; break;
    case 0x0E: perm = 0xCBAD; break;
    case 0x0F: perm = 0xCBDA; break;
    case 0x10: perm = 0xCDAB; break;
    case 0x11: perm = 0xCDBA; break;
    case 0x12: perm = 0xDABC; break;
    case 0x13: perm = 0xDACB; break;
    case 0x14: perm = 0xDBAC; break;
    case 0x15: perm = 0xDBCA; break;
    case 0x16: perm = 0xDCAB; break;
    case 0x17: perm = 0xDCBA; break;
  }

  uint16_t *targets[4];
  for (int i=0; i<4; i++) {
    int idx = ((perm >> 4*(3 - i)) & 0xF) - 0xA;
    targets[i] = res_->block[idx];
  }

  /* Prepare LCG */
  uint32_t lcg_state = data->enc_key; /* Seed the PRNG */

  /* Do the decryption */
  for (int i=0; i<4; i++) {
    for (int j=0; j<28; j++) {
      lcg_state = 0x41C64E6D * lcg_state + 0x6073;
      uint16_t rand = lcg_state >> 16; /* upper 16 bits */
      targets[i][j] = data->block[i][j] ^ rand;
    }
  }

  return res;
}
