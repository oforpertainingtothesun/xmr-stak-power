#include "cryptonight_sparc.hpp"

#include <cstring>

using namespace cryptonight;

void CryptonightSparc::explodeScratchPad()
{
  uint8_t text[INIT_SIZE_BYTE];
  memcpy(text, m_keccak + 64, sizeof(text));

  for (size_t i = 0; i < MEMORY / INIT_SIZE_BYTE; ++i)
  {
    for (size_t j = 0; j < Cryptonight::INIT_SIZE_BLOCK ; ++j)
    {
      uint64_t *this_text = reinterpret_cast<uint64_t*>(&text[j * Cryptonight::AES_BLOCK_SIZE]);
      uint64_t *keys = reinterpret_cast<uint64_t *>(m_keys);
      uint64_t out0(this_text[0]);
      uint64_t out1(this_text[1]);
      for (size_t k = 0; k < 10; ++k)
      {
        uint64_t key0(keys[k * 2]), key1(keys[k * 2 + 1]);
        uint64_t in0 = out0;
        __asm__("aes_eround01 %1, %2, %3, %0" : "=f"(out0) : "f"(key0), "f"(in0), "f"(out1));
        __asm__("aes_eround23 %1, %2, %3, %0" : "=f"(out1) : "f"(key1), "f"(in0), "f"(out1));
      }
      this_text[0] = out0;
      this_text[1] = out1;
    }
    memcpy(&m_scratchpad[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
  }
}

uint64_t CryptonightSparc::mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi)
{
    uint64_t hi;
    __asm__("umulxhi %1, %2, %0" : "=g"(hi) : "g"(multiplier), "g"(multiplicand));
    *product_hi = hi;
    return multiplier * multiplicand;
}

void CryptonightSparc::iteration(size_t total)
{
  stack_type ap, bp;
  auto p = initAandB();
  memcpy(&ap, &std::get<0>(p), sizeof(ap));
  memcpy(&bp, &std::get<1>(p), sizeof(bp));

  uint64_t av0 = ap.v[0], av1 = ap.v[1];
  uint64_t bv0 = bp.v[0], bv1 = bp.v[1];
  uint64_t cv0, cv1;
  for (size_t i = 0; i < total; ++i)
  {
    uint64_t *state64(reinterpret_cast<uint64_t *>(&m_scratchpad[stateIndex(&av0)]));
    uint64_t state64_0 = state64[0];
    uint64_t state64_1 = state64[1];
    __asm__("aes_eround01 %1, %2, %3, %0" : "=f"(cv0) : "f"(av0), "f"(state64_0), "f"(state64_1));
    __asm__("aes_eround23 %1, %2, %3, %0" : "=f"(cv1) : "f"(av1), "f"(state64_0), "f"(state64_1));

    state64[0] = cv0 ^ bv0;
    state64[1] = cv1 ^ bv1;

    uint64_t *dst         = reinterpret_cast<uint64_t *>(&m_scratchpad[stateIndex(&cv0)]);
    uint64_t multiplier   = swab64(cv0);
    uint64_t multiplicand = swab64(dst[0]);
    uint64_t lo           = multiplier * multiplicand, hi;
    __asm__("umulxhi %1, %2, %0" : "=g"(hi) : "g"(multiplier), "g"(multiplicand));

    lo += swab64(av1);
    hi += swab64(av0);

    lo = swab64(lo);
    hi = swab64(hi);

    av0 = dst[0] ^ hi;
    av1 = dst[1] ^ lo;
    dst[0] = hi;
    dst[1] = lo;
    bv0 = cv0;
    bv1 = cv1;
  }
}

void CryptonightSparc::implodeScratchPad()
{
  for (size_t i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
  {
    for (size_t j = 0; j < INIT_SIZE_BLOCK; j++)
    {
      uint64_t *block   = reinterpret_cast<uint64_t *>(m_keccak + 64 + j * AES_BLOCK_SIZE);
      uint64_t *scratch = reinterpret_cast<uint64_t *>(&m_scratchpad[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);

      uint64_t out0 = block[0] ^ scratch[0];
      uint64_t out1 = block[1] ^ scratch[1];

      uint64_t *keys = reinterpret_cast<uint64_t *>(m_keys);
      for (size_t k = 0; k < 10; ++k)
      {
        uint64_t key0(keys[k * 2]), key1(keys[k * 2 + 1]);
        uint64_t in0 = out0;
        __asm__("aes_eround01 %1, %2, %3, %0" : "=f"(out0) : "f"(key0), "f"(in0), "f"(out1));
        __asm__("aes_eround23 %1, %2, %3, %0" : "=f"(out1) : "f"(key1), "f"(in0), "f"(out1));
      }
      block[0] = out0;
      block[1] = out1;
    }
  }
}

bool CryptonightSparc::detect()
{
  return true;
}
