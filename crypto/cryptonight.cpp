#include "cryptonight.hpp"

#include "aes_data.hpp"
#include "groestl.h"
#include "keccak.h"
#include "portability.hpp"
#include <assert.h>
#include <cstdlib>

#ifdef __linux
#include <sys/mman.h>
#endif

extern "C" {
#include "blake256.h"
#include "jh.h"
#include "skein.h"
}

#include <iomanip>
#include <iostream>
#include <sstream>

using namespace cryptonight;

static uint8_t oaes_gf_8[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t oaes_sub_byte_value[16][16] = {
    //      0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    a,    b,    c,    d,    e,    f,
    /*0*/ {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    /*1*/ {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    /*2*/ {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    /*3*/ {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    /*4*/ {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    /*5*/ {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    /*6*/ {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    /*7*/ {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    /*8*/ {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    /*9*/ {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    /*a*/ {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    /*b*/ {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    /*c*/ {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    /*d*/ {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    /*e*/ {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    /*f*/ {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
};

static void oaes_sub_byte(uint8_t *byte)
{
  size_t _y = (*byte >> 4) & 0x0f;
  size_t _x = *byte & 0x0f;
  *byte     = oaes_sub_byte_value[_y][_x];
}

static void oaes_word_rot_left(uint8_t word[4])
{
  uint8_t _temp[4];
  memcpy(_temp, word + 1, 3);
  _temp[3] = word[0];
  memcpy(word, _temp, 4);
}

void Cryptonight::initRoundKeys(size_t offset)
{
  // the first _ctx->key->data_len are a direct copy
  memcpy(m_keys, m_keccak + offset, AES_KEY_SIZE);

  // apply ExpandKey algorithm for remainder
  static const size_t OAES_RKEY_LEN = 4;
  static const size_t OAES_COL_LEN  = 4;
  static const size_t BASE          = AES_KEY_SIZE / OAES_RKEY_LEN;
  for (size_t i = BASE; i < sizeof(m_keys) / OAES_RKEY_LEN; i++)
  {
    uint8_t *this_key = m_keys + i * OAES_RKEY_LEN;
    memcpy(this_key, m_keys + (i - 1) * OAES_RKEY_LEN, OAES_COL_LEN);

    // transform key column
    if (i % 8 == 0)
    {
      oaes_word_rot_left(this_key);
      for (size_t j = 0; j < OAES_COL_LEN; j++)
        oaes_sub_byte(this_key + j);
      this_key[0] = this_key[0] ^ oaes_gf_8[i / BASE - 1];
    }
    else if (i % BASE == 4)
    {
      for (size_t j = 0; j < OAES_COL_LEN; j++)
        oaes_sub_byte(this_key + j);
    }
    for (size_t j = 0; j < OAES_COL_LEN; j++)
    {
      m_keys[i * OAES_RKEY_LEN + j] ^= m_keys[i * OAES_RKEY_LEN - AES_KEY_SIZE + j];
    }
  }
}

array::type<uint8_t, 32> &Cryptonight::roundKey(size_t i)
{
  return array::of<32>(&m_keys[i * AES_KEY_SIZE]);
}

static inline void SubAndShiftAndMixAddRound(uint8_t *out8, uint8_t *state, uint8_t *aesenckey8)
{
  uint32_t *out32       = reinterpret_cast<uint32_t *>(out8);
  uint32_t *aesenckey32 = reinterpret_cast<uint32_t *>(aesenckey8);
  out32[0] = (TestTable1[state[0]]) ^ (TestTable2[state[5]]) ^ (TestTable3[state[10]]) ^ (TestTable4[state[15]]) ^
             aesenckey32[0];
  out32[1] = (TestTable4[state[3]]) ^ (TestTable1[state[4]]) ^ (TestTable2[state[9]]) ^ (TestTable3[state[14]]) ^
             aesenckey32[1];
  out32[2] = (TestTable3[state[2]]) ^ (TestTable4[state[7]]) ^ (TestTable1[state[8]]) ^ (TestTable2[state[13]]) ^
             aesenckey32[2];
  out32[3] = (TestTable2[state[1]]) ^ (TestTable3[state[6]]) ^ (TestTable4[state[11]]) ^ (TestTable1[state[12]]) ^
             aesenckey32[3];
}

static inline void SubAndShiftAndMixAddRoundInPlace(uint8_t *out, uint8_t *AesEncKey)
{
  alignas(16) uint8_t state[16];
  memcpy(state, out, sizeof(state));
  SubAndShiftAndMixAddRound(out, state, AesEncKey);
}

void Cryptonight::explodeScratchPad()
{
  alignas(16) uint8_t text[INIT_SIZE_BYTE];
  memcpy(text, m_keccak + 64, sizeof(text));

  for (size_t i = 0; i < MEMORY / INIT_SIZE_BYTE; ++i)
  {
    for (size_t j = 0; j < Cryptonight::INIT_SIZE_BLOCK; ++j)
    {
      for (size_t k = 0; k < 10; ++k)
      {
        SubAndShiftAndMixAddRoundInPlace(text + j * Cryptonight::AES_BLOCK_SIZE, &m_keys[k * 16]);
      }
    }
    memcpy(&m_scratchpad[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
  }
}

std::tuple<Cryptonight::stack_type, Cryptonight::stack_type> Cryptonight::initAandB()
{
  stack_type a, b;
  for (size_t i = 0; i < AES_BLOCK_SIZE; ++i)
  {
    a.v[i] = m_keccak[i] ^ m_keccak[i + 32];
    b.v[i] = m_keccak[i + 16] ^ m_keccak[i + 48];
  }
  return std::make_tuple(a, b);
}

inline void xor_blocks_dst(const uint8_t *a, const uint8_t *b, uint8_t *dst)
{
  for (size_t i = 0; i < Cryptonight::AES_BLOCK_SIZE; ++i)
    dst[i]      = a[i] ^ b[i];
}

uint64_t Cryptonight::mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi)
{
  // multiplier   = ab = a * 2^32 + b
  // multiplicand = cd = c * 2^32 + d
  // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
  uint64_t a = hi_dword(multiplier);
  uint64_t b = lo_dword(multiplier);
  uint64_t c = hi_dword(multiplicand);
  uint64_t d = lo_dword(multiplicand);

  uint64_t ac = a * c;
  uint64_t ad = a * d;
  uint64_t bc = b * c;
  uint64_t bd = b * d;

  uint64_t adbc       = ad + bc;
  uint64_t adbc_carry = adbc < ad ? 1 : 0;

  // multiplier * multiplicand = product_hi * 2^64 + product_lo
  uint64_t product_lo       = bd + (adbc << 32);
  uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
  *product_hi               = ac + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;
  assert(ac <= *product_hi);

  return product_lo;
}

inline void Cryptonight::mul_sum_xor_dst(const uint8_t *a, uint8_t *c, uint8_t *dst)
{
  uint64_t hi;
  uint64_t lo = mul128(get64(a, 0), get64(dst, 0), &hi);

  lo += get64(c, 1);
  hi += get64(c, 0);

  set64(c, 0, get64(dst, 0) ^ hi);
  set64(c, 1, get64(dst, 1) ^ lo);
  set64(dst, 0, hi);
  set64(dst, 1, lo);
}

void Cryptonight::iteration(size_t total)
{
  stack_type a, b, c;
  std::tie(a, b) = initAandB();

  for (size_t i = 0; i < total; ++i)
  {
    SubAndShiftAndMixAddRound(c.v, &m_scratchpad[stateIndex(a)], a.v);
    xor_blocks_dst(c.v, b.v, &m_scratchpad[stateIndex(a)]);
    mul_sum_xor_dst(c.v, a.v, &m_scratchpad[stateIndex(c)]);
    memcpy(b.v, c.v, sizeof(c.v));
  }
}

void Cryptonight::initKeccak(const uint8_t *in, size_t len)
{
  // Can't seem to use CryptoPP for this, looks like some
  // confusion between the creation of Monero and the acceptance
  // of SHA3 / Keccak in FIPS.
  keccak1600(in, len, m_keccak);
}

void Cryptonight::iterations()
{
  iteration(ITER / 2);
}

static inline void xor_blocks(uint8_t *a, const uint8_t *b)
{
  ((uint64_t *)a)[0] ^= ((uint64_t *)b)[0];
  ((uint64_t *)a)[1] ^= ((uint64_t *)b)[1];
}

void Cryptonight::implodeScratchPad()
{
  for (size_t i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
  {
    for (size_t j = 0; j < INIT_SIZE_BLOCK; j++)
    {
      uint8_t *block = m_keccak + 64 + j * AES_BLOCK_SIZE;
      xor_blocks(block, &m_scratchpad[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
      for (size_t k = 0; k < 10; ++k)
      {
        SubAndShiftAndMixAddRoundInPlace(block, &m_keys[k * AES_BLOCK_SIZE]);
      }
    }
  }
}

void Cryptonight::rerunKeccak()
{
  for (size_t i = 0; i < sizeof(m_keccak) / sizeof(uint64_t); ++i)
    set64(m_keccak, i, swab64(get64(m_keccak, i)));
  keccakf(reinterpret_cast<uint64_t *>(m_keccak), 24);
  for (size_t i = 0; i < sizeof(m_keccak) / sizeof(uint64_t); ++i)
    set64(m_keccak, i, swab64(get64(m_keccak, i)));
}

Cryptonight::HashType Cryptonight::hashType() const
{
  return HashType(m_keccak[0] & 3);
}

array::type<uint8_t, 64> &Cryptonight::calculateResult()
{
  switch (hashType())
  {
  case BLAKE256:
    blake256_hash(m_result, m_keccak, 200);
    break;
  case GROESTL:
    groestl(m_keccak, 200 * 8, m_result);
    break;
  case JH:
    jh_hash(32 * 8, m_keccak, 200 * 8, m_result);
    break;
  case SKEIN:
    skein_hash(32 * 8, m_keccak, 200 * 8, m_result);
    break;
  }
  return array::of<64>(m_result);
}

array::type<uint8_t, 64> &Cryptonight::calculateResult(const uint8_t *in, size_t len)
{
  std::chrono::steady_clock::time_point times[10];
  size_t stage   = 0;
  times[stage++] = std::chrono::steady_clock::now();
  initKeccak(in, len);
  times[stage++] = std::chrono::steady_clock::now();
  initRoundKeys(0);
  times[stage++] = std::chrono::steady_clock::now();
  explodeScratchPad();
  initAandB();
  times[stage++] = std::chrono::steady_clock::now();
  iterations();
  times[stage++] = std::chrono::steady_clock::now();
  initRoundKeys(32);
  times[stage++] = std::chrono::steady_clock::now();
  implodeScratchPad();
  times[stage++] = std::chrono::steady_clock::now();
  rerunKeccak();
  times[stage++] = std::chrono::steady_clock::now();
  auto &r        = calculateResult();
  times[stage++] = std::chrono::steady_clock::now();
  for (size_t i = 0; i < 9; ++i)
  {
    m_stage_times[i] += times[i + 1] - times[i];
  }
  return r;
}

Cryptonight::Cryptonight() : m_scratchpad(nullptr, ::free)
{
  for (auto &x : m_stage_times)
    x = std::chrono::steady_clock::duration(0);
  void *memory;
#ifndef __sparc
  if (::posix_memalign(&memory, AES_BLOCK_SIZE, MEMORY) != 0) throw std::bad_alloc();
#else
  if ((memory = malloc(MEMORY)) == nullptr) throw std::bad_alloc();
#endif
  m_scratchpad.reset(reinterpret_cast<uint8_t *>(memory));
#ifdef __linux
  madvise(memory, MEMORY, MADV_RANDOM | MADV_WILLNEED | MADV_HUGEPAGE);
  if (!geteuid()) mlock(memory, MEMORY);
#endif
}
