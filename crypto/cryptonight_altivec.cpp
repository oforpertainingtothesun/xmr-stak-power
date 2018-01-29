#include "cryptonight_altivec.hpp"

#include "aes_data.hpp"
#include <altivec.h>
#include <string.h>

using namespace cryptonight;

using vec_type = vector unsigned long long;

using simple_type = uint64_t;
using simple_vec = simple_type[2];

template <typename T> inline vec_type load(T *addr)
{
  return (vec_type)vec_vsx_ld(0, reinterpret_cast<uint8_t*>(addr));
}

template <typename T> inline void store(T *addr, vec_type &value)
{
  vec_vsx_st((vector unsigned char) value, 0, reinterpret_cast<uint8_t*>(addr));
}

uint64_t CryptonightAltivec::mul128(uint64_t a, uint64_t b, uint64_t *hi)
{
  simple_vec t2;
  __asm__("mulld  %0, %1, %2" : "=r" (t2[1]) : "r" (a), "r" (b));
  __asm__("mulhdu %0, %1, %2" : "=r" (t2[0]) : "r" (a), "r" (b));
  *hi = t2[0];
  return t2[1];
}

vec_type altivec_swab(vec_type src)
{
  using vec8 = __vector unsigned char;
  const vec8 mask = {7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8};
  const vec8 zero = {0};
  return (vec_type) vec_perm((vec8) src, zero, mask);
}

void CryptonightAltivec::iteration(size_t total)
{
  auto tpl = initAandB();

  vec_type _a = load(std::get<0>(tpl).v);
  vec_type _b = load(std::get<1>(tpl).v);
  vec_type _c;

  for(size_t i = 0 ; i < total; ++i)
  {
    simple_vec t0;
    store(t0, _a);
    auto index0 = stateIndex(t0);
    _c = load(&m_scratchpad[index0]);
    _c = __builtin_crypto_vcipher(_c, _a);

    simple_vec t1;
    store(t1, _c);
    auto index1 = stateIndex(t1);
    __builtin_prefetch(&m_scratchpad[index1]);

    _b = vec_xor(_b, _c);
    store(&m_scratchpad[index0], _b);

    uint64_t *p = (uint64_t*)(&m_scratchpad[index1]);

    simple_vec t2;
    __asm__("mulld  %0, %1, %2" : "=r" (t2[1]) : "r" (swab64(t1[0])), "r" (swab64(p[0])));
    __asm__("mulhdu %0, %1, %2" : "=r" (t2[0]) : "r" (swab64(t1[0])), "r" (swab64(p[0])));
    _b = load(p);

    vec_type _r = load(t2);
    _a = altivec_swab(_a);
    _a = vec_add(_a, _r);
    _a = altivec_swab(_a);

    store(p, _a);
    _a = vec_xor(_a, _b);
    _b = _c;
  }
}

void CryptonightAltivec::explodeScratchPad()
{
  uint8_t text[INIT_SIZE_BYTE];
  memcpy(text, m_keccak + 64, sizeof(text));

  for(size_t i = 0 ; i < MEMORY / INIT_SIZE_BYTE; ++i)
  {
    for(size_t j = 0; j < Cryptonight::INIT_SIZE_BLOCK; ++j)
    {
      vec_type d = load(text + j * Cryptonight::AES_BLOCK_SIZE);
      vec_type *keys = (vec_type*)(&m_keys);
      for(size_t k = 0 ; k < 10 ; ++k)
      {
        d = __builtin_crypto_vcipher(d, *keys++);
      }
      store(text + j * Cryptonight::AES_BLOCK_SIZE, d);
    }
    memcpy(m_scratchpad.get() + i * INIT_SIZE_BYTE, text, INIT_SIZE_BYTE);
  }
}

void CryptonightAltivec::implodeScratchPad()
{
  for(size_t i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
  {
    vec_type *keys = (vec_type*)(&m_keys);
    vec_type *x    = (vec_type*)(&m_scratchpad[i * INIT_SIZE_BYTE]);
    for(size_t j = 0; j < INIT_SIZE_BLOCK; j++)
    {
      vec_type d = load(m_keccak + 64 + j * AES_BLOCK_SIZE);
      d = vec_xor(d, *(vec_type*)(x++));
      for(size_t k = 0 ; k < 10 ; ++k)
      {
        d = __builtin_crypto_vcipher(d, *(vec_type*)(&keys[k]));
      }
      store(m_keccak + 64 + j * AES_BLOCK_SIZE, d);
    }
  }
}

bool CryptonightAltivec::detect()
{
  return true;
}
