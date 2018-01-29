#include "cryptonight_aesni.hpp"
#include <signal.h>
#include <string.h>
#include <x86intrin.h>

using namespace cryptonight;

void aes_256_assist1(__m128i *t1, __m128i *t2)
{
  __m128i t4;
  *t2 = _mm_shuffle_epi32(*t2, 0xff);
  t4  = _mm_slli_si128(*t1, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  t4  = _mm_slli_si128(t4, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  t4  = _mm_slli_si128(t4, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  *t1 = _mm_xor_si128(*t1, *t2);
}
void aes_256_assist2(__m128i *t1, __m128i *t3)
{
  __m128i t2, t4;
  t4  = _mm_aeskeygenassist_si128(*t1, 0x00);
  t2  = _mm_shuffle_epi32(t4, 0xaa);
  t4  = _mm_slli_si128(*t3, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  t4  = _mm_slli_si128(t4, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  t4  = _mm_slli_si128(t4, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  *t3 = _mm_xor_si128(*t3, t2);
}

void CryptonightAESNI::initRoundKeys(size_t offset)
{
  __m128i *ek = R128(m_keys);
  __m128i t1  = _mm_loadu_si128(R128(m_keccak + offset));
  __m128i t3  = _mm_loadu_si128(R128(m_keccak + offset + 16));

  ek[0] = t1;
  ek[1] = t3;

  __m128i t2 = _mm_aeskeygenassist_si128(t3, 0x01);
  aes_256_assist1(&t1, &t2);
  ek[2] = t1;
  aes_256_assist2(&t1, &t3);
  ek[3] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x02);
  aes_256_assist1(&t1, &t2);
  ek[4] = t1;
  aes_256_assist2(&t1, &t3);
  ek[5] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x04);
  aes_256_assist1(&t1, &t2);
  ek[6] = t1;
  aes_256_assist2(&t1, &t3);
  ek[7] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x08);
  aes_256_assist1(&t1, &t2);
  ek[8] = t1;
  aes_256_assist2(&t1, &t3);
  ek[9] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x10);
  aes_256_assist1(&t1, &t2);
  ek[10] = t1;
}

uint64_t CryptonightAESNI::mul128(uint64_t a, uint64_t b, uint64_t *hi)
{
  uint64_t t2[2];
  __asm__("mulq %3\n\t" : "=d"(t2[0]), "=a"(t2[1]) : "%a"(a), "rm"(b) : "cc");
  *hi = t2[0];
  return t2[1];
}

void CryptonightAESNI::iteration(size_t total)
{
  auto tpl = initAandB();

  stack_type _a = _mm_load_si128(R128(std::get<0>(tpl).v));
  stack_type _b = _mm_load_si128(R128(std::get<1>(tpl).v));
  stack_type _c;

  for (size_t i = 0; i < total; ++i)
  {
    uint64_t t0[2];
    _mm_store_si128(R128(t0), _a);
    auto index0 = stateIndex(t0);
    _c          = _mm_load_si128(R128(&m_scratchpad[index0]));
    _c          = _mm_aesenc_si128(_c, _a);

    uint64_t t1[2];
    _mm_store_si128(R128(t1), _c);
    auto index1 = stateIndex(t1);
    __builtin_prefetch(&m_scratchpad[index1]);

    _b = _mm_xor_si128(_b, _c);
    _mm_store_si128(R128(&m_scratchpad[index0]), _b);

    uint64_t *p = (uint64_t *)(&m_scratchpad[index1]);

    uint64_t t2[2];
    __asm__("mulq %3\n\t" : "=d"(t2[0]), "=a"(t2[1]) : "%a"(t1[0]), "rm"(p[0]) : "cc");
    _b = _mm_load_si128(R128(p));

    _a = _mm_add_epi64(_a, *R128(t2));

    _mm_store_si128(R128(p), _a);
    _a = _mm_xor_si128(_a, _b);
    _b = _c;
  }
}

void CryptonightAESNI::explodeScratchPad()
{
  uint8_t text[INIT_SIZE_BYTE];
  memcpy(text, m_keccak + 64, sizeof(text));

  for (size_t i = 0; i < MEMORY / INIT_SIZE_BYTE; ++i)
  {
    __m128i *keys = R128(m_keys);
    for (size_t j = 0; j < Cryptonight::INIT_SIZE_BLOCK; ++j)
    {
      __m128i d = _mm_loadu_si128(R128(text + j * Cryptonight::AES_BLOCK_SIZE));
      for (size_t k = 0; k < 10; ++k)
      {
        d = _mm_aesenc_si128(d, *R128(&keys[k]));
      }
      _mm_storeu_si128((R128(text + j * Cryptonight::AES_BLOCK_SIZE)), d);
    }
    memcpy(m_scratchpad.get() + i * INIT_SIZE_BYTE, text, INIT_SIZE_BYTE);
  }
}

void CryptonightAESNI::implodeScratchPad()
{
  for (size_t i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
  {
    __m128i *keys = R128(m_keys);
    __m128i *x    = R128(&m_scratchpad[i * INIT_SIZE_BYTE]);
    for (size_t j = 0; j < INIT_SIZE_BLOCK; j++)
    {
      __m128i d = _mm_loadu_si128(R128(m_keccak + 64 + j * AES_BLOCK_SIZE));
      d         = _mm_xor_si128(d, *R128(x++));
      for (size_t k = 0; k < 10; ++k)
      {
        d = _mm_aesenc_si128(d, *R128(&keys[k]));
      }
      _mm_storeu_si128((R128(m_keccak + 64 + j * AES_BLOCK_SIZE)), d);
    }
  }
}

static bool global_sigill = false;
void sighandler(int signo, siginfo_t *si, void *data)
{
  (void)signo;
  (void)si;
  ucontext_t *uc         = (ucontext_t *)data;
  int instruction_length = 6;  // aeskeygenassist
  uc->uc_mcontext.gregs[REG_RIP] += instruction_length;
  global_sigill = true;
}

bool testAES()
{
  __m128i mt1;
  uint64_t t1[2] = {0};
  mt1            = _mm_loadu_si128(R128(t1));
  mt1            = _mm_aeskeygenassist_si128(mt1, 0x00);
  _mm_store_si128(R128(t1), mt1);
  return t1[0] != 0;
}

bool CryptonightAESNI::detect()
{
  struct sigaction sa, osa;
  sa.sa_flags     = SA_ONSTACK | SA_RESTART | SA_SIGINFO;
  sa.sa_sigaction = &sighandler;
  if (sigaction(SIGILL, &sa, &osa) != 0) throw Exception("Failed to install signal handler");
  bool r = testAES();
  sigaction(SIGILL, &osa, &sa);
  return !global_sigill && r;
}
