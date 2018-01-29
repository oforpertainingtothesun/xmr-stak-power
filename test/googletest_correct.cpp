// AllTests.cpp
#include "cryptonight.hpp"
#include "gtest/gtest.h"

#ifdef __x86_64
#include "cryptonight_aesni.hpp"
#elif __PPC__
#include "cryptonight_altivec.hpp"
#else
#include "cryptonight_sparc.hpp"
#endif

#include "keccak.h"
#include "portability.hpp"

using byte = uint8_t;

#define BS(x) reinterpret_cast<const byte *>(x)

const byte *testvector = BS("This is a test");

template <typename T> std::string bytestring(const T *x, size_t len)
{
  const uint8_t *bp = reinterpret_cast<const uint8_t *>(x);
  std::ostringstream rs;
  while (len-- != 0)
    rs << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)(*bp++);
  return rs.str();
}

namespace cryptonight
{
template <typename T> class HashCorrect : public ::testing::Test
{
public:
  T ctx;
};

#ifdef __x86_64
typedef testing::Types<Cryptonight, CryptonightAESNI> Implementations;
#elif __PPC__
typedef testing::Types<Cryptonight, CryptonightAltivec> Implementations;
#else
typedef testing::Types<Cryptonight, CryptonightSparc> Implementations;
#endif

TYPED_TEST_CASE(HashCorrect, Implementations);

#define EXPECT_EQ_A(a1, cs, l) EXPECT_EQ(bytestring(a1, l), bytestring(cs, l))

TEST(PortabilityCorrect, Get64)
{
  uint8_t test[] = {0, 1, 0, 0, 0, 0, 0, 0};
  EXPECT_EQ(get64(test, 0), 256u);
}

TEST(PortabilityCorrect, Get32Byte)
{
  uint8_t test[] = {0, 0, 1, 0, 0};
  EXPECT_EQ(get32byte(test, 0), 256u * 256u);
  EXPECT_EQ(get32byte(test, 1), 256u);
}

TEST(PortabilityCorrect, Set32Byte)
{
  uint8_t test[] = {0, 0, 1, 0, 255};
  set32byte(test, 0, 256u);
  EXPECT_EQ_A(test, BS("\x00\x01\x00\x00\xff"), 5);
  set32byte(test, 1, 256u);
  EXPECT_EQ_A(test, BS("\x00\x00\x01\x00\x00"), 5);
}

TEST(CCorrect, Keccak)
{
  uint64_t st1[25] = {0x0102030405060708};
  keccakf(st1, 1);
  EXPECT_EQ(st1[0], 0x102030405060709ull);

  uint64_t st2[25] = {0x0102030405060708};
  keccakf(st2, 2);
  EXPECT_EQ(st2[0], 0x4c434cfaC9a5b256ull);
}

TYPED_TEST(HashCorrect, Mul128)
{
  auto &ctx = this->ctx;
  uint64_t out;
  EXPECT_EQ(ctx.mul128(10u, 20u, &out), 200u);

  EXPECT_EQ(ctx.mul128(10ull << 32, 20ull << 32, &out), 0);
  EXPECT_EQ(out, 200u);
}

TYPED_TEST(HashCorrect, KeccakCorrect)
{
  auto &ctx = this->ctx;
  ctx.initKeccak(testvector, 14);
  const byte *keccakv0 = BS("\x93\xb9\x0f\xab\x55\xad\xf4\xe9\x87\x87\xd3\x3a\x38\xe7\x11\x06");
  EXPECT_EQ_A(ctx.m_keccak, keccakv0, 16);
  const byte *keccakv64 = BS("\x40\x5e\x91\xde\xec\x2a\x04\x78\x57\x88\x25\x37\x3a\xf7\xea\x64");
  EXPECT_EQ_A(ctx.m_keccak + 64, keccakv64, 16);
}

TYPED_TEST(HashCorrect, KeysCorrect)
{
  auto &ctx = this->ctx;
  ctx.initKeccak(testvector, 14);
  ctx.initRoundKeys(0);
  const byte *key0 = BS("\x93\xb9\x0f\xab\x55\xad\xf4\xe9\x87\x87\xd3\x3a\x38\xe7\x11\x06");
  const byte *key3 = BS("\xe8\x16\xbe\x1b\x69\xc1\x53\x46\xaf\x4d\xef\x56\x16\x7d\x13\x0d");
  EXPECT_EQ_A(ctx.roundKey(0), key0, 16);
  EXPECT_EQ_A(ctx.roundKey(3), key3, 16);
}

TYPED_TEST(HashCorrect, AESRoundCorrect)
{
  auto &ctx = this->ctx;
  memset(ctx.m_keccak, 0, sizeof(ctx.m_keccak));
  memset(&ctx.m_scratchpad[0], 0, Cryptonight::MEMORY);
  ctx.iteration(1);
  const byte *scratch0 = BS("\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63");
  EXPECT_EQ_A(&ctx.m_scratchpad[0], scratch0, 16);

  memset(ctx.m_keccak, 0, sizeof(ctx.m_keccak));
  memcpy(&ctx.m_scratchpad[0], BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), 16);
  ctx.iteration(1);
  const byte *scratch1 = BS("\x6a\x6a\x5c\x45\x2c\x6d\x33\x51\xb0\xd9\x5d\x61\x27\x9c\x21\x5c");
  EXPECT_EQ_A(&ctx.m_scratchpad[0], scratch1, 16);
}

TYPED_TEST(HashCorrect, XORCorrect)
{
  auto &ctx = this->ctx;
  memset(ctx.m_keccak, 0, sizeof(ctx.m_keccak));
  memcpy(ctx.m_keccak + 16, BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), 16);
  memset(&ctx.m_scratchpad[0], 0, Cryptonight::MEMORY);
  ctx.iteration(1);
  const byte *scratch0 = BS("\x63\x62\x61\x60\x67\x66\x65\x64\x6b\x6a\x69\x68\x6f\x6e\x6d\x6c");
  EXPECT_EQ_A(&ctx.m_scratchpad[0], scratch0, 16);
}

TYPED_TEST(HashCorrect, MulSumXORCorrectSimple)
{
  auto &ctx = this->ctx;

  memset(ctx.m_keccak, 0, sizeof(ctx.m_keccak));
  memset(&ctx.m_scratchpad[0], 0, Cryptonight::MEMORY);

  // Ensure that a = the following string and b = 0
  const uint8_t *a = BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
  memcpy(ctx.m_keccak, a, 16);
  memcpy(&ctx.m_scratchpad[ctx.stateIndex(a)], BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
         16);

  // Run the iteration
  ctx.iteration(1);

  // index(a) encoded with a is written back
  const byte *scratch0 = BS("\x6a\x6b\x5e\x46\x28\x68\x35\x56\xb8\xd0\x57\x6a\x2b\x91\x2f\x53");
  EXPECT_EQ_A(&ctx.m_scratchpad[ctx.stateIndex(a)], scratch0, 16);

  // scratch0 *+ a *+ stateIndex(scratch0) is written to stateIndex(scratch0)
  const byte *scratch1 = BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
  EXPECT_EQ_A(&ctx.m_scratchpad[ctx.stateIndex(scratch0)], scratch1, 16);
}

TYPED_TEST(HashCorrect, MulSumXORCorrect)
{
  auto &ctx = this->ctx;

  memset(ctx.m_keccak, 0, sizeof(ctx.m_keccak));
  memset(&ctx.m_scratchpad[0], 0, Cryptonight::MEMORY);

  // Ensure that a = the following string and b = 0
  const uint8_t *a = BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
  memcpy(ctx.m_keccak, a, 16);
  memcpy(&ctx.m_scratchpad[ctx.stateIndex(a)], BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
         16);

  // Ensure that dst is an interesting string
  const byte *scratch0 = BS("\x6a\x6b\x5e\x46\x28\x68\x35\x56\xb8\xd0\x57\x6a\x2b\x91\x2f\x53");
  memcpy(&ctx.m_scratchpad[ctx.stateIndex(scratch0)],
         BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), 16);

  // Run the iteration
  ctx.iteration(1);

  // index(a) encoded with a is written back
  EXPECT_EQ_A(&ctx.m_scratchpad[ctx.stateIndex(a)], scratch0, 16);

  // scratch0 *+ a *+ stateIndex(scratch0) is written to stateIndex(scratch0)
  const byte *scratch1 = BS("\x20\xf3\xc1\xf2\xcd\x81\x63\x09\x08\x73\x49\x7e\xf9\x9c\xa8\xe9");
  EXPECT_EQ_A(&ctx.m_scratchpad[ctx.stateIndex(scratch0)], scratch1, 16);
}

TYPED_TEST(HashCorrect, ScratchPadInitCorrect)
{
  auto &ctx = this->ctx;
  memset(ctx.m_keccak, 0, sizeof(ctx.m_keccak));
  for (size_t i = 0; i < sizeof(ctx.m_keys); i += 16)
  {
    memcpy(&ctx.m_keys[i], BS("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), 16);
  }
  ctx.explodeScratchPad();
  const byte *scratch0   = BS("\x18\x3a\x35\xd2\x5b\xe8\x86\x0a\xe5\xf0\x5b\x87\x99\x31\x92\x14");
  const byte *scratch64  = BS("\x18\x3a\x35\xd2\x5b\xe8\x86\x0a\xe5\xf0\x5b\x87\x99\x31\x92\x14");
  const byte *scratch1MB = BS("\x14\x67\x33\x4b\xa2\x8b\x01\xef\x91\x67\x9a\xc3\xc0\x67\xfd\xe3");
  EXPECT_EQ_A(&ctx.m_scratchpad[0], scratch0, 16);
  EXPECT_EQ_A(&ctx.m_scratchpad[64], scratch64, 16);
  EXPECT_EQ_A(&ctx.m_scratchpad[1024 * 1024], scratch1MB, 16);
}

TYPED_TEST(HashCorrect, IterationCorrect)
{
  auto &ctx = this->ctx;
  ctx.initKeccak(testvector, 14);
  ctx.initRoundKeys(0);
  ctx.explodeScratchPad();
  auto tpl = ctx.initAandB();

  // Iteration 0
  {
    const byte *a       = BS("\xf4\x64\xb8\x12\x38\xa4\x3f\x1f\x9d\xb3\xe3\x75\xd0\x21\x2a\xb4");
    const byte *b       = BS("\x03\x07\x9f\xf3\x25\x0b\x03\x50\x6c\x4a\x61\x04\x5f\x0f\xe9\xb7");
    const byte *reading = BS("\x1a\x5c\x80\x44\x98\xe7\x0d\x0a\x49\x6d\x9e\x6d\xbb\xfd\x2f\x5a");

    auto address = ctx.stateIndex(std::get<0>(tpl).v);
    EXPECT_EQ(address, 1598704u);
    EXPECT_EQ_A(std::get<0>(tpl).v, a, 16);
    EXPECT_EQ_A(std::get<1>(tpl).v, b, 16);
    EXPECT_EQ_A(&ctx.m_scratchpad[address], reading, 16);

    ctx.iteration(1);
    const byte *writing = BS("\xd4\x40\x5c\xee\x33\xcc\x67\x47\xb5\x6b\x44\x9b\x81\x58\xbb\x34");
    EXPECT_EQ_A(&ctx.m_scratchpad[87728u], writing, 16);
  }

  // Iteration 1
  {
    ctx.explodeScratchPad();
    ctx.iteration(2);
    const byte *writing = BS("\xe2\xa3\xc0\xa2\xd4\x62\xb8\xd0\x41\x71\x56\x06\x7e\xbd\xec\xa6");
    EXPECT_EQ_A(&ctx.m_scratchpad[1082800u], writing, 16);
  }

  // Iteration 2
  {
    ctx.explodeScratchPad();
    ctx.iteration(3);
    const byte *writing = BS("\x73\xfe\x5b\xb0\xfd\x42\x69\xee\x6d\x63\x0d\x7c\xe9\x45\xda\x81");
    EXPECT_EQ_A(&ctx.m_scratchpad[1978496u], writing, 16);
  }
}

TYPED_TEST(HashCorrect, IterationsCorrect)
{
  auto &ctx = this->ctx;
  ctx.initKeccak(testvector, 14);
  ctx.initRoundKeys(0);
  ctx.explodeScratchPad();
  ctx.initAandB();
  ctx.iterations();
  const byte *scratch0   = BS("\xcf\xe2\xdd\x39\x00\x7e\x44\x84\x33\xa0\x91\x57\x75\xf0\x3a\x72");
  const byte *scratch64  = BS("\xca\xd2\x79\x27\x6c\x80\x03\xd1\xbc\x20\x23\x9e\xa6\xb1\xef\x58");
  const byte *scratch1MB = BS("\x60\x29\x19\xfb\xcb\x36\xe9\x75\x7d\x38\xa9\x22\xf0\x22\xc6\x0b");
  EXPECT_EQ_A(&ctx.m_scratchpad[0], scratch0, 16);
  EXPECT_EQ_A(&ctx.m_scratchpad[64], scratch64, 16);
  EXPECT_EQ_A(&ctx.m_scratchpad[1024 * 1024], scratch1MB, 16);
}

TYPED_TEST(HashCorrect, Keys4Correct)
{
  auto &ctx = this->ctx;
  ctx.initKeccak(testvector, 14);
  ctx.initRoundKeys(0);
  ctx.explodeScratchPad();
  ctx.initAandB();
  ctx.iterations();
  ctx.initRoundKeys(32);
  const byte *key0 = BS("\x67\xdd\xb7\xb9\x6d\x09\xcb\xf6\x1a\x34\x30\x4f\xe8\xc6\x3b\xb2");
  const byte *key3 = BS("\x65\xf7\x8a\x66\x8e\x96\xe9\xbd\xee\x7d\x6b\x22\xed\xda\x33\x4b");
  EXPECT_EQ_A(ctx.roundKey(0), key0, 16);
  EXPECT_EQ_A(ctx.roundKey(3), key3, 16);
}

TYPED_TEST(HashCorrect, EncryptedKeccakCorrect)
{
  auto &ctx = this->ctx;
  ctx.initKeccak(testvector, 14);
  ctx.initRoundKeys(0);
  ctx.explodeScratchPad();
  ctx.initAandB();
  ctx.iterations();
  ctx.initRoundKeys(32);
  ctx.implodeScratchPad();
  const byte *keccakv = BS("\xae\xef\xd1\x18\xbb\xd1\x5b\xe2\x15\xcc\x40\x10\x9e\x22\x5b\xb6");
  EXPECT_EQ_A(ctx.m_keccak + 64, keccakv, 16);
}

TYPED_TEST(HashCorrect, RerunKeccakCorrect)
{
  auto &ctx = this->ctx;
  ctx.initKeccak(testvector, 14);
  ctx.initRoundKeys(0);
  ctx.explodeScratchPad();
  ctx.initAandB();
  ctx.iterations();
  ctx.initRoundKeys(32);
  ctx.implodeScratchPad();
  ctx.rerunKeccak();
  const byte *keccakv = BS("\xfc\xd1\x1c\x24\xfc\xb0\xf5\x0c\x9f\xf3\x73\x25\x55\x22\x8b\x94");
  EXPECT_EQ_A(ctx.m_keccak + 64, keccakv, 16);
}

TYPED_TEST(HashCorrect, ResultCorrect)
{
  auto &ctx = this->ctx;
  ctx.initKeccak(testvector, 14);
  ctx.initRoundKeys(0);
  ctx.explodeScratchPad();
  ctx.initAandB();
  ctx.iterations();
  ctx.initRoundKeys(32);
  ctx.implodeScratchPad();
  ctx.rerunKeccak();
  EXPECT_EQ(ctx.hashType(), Cryptonight::GROESTL);
  EXPECT_EQ_A(ctx.calculateResult(), "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54", 16);
}

TYPED_TEST(HashCorrect, VectorBlake)
{
  auto &ctx = this->ctx;
  EXPECT_EQ_A(ctx.calculateResult(BS("This is a quick test"), 20),
              "\x1e\x27\x32\x1c\xe1\x2b\x20\xc2\x77\x3b\x28\xb5\x07\x61\x87\xa1", 16);
  EXPECT_EQ(ctx.hashType(), Cryptonight::BLAKE256);
}

TYPED_TEST(HashCorrect, VectorGroestl)
{
  auto &ctx = this->ctx;
  EXPECT_EQ_A(ctx.calculateResult(BS("This is a test"), 14),
              "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54", 16);
  EXPECT_EQ(ctx.hashType(), Cryptonight::GROESTL);
}

TYPED_TEST(HashCorrect, VectorJH)
{
  auto &ctx = this->ctx;
  EXPECT_EQ_A(ctx.calculateResult(BS("This is another test"), 20),
              "\x18\x91\x05\x42\x8a\x6b\x09\x23\xe4\xfa\x41\x7e\x88\x36\x63\x4c", 16);
  EXPECT_EQ(ctx.hashType(), Cryptonight::JH);
}

TYPED_TEST(HashCorrect, VectorSkein)
{
  auto &ctx = this->ctx;
  EXPECT_EQ_A(ctx.calculateResult(BS("This is yet another quick test"), 30),
              "\x48\x47\xcd\x48\xbc\xd6\xa5\x9b\x7f\x81\xe3\xd5\xcb\xe2\xbb\xc7", 16);
  EXPECT_EQ(ctx.hashType(), Cryptonight::SKEIN);
}
}
