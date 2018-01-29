/*!
 * @file cryptonight_aesni.hpp
 * An extension of the base cryptonight class
 * to use the x86 aesni instructions
 */
#ifndef CRYPTONIGHT_AESNI_HPP
#define CRYPTONIGHT_AESNI_HPP

#include <cryptonight.hpp>
#include <x86intrin.h>

namespace cryptonight
{

/*!
 * Cast a value to an aligned 128bit vector type
 */
template <typename T> __m128i *R128(T x)
{
  return reinterpret_cast<__m128i *>(x);
}

/*!
 * The AESNI extension of the Cryptonight algorithm
 */
class alignas(16) CryptonightAESNI : public Cryptonight
{
public:
  //! Our stack type
  using stack_type = __m128i;

  /*!
   * Init the round keys, not necessarily slow but we
   * do have the tools to do this so might as well
   * \param offset The offset of the keys
   */
  void initRoundKeys(size_t offset) override;

  //! Explode the scratchpad using AESNI
  void explodeScratchPad() override;
  //! Perform iterations using AESNI
  void iteration(size_t total) override;
  //! Implode the scratchpad using AESNI
  void implodeScratchPad() override;

  //! Multiply two 64bit numbers for testing purposes
  static uint64_t mul128(uint64_t a, uint64_t b, uint64_t *hi);

  //! Detect whether AESNI exists on this machine
  static bool detect();
};
}
#endif  // CRYPTONIGHT_AESNI_HPP
