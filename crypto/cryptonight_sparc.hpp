/*!
 * @file cryptonight_sparc.hpp
 * An extension of the base cryptonight class
 * to use the sparc t4 aes instructions
 */
#ifndef CRYPTONIGHT_SPARC_HPP
#define CRYPTONIGHT_SPARC_HPP

#include <cryptonight.hpp>

namespace cryptonight
{

/*!
 * The Sparc extension of the Cryptonight algorithm
 */
class alignas(16) CryptonightSparc : public Cryptonight
{
public:
  //! Our stack type
  struct stack_type
  {
    uint64_t v[2];
  };

  //! Explode the scratchpad using AES
  void explodeScratchPad() override;
  //! Perform iterations using AES
  void iteration(size_t total) override;
  //! Implode the scratchpad using AES
  void implodeScratchPad() override;

  //! Multiply two 64bit numbers for testing purposes
  static uint64_t mul128(uint64_t a, uint64_t b, uint64_t *hi);

  //! Detect whether AES exists on this machine
  static bool detect();
};
}
#endif  // CRYPTONIGHT_SPARC_HPP
