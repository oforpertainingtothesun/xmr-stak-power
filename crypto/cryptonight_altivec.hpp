#ifndef CRYPTONIGHT_ALTIVEC_HPP
#define CRYPTONIGHT_ALTIVEC_HPP

#include <cryptonight.hpp>

namespace cryptonight
{

class alignas(16) CryptonightAltivec : public Cryptonight
{
public:
  void explodeScratchPad();
  void iteration(size_t total);
  void implodeScratchPad();
  static uint64_t mul128(uint64_t a, uint64_t b, uint64_t *hi);

  static bool detect();

};
}

#endif // CRYPTONIGHT_ALTIVEC_HPP
