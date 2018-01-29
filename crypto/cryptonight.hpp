/*!
 * @file cryptonight.hpp
 * The header file for the base cryptonight implementation
 */
#ifndef CRYPTONIGHT_HPP
#define CRYPTONIGHT_HPP

#include "portability.hpp"
#include "gtest/gtest_prod.h"
#include <chrono>
#include <memory>
#include <unistd.h>

/*!
 * An array type to make returning / taking fixed-size C
 * arrays more pleasant
 */
namespace array
{
/*!
 * Create a C array of the given type:
 * array::type<uint8_t, 64>
 */
template <typename T, size_t N> using type = T[N];

/*!
 * Create a C array of the given type from an arbitrary array:
 * auto x = array::of<uint8_t, 64>(my_pointer);
 */
template <size_t N, typename T> type<T, N> &of(T *x)
{
  return reinterpret_cast<type<T, N> &>(*x);
}
}

namespace cryptonight
{

/*!
 * Exceptions thrown for serious initialisation events only
 * Initialisation should only be performed once per thread so
 * this shouldn't be seen during operation.
 */
class Exception : public std::exception
{
private:
  //! Local message storage
  std::string m_message;

public:
  /*!
   * Construct with a new message
   * \param message The message
   */
  Exception(const std::string &message) : m_message(message)
  {
  }

  /*!
   * Return the message for information purposes
   * \return The message
   */
  const char *what() const noexcept
  {
    return m_message.c_str();
  }
};

/*!
 * The cryptonight class provides the base implementation
 * of the Cryptonight algorithm that should work on all
 * processors
 */
class alignas(16) Cryptonight
{
public:
  //! Total size of scratch-pad memory
  static const size_t MEMORY = (1 << 21);
  //! Number of scratch-pad iterations
  static const size_t ITER = (1 << 20);
  //! Size of an AES block
  static const size_t AES_BLOCK_SIZE = 16;
  //! Size of an AES key
  static const size_t AES_KEY_SIZE = 32;
  //! Number of blocks to initialize from keccak state
  static const size_t INIT_SIZE_BLOCK = 8;
  //! Number of scratchpad bytes initialised simultaneously
  static const size_t INIT_SIZE_BYTE = (INIT_SIZE_BLOCK * AES_BLOCK_SIZE);
  //! Total number of AES blocks in the scratch pad
  static const size_t TOTALBLOCKS = (MEMORY / AES_BLOCK_SIZE);

protected:
  //! Our storage of the keccak state
  alignas(16) uint8_t m_keccak[200];
  //! Our storage of the AES keys
  alignas(16) uint8_t m_keys[AES_KEY_SIZE * 10];
  //! Our storage of the result
  alignas(16) uint8_t m_result[64];

  //! The stack type is a simple aligned block
  //! This will be redefined by more precise implementations
  struct alignas(16) stack_type
  {
    uint8_t v[AES_BLOCK_SIZE];
  };

  //! Record the stage times for benchmarking
  std::chrono::steady_clock::duration m_stage_times[9];

  //! Our scratchpad memory
  std::unique_ptr<uint8_t[], decltype(&::free)> m_scratchpad;

  /*!
   * Tests that require private / protected access to this class
   */
  template <typename T> FRIEND_TEST(HashCorrect, KeccakCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, AESRoundCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, XORCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, MulSumXORCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, MulSumXORCorrectSimple);
  template <typename T> FRIEND_TEST(HashCorrect, ScratchPadInitCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, KeysCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, ABCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, IterationCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, IterationsCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, EncryptedKeccakCorrect);
  template <typename T> FRIEND_TEST(HashCorrect, RerunKeccakCorrect);

  /*!
   * Perform the 64 bit multiply and add function:
   * a[0] * dst[0] + swap(c)
   * \param a   Constant parameter (e.g. a, b or c)
   * \param c   Changing parameter (e.g. a, b or c)
   * \param dst Destination in the scratchpad
   */
  static void mul_sum_xor_dst(const uint8_t *a, uint8_t *c, uint8_t *dst);

public:
  //! Base constructor initializes memory, does no processing
  Cryptonight();

  //! Initialise the Keccak state with a new input byte stream
  void initKeccak(const uint8_t *in, size_t len);
  //! Calculate the round keys (not that slow)
  virtual void initRoundKeys(size_t offset);
  //! Explode the scratch pad (SLOW)
  virtual void explodeScratchPad();
  //! Initialise A and B to the stack type
  std::tuple<stack_type, stack_type> initAandB();
  //! Perform N iterations (SLOW)
  virtual void iteration(size_t total);
  //! Perform all iterations
  void iterations();
  //! Impplode the scratch pad (SLOW)
  virtual void implodeScratchPad();
  //! Re-run keccak at the end
  void rerunKeccak();

  /*!
   * 128 bit multiplication of a & b
   * \param a  LHS parameter
   * \param b  RHS parameter
   * \param hi Output high bits
   * \return Low bits
   */
  static uint64_t mul128(uint64_t a, uint64_t b, uint64_t *hi);

  /*!
   * The type of the hash function to apply at the end
   */
  enum HashType
  {
    BLAKE256 = 0,
    GROESTL  = 1,
    JH       = 2,
    SKEIN    = 3
  };

  /*!
   * Find the type of the hash function after the re-run of keccak
   * \return The type of the hash function to find the result
   */
  HashType hashType() const;

  /*!
   * Calculate the result and return it. Requires all other stages
   * have been performed in order
   * @return The result
   */
  array::type<uint8_t, 64> &calculateResult();

  /*!
   * Calculate the result from an input vector. Performs all stages
   * internally in this function.
   * \param in  The input byte array
   * \param len The length of the array
   * \return The calculated result
   */
  array::type<uint8_t, 64> &calculateResult(const uint8_t *in, size_t len);

  /*!
   * Dump all of the stage times to the output iterator
   * @tparam T duration type for output
   * @tparam O output iterator type
   * @param output The output iterator
   */
  template <typename T, typename O> void stageTimes(O output)
  {
    for (auto &x : m_stage_times)
    {
      *output++ = std::chrono::duration_cast<T>(x).count();
    }
  }

  /*!
   * Calculate state index given a stack variable
   * \param a The stack variable
   * \return The state index
   */
  inline uint32_t stateIndex(const stack_type &a) const
  {
    return stateIndex(a.v);
  }
  /*!
   * Calculate the state index given a byte pointer to the state variable
   * \param a The byte pointer
   * \return The state index
   */
  inline uint32_t stateIndex(const uint8_t *a) const
  {
    return ((get64(a, 0) >> 4) & (TOTALBLOCKS - 1)) << 4;
  }
  /*!
   * Calculate the state index given a 64 bit pointer to the state variable
   * \param a The 64bit pointer
   * \return The state index
   */
  inline uint32_t stateIndex(const uint64_t *a) const
  {
    return ((swab64(*a) >> 4) & (TOTALBLOCKS - 1)) << 4;
  }

  /*!
   * Return a round key from the AES key array
   * \param i The key number
   * \return The key
   */
  array::type<uint8_t, 32> &roundKey(size_t i);

  /*!
   * Return true if this class is applicable to this CPU
   * \return true
   */
  static inline bool detect()
  {
    return true;
  }
};

/*!
 * Perform the full hash calculation
 * \param in  The input byte array
 * \param len The length of the byte array
 * \param out The output calculation (must be >= 64 bytes)
 */
inline void cryptonight(const uint8_t *in, size_t len, char *out)
{
  Cryptonight ctx;
  auto &r = ctx.calculateResult(reinterpret_cast<const uint8_t *>(in), len);
  std::copy(r, r + sizeof(r), out);
}
}
#endif  // CRYPTONIGHT_HPP
