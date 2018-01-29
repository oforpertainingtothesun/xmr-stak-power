#ifndef PORTABILITY_HPP
#define PORTABILITY_HPP

#include <cstdint>
#include <cstdlib>

constexpr uint32_t swab32(uint32_t in)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return in;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return
      ((in & 0xff000000) >> 24) |
      ((in & 0x00ff0000) >> 8) |
      ((in & 0x0000ff00) << 8) |
      ((in & 0x000000ff) << 24);
#else
#error Unknown byte order...
#endif
}

constexpr uint64_t swab64(uint64_t in)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return in;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return
      ((in & 0xff00000000000000) >> 56) |
      ((in & 0x00ff000000000000) >> 40) |
      ((in & 0x0000ff0000000000) >> 24) |
      ((in & 0x000000ff00000000) >> 8) |
      ((in & 0x00000000ff000000) << 8) |
      ((in & 0x0000000000ff0000) << 24) |
      ((in & 0x000000000000ff00) << 40) |
      ((in & 0x00000000000000ff) << 56);
#else
#error Unknown byte order...
#endif
}

constexpr uint64_t get64(const uint8_t *ptr, size_t offset)
{
  return swab64(reinterpret_cast<const uint64_t*>(ptr)[offset]);
}

inline void set64(uint8_t *ptr, size_t offset, uint64_t value)
{
  reinterpret_cast<uint64_t*>(ptr)[offset] = swab64(value);
}

constexpr uint32_t get32(const uint8_t *ptr, size_t offset)
{
  return swab32(reinterpret_cast<const uint32_t*>(ptr)[offset]);
}

inline uint32_t set32(uint8_t *ptr, size_t offset, uint32_t value)
{
  reinterpret_cast<uint32_t*>(ptr)[offset] = swab32(value);
  return value;
}

union u8_or_32
{
  uint32_t u32;
  uint8_t  u8[4];
};

inline uint32_t get32byte(const uint8_t *ptr, size_t offset)
{
#ifdef __sparc
  u8_or_32 value;
  value.u8[0] = ptr[offset + 3];
  value.u8[1] = ptr[offset + 2];
  value.u8[2] = ptr[offset + 1];
  value.u8[3] = ptr[offset + 0];
  return value.u32;
#else
  return swab32(reinterpret_cast<const uint32_t*>(ptr + offset)[0]);
#endif
}

inline uint32_t set32byte(uint8_t *ptr, size_t offset, uint32_t value)
{
#ifdef __sparc
  u8_or_32 u;
  u.u32 = value;
  ptr[offset + 0] = u.u8[3];
  ptr[offset + 1] = u.u8[2];
  ptr[offset + 2] = u.u8[1];
  ptr[offset + 3] = u.u8[0];
#else
  reinterpret_cast<uint32_t*>(ptr + offset)[0] = swab32(value);
#endif
  return value;
}

inline uint32_t byte_from32(uint32_t *x, size_t byte_pos)
{
  size_t word_pos = byte_pos / 4;
  byte_pos = byte_pos & 3;
  auto shifted = x[word_pos] >> (byte_pos * 8);
  return shifted & 0xff;
}

#endif // PORTABILITY_HPP
