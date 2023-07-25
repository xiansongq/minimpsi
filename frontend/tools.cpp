#include "tools.h"
/* Eccpoint to block */
block Eccpoint_to_block(REccPoint point)
{
  std::array<u8, REccPoint::size> buffer;
  // Serialize the ECC point to the buffer
  point.toBytes(buffer.data());
  // Convert the buffer to a 128-bit block
  block encodedBlock;
  // encodedBlock.set(buffer.data());
  std::memcpy(&encodedBlock, buffer.data(), sizeof(block));
  return encodedBlock;
}

REccPoint block_to_Eccpoint(block a)
{
  std::cout << a << std::endl;
  std::array<u8, REccPoint::size> buffer;
  std::memcpy(buffer.data(), &a, sizeof(block));
  // Deserialize the buffer to an ECC point
  REccPoint point;
  point.fromBytes(buffer.data());
  return point;
}