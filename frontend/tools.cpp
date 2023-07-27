#include "tools.h"
/* Eccpoint to block */
volePSI::block256 Eccpoint_to_block(REccPoint point)
{
  std::array<u8, REccPoint::size> buffer;
  // Serialize the ECC point to the buffer
  point.toBytes(buffer.data());
  // Convert the buffer to a 128-bit block
  volePSI::block256 encodedBlock;
  // encodedBlock.set(buffer.data());
  std::memcpy(&encodedBlock, buffer.data(), sizeof(block));
  return encodedBlock;
}

/*
   先将 point 转 block 再将 block转point 是能够成功转回来的 但是结果不对。。。。
 */
REccPoint block_to_Eccpoint(volePSI::block256 a)
{
  std::array<u8, REccPoint::size> buffer;
  std::memcpy(buffer.data(), &a, sizeof(block));
  // Deserialize the buffer to an ECC point
  REccPoint point;
  try
  {
    point.fromBytes(buffer.data());
  }
  catch (std::exception &e)
  {
    // If block cannot be converted to REccPoint, create a random REccPoint
    PRNG prng; // Create a PRNG (you may need to seed it with a random seed)
    // prng.SetSeed(a);
    point.randomize(prng);
  }
  return point;
}

std::string REccPoint_to_string(const oc::REccPoint &point)
{
  std::array<uint8_t, oc::REccPoint::size> buffer;
  point.toBytes(buffer.data());
  std::string result(buffer.begin(), buffer.end());
  return result;
}
REccPoint string_to_REccPoint(const std::string &str)
{
  if (str.size() != oc::REccPoint::size)
  {
    throw std::invalid_argument("Invalid string size for REccPoint conversion.");
  }
  std::array<uint8_t, oc::REccPoint::size> buffer;
  std::copy(str.begin(), str.end(), buffer.begin());
  oc::REccPoint point;
  point.fromBytes(buffer.data());
  return point;
}

std::vector<u8> REccPoint_to_Vector(const REccPoint &point)
{
  std::vector<u8> result(REccPoint::size);
  point.toBytes(result.data());
  return result;
}
REccPoint vector_to_REccPoint(std::vector<u8> &data)
{
  REccPoint point;
  try
  {
    point.fromBytes(data.data());
  }
  catch (std::exception &e)
  {
    // If block cannot be converted to REccPoint, create a random REccPoint
    PRNG prng; // Create a PRNG (you may need to seed it with a random seed)
    // prng.SetSeed(a);
    point.randomize(prng);
  }
  return point;
}