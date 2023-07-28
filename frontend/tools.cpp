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
   会出现精度的损失
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
  catch (const std::runtime_error &e)
  {
    //std::cout << "生成随机的椭圆曲线" << std::endl;
    REllipticCurve curve;
    // If block cannot be converted to REccPoint, create a random REccPoint
    PRNG prng; // Create a PRNG (you may need to seed it with a random seed)
    prng.SetSeed(block(data[0], data[1]));
    // prng.SetSeed(a);
    point.randomize(prng);
  }
  return point;
}

// Serialize an REccPoint to a BitVector
BitVector REccPoint_to_BitVector(const REccPoint &point)
{
  constexpr size_t pointSize = 2 * RLC_FP_BYTES;
  std::vector<u8> buffer(pointSize);
  point.toBytes(buffer.data());
  return BitVector(buffer.data(), pointSize * 8);
}

// Deserialize a BitVector to an REccPoint
REccPoint BitVector_to_REccPoint(const BitVector &bv)
{
  constexpr size_t pointSize = 2 * RLC_FP_BYTES;
  if (bv.size() != pointSize * 8)
  {
    throw std::runtime_error("BitVector size mismatch");
  }

  REccPoint point;
  point.fromBytes(bv.data());
  return point;
}

REccPoint REccPoint_xor_u8(const REccPoint &point, const std::vector<u8> &vecu)
{
  // 首先将 Point 转为 bitvector
  BitVector vs = REccPoint_to_BitVector(point);
  // 迭代
  for (auto a : vecu)
  {
    // 将 a 转为 bitvector
    BitVector zs(a);
    // 补齐zs的长度 使其与vs相同
    zs.resize(vs.size());
    vs = vs ^ zs;
  }
  // 异或后的结果 转为 REccPoint
  return BitVector_to_REccPoint(vs);
}
