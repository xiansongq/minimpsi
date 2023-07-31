#include "tools.h"

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
  try
  {
    point.fromBytes(buffer.data());
  }
  catch (const std::runtime_error &e)
  {
    // std::cout << "生成随机的椭圆曲线" << std::endl;
    REllipticCurve curve;
    // If block cannot be converted to REccPoint, create a random REccPoint
    PRNG prng; // Create a PRNG (you may need to seed it with a random seed)
    prng.SetSeed(block(str[0] - '0', str[1] - '0'));
    // prng.SetSeed(a);
    point.randomize(prng);
    // std::cout << "随机椭圆曲线生成成功" << std::endl;
  }
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
  catch (const std::exception &e)
  {
    REllipticCurve curve;
    // If block cannot be converted to REccPoint, create a random REccPoint
    // PRNG prng; // Create a PRNG (you may need to seed it with a random seed)
    // PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
    PRNG prng;
    std::random_device rd; // 获取真随机数设备
    prng.SetSeed(block(rd(), rd()));
    REccNumber num;
    num.randomize(prng);
    point = curve.getGenerator() * num;
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
  try
  {
    point.fromBytes(bv.data());
  }
  catch (const std::runtime_error &e)
  {
    // std::cout << "生成随机的椭圆曲线" << std::endl;
    REllipticCurve curve;
    // If block cannot be converted to REccPoint, create a random REccPoint
    PRNG prng; // Create a PRNG (you may need to seed it with a random seed)
    prng.SetSeed(block(bv[0], bv[1]));
    // prng.SetSeed(a);
    point.randomize(prng);
    // std::cout << "随机椭圆曲线生成成功" << std::endl;
  }
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

oc::Matrix<u8> Matrix_xor(const oc::Matrix<u8> &a, const oc::Matrix<u8> &b)
{

  if (a.rows() == 0 || b.rows() == 0 || a.cols() == 0 || b.cols() == 0)
  {
    std::cout << "Matrix equal zero" << std::endl;
  }
  else if (a.rows() != b.rows() || a.cols() != b.cols())
  {
    std::cout << "Unequal matrix dimensions" << std::endl;
  }
  oc::Matrix<u8> c(a.rows(), a.cols());
  for (u64 i = 0; i < a.rows(); i++)
  {
    for (u64 j = 0; j < a.cols(); j++)
    {
      c(i, j) = a(i, j) ^ b(i, j);
    }
  }
  return c;
}
oc::REccPoint REccPoint_xor(const REccPoint &a, const REccPoint &b)
{
  // 首先将 REccPoint 转为BitVector
  BitVector pa = REccPoint_to_BitVector(a);
  BitVector pb = REccPoint_to_BitVector(b);
  BitVector pc = pa ^ pb;
  return BitVector_to_REccPoint(pc);
}

std::vector<u8> Matrix_to_vector(oc::Matrix<u8> &a)
{
  std::vector<u8> ans;
  for (u64 i = 0; i < a.rows(); i++)
  {
    for (u64 j = 0; j < a.cols(); j++)
    {
      ans.push_back(a(i, j));
    }
  }
  return ans;
}

void Matrix_xor_Vector(const oc::Matrix<u8> &a, const std::vector<u8> &b)
{
  // 首先将vector<u8> 中的值全部异或 只留一个 结果数据
  u8 ans = 1;
  for (auto a : b)
  {
    ans = ans ^ a;
  }
  // 将异或结果转为BitVector
  BitVector num(ans);
  // num 与 Matrix 每一行进行异或
  for (u64 i = 0; i < a.rows(); i++)
  {
    // 将每行的每一个数字都与 ans 异或 （不知道正确不 还有待思考...）
    for (u64 j = 0; j < a.cols(); j++)
    {
      a[i][j] = a[i][j] ^ ans;
    }
  }
}

// void REccPoint_xor_Test(REccPoint point, std::vector<u8> zeroshare)
// {
//   // 首先测试 REccPoint 转为u8 异或
//   std::vector<u8> vec(point.sizeBytes());
//   vec = REccPoint_to_Vector(point);
//   oc::Matrix<u8> ts(1, vec.size());
//   for (u64 i = 0; i < vec.size(); i++)
//     ts(0, i) = vec[i];
//   Matrix_xor_Vector(ts, zeroshare);
//   for (u64 i = 0; i < vec.size(); i++)
//     vec[i] = ts(0, i);
//   REccPoint po = vector_to_REccPoint(vec);
//   std::cout << "po: " << po << std::endl;
//   // vec = REccPoint_to_Vector(point);
//   REccPoint pot = REccPoint_xor_u8(point, zeroshare);
//   std::cout << "pot: " << pot << std::endl;
// }

void PrintLine(char c)
{
  int count = 50;
  std::string line = std::string(count, c);
  std::cout << line << std::endl;
}
