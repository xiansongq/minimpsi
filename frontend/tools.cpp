// Copyright 2023 xiansongq.

#include "frontend/tools.h"

block REccPoint_to_block(const REccPoint &point) {
  std::array<u8, oc::REccPoint::size> buffer;
  point.toBytes(buffer.data());
  block result;
  memcpy(&result, buffer.data(), sizeof(block));
  return result;
}
std::string block_to_string(const block &block) {
  std::stringstream ss;
  ss << std::hex << block;
  return ss.str();
}
std::string REccPoint_to_string(const oc::REccPoint &point) {
  std::array<u8, oc::REccPoint::size> buffer;
  point.toBytes(buffer.data());
  std::string result(buffer.begin(), buffer.end());
  return result;
}
REccPoint string_to_REccPoint(const std::string &str) {
  if (str.size() != oc::REccPoint::size) {
    throw std::invalid_argument(
        "Invalid string size for REccPoint conversion.");
  }
  std::array<u8, oc::REccPoint::size> buffer;
  std::copy(str.begin(), str.end(), buffer.begin()); //NOLINT
  oc::REccPoint point;
  try {
    point.fromBytes(buffer.data());
  } catch (const std::runtime_error &e) {
    REllipticCurve curve;
    PRNG prng;
    prng.SetSeed(block(str[0] - '0', str[1] - '0'));
    point.randomize(prng);
  }
  return point;
}

std::vector<u8> REccPoint_to_Vector(const REccPoint &point) {
  std::vector<u8> result(REccPoint::size);
  point.toBytes(result.data());
  return result;
}

REccPoint vector_to_REccPoint(std::vector<u8> &data) {
  REccPoint point;
  try {
    point.fromBytes(data.data());
  } catch (const std::runtime_error &e) {
    REllipticCurve curve;
    PRNG prng;
    // 获取真随机数设备
    std::random_device rd;
    prng.SetSeed(block(rd(), rd()));
    REccNumber num;
    num.randomize(prng);
    point = curve.getGenerator() * num;
  }
  return point;
}

// Serialize an REccPoint to a BitVector
BitVector REccPoint_to_BitVector(const REccPoint &point) {
  constexpr size_t pointSize = 2 * RLC_FP_BYTES;
  std::vector<u8> buffer(pointSize);
  point.toBytes(buffer.data());
  return BitVector(buffer.data(), pointSize * 8);
}

// Deserialize a BitVector to an REccPoint
REccPoint BitVector_to_REccPoint(const BitVector &bv) {
  constexpr size_t pointSize = 2 * RLC_FP_BYTES;
  if (bv.size() != pointSize * 8) {
    throw std::runtime_error("BitVector size mismatch");
  }
  REccPoint point;
  try {
    point.fromBytes(bv.data());
  } catch (const std::runtime_error &e) {
    REllipticCurve curve;
    PRNG prng;
    std::random_device rd;
    prng.SetSeed(block(rd(), rd()));
    point.randomize(prng);
  }
  return point;
}

REccPoint REccPoint_xor_u8(const REccPoint &point,
                           const std::vector<u8> &vecu) {
  // 首先将 Point 转为 bitvector
  BitVector vs = REccPoint_to_BitVector(point);
  // 迭代
  for (auto a : vecu) {
    // 将 a 转为 bitvector
    BitVector zs(a);
    // 补齐zs的长度 使其与vs相同
    zs.resize(vs.size());
    vs = vs ^ zs;
  }
  // 异或后的结果 转为 REccPoint
  return BitVector_to_REccPoint(vs);
}

oc::Matrix<u8> Matrix_xor(const oc::Matrix<u8> &a, const oc::Matrix<u8> &b) {
  if (a.rows() == 0 || b.rows() == 0 || a.cols() == 0 || b.cols() == 0) {
    std::cout << "Matrix equal zero" << std::endl;
  } else if (a.rows() != b.rows() || a.cols() != b.cols()) {
    std::cout << "Unequal matrix dimensions" << std::endl;
  }
  oc::Matrix<u8> c(a.rows(), a.cols());
  for (u64 i = 0; i < a.rows(); i++) {
    for (u64 j = 0; j < a.cols(); j++) {
      c(i, j) = a(i, j) ^ b(i, j);
    }
  }
  return c;
}
oc::REccPoint REccPoint_xor(const REccPoint &a, const REccPoint &b) {
  // 首先将 REccPoint 转为BitVector
  BitVector pa = REccPoint_to_BitVector(a);
  BitVector pb = REccPoint_to_BitVector(b);
  BitVector pc = pa ^ pb;
  return BitVector_to_REccPoint(pc);
}

std::vector<u8> Matrix_to_vector(oc::Matrix<u8> &a) {
  std::vector<u8> ans;
  for (u64 i = 0; i < a.rows(); i++) {
    for (u64 j = 0; j < a.cols(); j++) {
      ans.push_back(a(i, j));
    }
  }
  return ans;
}

void Matrix_xor_Vector(const oc::Matrix<u8> &a, const std::vector<u8> &b) { //NOLINT:
  u8 ans = 1;
  for (auto a : b) {
    ans = ans ^ a;
  }
  BitVector num(ans);
  for (u64 i = 0; i < a.rows(); i++) {
    for (u64 j = 0; j < a.cols(); j++) {
      a[i][j] = a[i][j] ^ ans;
    }
  }
}
u64 checkThreadsNum(u64 numthreads, u64 setSize) {
  return (numthreads <= setSize) ? numthreads : setSize;
}

void PrintLine(char c) {
  int count = 60;
  std::string line = std::string(count, c); //NOLINT:
  std::cout << line << std::endl;
}
block unsignend_char_to_block(const unsigned char *str){
    block result;
    std::memcpy(result.data(), str, sizeof(block));
    return result;
}
std::vector<block> Ristretto225_to_block(const unsigned char *point){
  std::vector<block> ans;
  ans.push_back(toBlock(point));
  ans.push_back(toBlock(point+sizeof(block)));
  std::cout<<ans[0]<<" "<<ans[1]<<std::endl;
  return ans;
}
unsigned char * Block_to_Ristretto225(const block &a,const block &b){
  unsigned char * point =new unsigned char[crypto_core_ristretto255_BYTES];
  memcpy(point, &a, sizeof(block));
  memcpy(point + sizeof(block), &b, sizeof(block));
  return point;
}
std::string Ristretto225_to_string(const block &a, const block &b) {
    std::string result;
    result.reserve(2 * sizeof(block));

    const unsigned char *aPtr = reinterpret_cast<const unsigned char *>(&a);
    const unsigned char *bPtr = reinterpret_cast<const unsigned char *>(&b);

    for (size_t i = 0; i < sizeof(block); ++i) {
        result += aPtr[i];
    }
    for (size_t i = 0; i < sizeof(block); ++i) {
        result += bPtr[i];
    }

    return result;
}


