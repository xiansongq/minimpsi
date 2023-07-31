#pragma once
/* 这里包含一些 基础的工具函数 */

#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/RCurve.h"
#include <iostream>
#include <random>
// #include "volePSI/PaxosImpl.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto;

/* REccPoint to string */
std::string REccPoint_to_string(const oc::REccPoint &point);
/* string to REccPoint */
REccPoint string_to_REccPoint(const std::string &str);
std::vector<u8> REccPoint_to_Vector(const REccPoint &point);
REccPoint vector_to_REccPoint(std::vector<u8> &data);
/* REccPoint to bitvector */
BitVector REccPoint_to_BitVector(const REccPoint &point);
/* bitvector to REccPoint */
REccPoint BitVector_to_REccPoint(const BitVector &bv);
/* REccPoint xor u8 vector */
REccPoint REccPoint_xor_u8(const REccPoint &point, const std::vector<u8> &vecu);
/* Matrix xor operation */
oc::Matrix<u8> Matrix_xor(const oc::Matrix<u8> &a, const oc::Matrix<u8> &b);
/* REccPoint xor operation */
oc::REccPoint REccPoint_xor(const REccPoint &a, const REccPoint &b);
/* Matrix to Vector operation */
std::vector<u8> Matrix_to_vector(oc::Matrix<u8> &a);
/* Matrix xor Vector operation */
void Matrix_xor_Vector(const oc::Matrix<u8> &a, const std::vector<u8> &b);
void REccPoint_xor_Test(REccPoint point, std::vector<u8> zeroshare);
/* output char line */
void PrintLine(char c);
