#pragma once
/* 这里包含一些 基础的工具函数 */

#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/RCurve.h"
#include <iostream>
//#include "volePSI/PaxosImpl.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto;

/* Eccpoint to block */
volePSI::block256 Eccpoint_to_block(REccPoint point);
/* block to Eccpoint */
REccPoint block_to_Eccpoint(volePSI::block256 a);
/* REccPoint to string */
std::string REccPoint_to_string(const oc::REccPoint &point);
/* string to REccPoint */
REccPoint string_to_REccPoint(const std::string &str);
std::vector<u8> REccPoint_to_Vector(const REccPoint &point);
REccPoint vector_to_REccPoint(std::vector<u8> &data);
