/**
 * 基于ECDH 实现的 OPRF 协议
 * @description: Dhoprf.h
 * @author: XianSong Qian
 * @date: 2024/04/11
 */
#pragma once

#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>

// #include "../common/defines.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/SodiumCurve.h"
// #include "minimpsi.h"
#include "volePSI/Defines.h"
#include "volePSI/Paxos.h"
#include "volePSI/config.h"

using osuCrypto::Sodium::Monty25519;
using osuCrypto::Sodium::Scalar25519;
using namespace osuCrypto;
using namespace volePSI;
// using Block = typename oc::Rijndael256Enc::Block;

namespace volePSI {
struct oprfParameters {
  u64 setSize;
  u64 numThreads = 1;
  bool malicious = false;
  u64 stasecParam;
  u64 myIdx;
  void init(u64 setSize, u64 numThreads, bool malicious, u64 stasecParam,
            u64 myIdx) {
    this->setSize = setSize;
    this->numThreads = numThreads;
    this->malicious = malicious;
    this->stasecParam = stasecParam;
    this->myIdx = myIdx;
  }
};
class dhOprfSender : public oprfParameters, public TimerAdapter {
 private:
  std::vector<Scalar25519> ska;
  Monty25519 pkb;
  PRNG prng1;
  const std::uint8_t userKeyArr[33] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };

 public:
  Proto send(std::vector<block> inputs, PRNG &prng, coproto::Socket &chl);
  void eval(std::vector<block> &outputs);
};
class dhOprfReceiver : public oprfParameters, public TimerAdapter {
 private:
  const std::uint8_t userKeyArr[33] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };

 public:
  Proto receive(std::vector<block> inputs, std::vector<block> &outputs,
                PRNG &prng, coproto::Socket &chl);
};
}  // namespace volePSI