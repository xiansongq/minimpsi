#pragma once
// Copyright 2023 xiansongq.

#include <cassert>
#include <iostream>
#include <memory>
#include <thread>  //NOLINT
#include <unordered_set>

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/Rijndael256.h"
#include "cryptoTools/Crypto/SodiumCurve.h"
#include "miniMPSI/tools.h"
#include "sodium.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto;  // NOLINT
using namespace volePSI;    // NOLINT
using osuCrypto::Sodium::Monty25519;
using osuCrypto::Sodium::Scalar25519;
namespace volePSI {
class miniMPSISender_Ris : public oc::TimerAdapter {
 public:
  u64 secParam;
  u64 stasecParam;
  u64 nParties;
  u64 numThreads;
  u64 myIdx;
  volePSI::Baxos paxos;
  bool malicious = false;
  std::vector<block> inputs;
  u64 setSize;
  u64 bitSize;
  
  void send(std::vector<PRNG> &mseed, Socket &chl, u64 numThreads);
  void init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize,
            std::vector<block> inputs, bool malicious, u64 numThreads);
  void sendMonty(std::vector<PRNG> &mseed, Socket &chl, u64 numThreads);
};

}  // namespace volePSI
