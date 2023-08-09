#pragma once
// Copyright 2023 xiansongq.

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/Rijndael256.h"
#include "sodium.h"
#include <cassert>
#include <iostream>
#include <memory>
#include <thread> //NOLINT
#include <unordered_set>
#include "frontend/PsiDefines.h"

#include "frontend/tools.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto; // NOLINT
using namespace volePSI;   // NOLINT
namespace volePSI {
class miniMPSISender_Ris : public oc::TimerAdapter {
public:
  u64 secParam;
  u64 stasecParam;
  u64 nParties;
  u64 numThreads;
  u64 myIdx;
  volePSI::Baxos paxos;
  // Paxos<u64> paxos;
  bool malicious = false;
  std::vector<block> inputs;
  u64 setSize;
  u64 bitSize;
  unsigned char *mK;
  unsigned char *mG_K;

  Timer timer;
  void send(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads);
  void init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize,
            u64 bitSize, std::vector<block> inputs, bool malicious,
            u64 numThreads);
};
class miniMPSIReceiver_Ris : public oc ::TimerAdapter {
public:
  u64 secParam;
  u64 stasecParam;
  u64 nParties;
  u64 numThreads;
  u64 myIdx;
  volePSI::Baxos paxos;
  // Paxos<u64> paxos;
  bool malicious = false;
  std::vector<block> inputs;
  u64 setSize;
  u64 bitSize;
  std::vector<block> outputs;
	ropo_fe25519 mfe25519_one;
		

  Timer timer;
  std::vector<block> receive(std::vector<PRNG> &mseed, std::vector<Socket> &chl,
                             u64 numThreads);
  void init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize,
            u64 bitSize, std::vector<block> inputs, bool malicious,
            u64 numThreads);
};
} // namespace volePSI
