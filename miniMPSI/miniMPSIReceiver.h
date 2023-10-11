#pragma once
// Copyright 2023 xiansongq.

#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_core_ristretto255.h>

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
#include "volePSI/Defines.h"
#include "volePSI/Paxos.h"
// using namespace osuCrypto;  // NOLINT
// using namespace volePSI;    // NOLINT
using osuCrypto::Sodium::Monty25519;
using osuCrypto::Sodium::Scalar25519;
namespace volePSI {

class miniMPSIReceiver : public oc ::TimerAdapter {
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
  std::vector<unsigned char *> allSeeds;
  std::vector<Scalar25519> allSeed;
  std::vector<block> zeroValue;

  unsigned char *randomAK = new unsigned char[crypto_core_ristretto255_BYTES];

  // use crypto_core_ristretto255 elliptic curve
  std::vector<std::vector<block>> receive(std::vector<PRNG> &mseed,
                                          Socket &chl);

  void init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize,
            std::vector<block> inputs, bool malicious, u64 numThreads);

  // use Monty25519 elliptic curve
  std::vector<std::vector<block>> receiveMonty(std::vector<PRNG> &mseed,
                                               Socket &chl);
};
}  // namespace volePSI
