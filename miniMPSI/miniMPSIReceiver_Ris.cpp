// Copyright 2023 xiansongq.

#include "miniMPSI/miniMPSIReceiver_Ris.h"

#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_scalarmult_ristretto255.h>

#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>

#include "coproto/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "macoro/sync_wait.h"
#include "macoro/thread_pool.h"
#include "miniMPSI/tools.h"
#include "volePSI/Defines.h"
#include "volePSI/RsCpsi.h"
// #define Debug
#define Len 2
namespace volePSI {

std::vector<std::vector<block>> miniMPSIReceiver_Ris::receive(
    std::vector<PRNG> &mseed, Socket &chl, u64 numThreads) {
  // define variables

  PRNG prng;
  PRNG prng1;
  prng1.SetSeed(toBlock(myIdx, myIdx));

  Matrix<block> vals(setSize, Len);
  prng.SetSeed(toBlock(myIdx, myIdx));

  std::vector<std::thread> thrds(nParties);
  std::vector<block> reinputs(setSize);
  std::mutex mtx;
  reinputs = inputs;
  using Block = typename Rijndael256Enc::Block;
  const std::uint8_t userKeyArr[] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };
  Block userKey = Block256(userKeyArr);
  Rijndael256Enc encKey(userKey);

  setTimePoint("miniMPSI::reciver start");
  // if malicious mode is enabled
  if (malicious) {
    oc::RandomOracle hash(sizeof(block));
    for (u64 i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      block hh;
      hash.Final(hh);
      inputs[i] = hh;
    }
    setTimePoint("miniMPSI::receiver hash_input");
  }

  paxos.init(setSize, 1 << 14, 3, stasecParam, PaxosParam::GF128, block(1, 1));

#ifdef Debug
  setTimePoint("miniMPSI::reciver ris start");
#endif
  auto *mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
  allSeeds.resize(setSize);
  for (u64 i = 0; i < setSize; i++) {
    allSeeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];
    prng1.implGet(allSeeds[i], crypto_core_ristretto255_BYTES);
    crypto_scalarmult_ristretto255_base(mG_K, allSeeds[i]);
    auto permute_ctxt = encKey.encBlock(Block256(mG_K));
    vals[i][0] = toBlock(permute_ctxt.data());
    vals[i][1] = toBlock(permute_ctxt.data() + sizeof(block));
  }

#ifdef Debug
  setTimePoint("miniMPSI::reciver ris end");
#endif

  macoro::sync_wait(chl.recv(randomAK));
#ifdef Debug
  PrintLine('-');
  std::cout << "receiver encode value\n";
  for (u64 i = 0; i < setSize; i++) {
    for (u64 j = 0; j < Len; j++) {
      std::cout << vals[i][j] << " ";
    }
    std::cout << "\n";
  }
  PrintLine('-');
#endif

  //  OKVS encode for (inputs, g_(a_i))
  Matrix<block> pax(paxos.size(), Len);
  paxos.solve<block>(inputs, vals, pax, &prng, numThreads);

  // send parameters of OKVS encode results
  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax)));  // NOLINT

  std::vector<block> allpx(setSize);
  size_t size = 0;
  macoro::sync_wait(chl.recv(size));
  std::vector<block> pax2(size);
  macoro::sync_wait(chl.recv(pax2));
  std::vector<block> val3(setSize);
  paxos.decode<block>(inputs, val3, pax2, numThreads);
  setTimePoint("miniMPSI::reciver decode all ");
  std::vector<block> allkey(setSize);
  std::vector<std::thread> pThrds(numThreads);
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx] = std::thread([&, pIdx]() {
      u64 datalen = setSize / pThrds.size();
      u64 startlen = pIdx * datalen;
      u64 endlen = (pIdx + 1) * datalen;
      if (pIdx == pThrds.size() - 1) {
        endlen = setSize;
      }
      for (u64 i = startlen; i < endlen; ++i) {
        auto *g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
        crypto_scalarmult_ristretto255(g_ab, allSeeds[i],  // NOLINT
                                       randomAK);
        allkey[i] = toBlock(g_ab);
        if (malicious) {
          oc::RandomOracle hash(sizeof(block));
          hash.Update(allkey[i]);
          hash.Final(allkey[i]);
        }
      }
    });
  }
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) pThrds[pIdx].join();
  setTimePoint("miniMPSI::receiver calculate allkey");
  std::vector<std::vector<block>> ans;
  ans.push_back(val3);
  ans.push_back(allkey);
  return ans;
  // return val3;
}

std::vector<std::vector<block>> miniMPSIReceiver_Ris::receiveMonty(
    std::vector<PRNG> &mseed, Socket &chl, u64 numThreads) {
  PRNG prng;
  Matrix<block> vals(setSize, Len);
  prng.SetSeed(toBlock(myIdx, myIdx));
  std::vector<std::thread> thrds(nParties);
  std::vector<block> reinputs(setSize);
  std::mutex mtx;
  reinputs = inputs;
  using Block = typename Rijndael256Enc::Block;
  const std::uint8_t userKeyArr[] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };
  Block userKey = Block256(userKeyArr);
  Rijndael256Enc encKey(userKey);

  setTimePoint("miniMPSI::reciver start");
  if (malicious) {
    oc::RandomOracle hash(sizeof(block));
    for (u64 i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      block hh;
      hash.Final(hh);
      inputs[i] = hh;
    }
    setTimePoint("miniMPSI::receiver hash_input");
  }
  paxos.init(setSize, 1 << 14, 3, stasecParam, PaxosParam::GF128, block(1, 1));

  // create g^bi
  allSeed.resize(setSize);
  for (u64 i = 0; i < setSize; i++) {
    allSeed[i].randomize(prng);
    Monty25519 point = {Monty25519::wholeGroupGenerator * allSeed[i]};
    auto permute_ctxt = encKey.encBlock(Block256((u8 *)&point));
    vals[i][0] = toBlock(permute_ctxt.data());
    vals[i][1] = toBlock(permute_ctxt.data() + sizeof(block));
  }

  block seed = oc::sysRandomSeed();
  prng.SetSeed(seed);

  Monty25519 mG_a;
  macoro::sync_wait(chl.recv(mG_a));
  //  OKVS encode for (inputs, g_(a_i))
  Matrix<block> pax(paxos.size(), Len);
  paxos.solve<block>(inputs, vals, pax, &prng, numThreads);
  // send parameters of OKVS encode results
  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax)));  // NOLINT

  std::vector<block> allpx(setSize);
  size_t size = 0;
  macoro::sync_wait(chl.recv(size));
  std::vector<block> pax2(size);
  macoro::sync_wait(chl.recv(pax2));
  std::vector<block> val3(setSize);
  paxos.decode<block>(inputs, val3, pax2, numThreads);
#ifdef Debug

  PrintLine('-');
  std::cout << "receiver decode val3 myIdx=" << myIdx << std::endl;
  for (u64 i = 0; i < setSize; i++) {
    std::cout << val3[i] << "\n";
  }
  PrintLine('-');
#endif

  setTimePoint("miniMPSI::reciver decode all ");
  std::vector<block> allkey(setSize);
  std::vector<std::thread> pThrds(numThreads);
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx] = std::thread([&, pIdx]() {
      u64 datalen = setSize / pThrds.size();
      u64 startlen = pIdx * datalen;
      u64 endlen = (pIdx + 1) * datalen;
      if (pIdx == pThrds.size() - 1) {
        endlen = setSize;
      }
      for (u64 i = startlen; i < endlen; ++i) {
        Monty25519 g_ab = mG_a * allSeed[i];
        allkey[i] = toBlock((u8 *)&g_ab);
        if (malicious) {
          oc::RandomOracle hash(sizeof(block));
          hash.Update(allkey[i]);
          hash.Final(allkey[i]);
        }
      }
    });
  }
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) pThrds[pIdx].join();
  setTimePoint("miniMPSI::receiver calculate allkey");
  std::vector<std::vector<block>> ans;
  ans.push_back(val3);
  ans.push_back(allkey);
  return ans;
}
void miniMPSIReceiver_Ris::init(u64 secParam, u64 stasecParam, u64 nParties,
                                u64 myIdx, u64 setSize,
                                std::vector<block> inputs,  // NOLINT
                                bool malicious, u64 numThreads) {
  this->secParam = secParam;
  this->stasecParam = stasecParam;
  this->nParties = nParties;
  this->myIdx = myIdx;
  this->setSize = setSize;
  this->inputs = inputs;
  this->malicious = malicious;
  this->numThreads = numThreads;
}

}  // namespace volePSI
