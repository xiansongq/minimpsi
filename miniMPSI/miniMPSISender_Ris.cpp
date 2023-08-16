// Copyright 2023 xiansongq.

#include "miniMPSI/miniMPSISender_Ris.h"

#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ristretto255.h>
#include <sodium/utils.h>

#include <cstddef>
#include <cstring>
#include <exception>
#include <iostream>
#include <ostream>
#include <stdexcept>
#include <string>
#include <type_traits>

#include "coproto/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "macoro/sync_wait.h"
#include "macoro/thread_pool.h"
#include "miniMPSI/PsiDefines.h"
#include "miniMPSI/tools.h"
#include "volePSI/Defines.h"
#include "volePSI/RsCpsi.h"

// #define Debug
#define Len 2
namespace volePSI {

void miniMPSISender_Ris::init(u64 secParam, u64 stasecParam, u64 nParties,
                              u64 myIdx, u64 setSize, u64 bitSize,
                              std::vector<block> inputs, bool malicious,
                              u64 numThreads) {
  this->secParam = secParam;
  this->stasecParam = stasecParam;
  this->nParties = nParties;
  this->myIdx = myIdx;
  this->setSize = setSize;
  this->bitSize = bitSize;
  this->inputs = inputs;
  this->malicious = malicious;
  this->numThreads = numThreads;
}

void miniMPSISender_Ris::send(std::vector<PRNG> &mseed, Socket &chl,
                              u64 numThreads) {
  std::vector<block> zeroValue(nParties);
  u64 leaderParty = nParties - 1;
  PRNG prng;
  PRNG prng1;

  prng.SetSeed(toBlock(myIdx, myIdx));

  std::vector<std::thread> thrds(nParties);
  using Block = typename Rijndael256Enc::Block;
  const std::uint8_t userKeyArr[] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };
  Block userKey = Block256(userKeyArr);
  Rijndael256Dec decKey(userKey);
  // std::mutex mtx;
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " start");

  // if malicious mode is enabled
  if (malicious) {
    oc::RandomOracle hash(sizeof(block));
    for (auto i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      block hh;
      hash.Final(hh);
      inputs[i] = hh;
    }
    setTimePoint("miniMPSI::sender hash_input");
  }

  paxos.init(setSize, 1 << 14, 3, stasecParam, PaxosParam::GF128, block(1, 1));
  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);

  for (u64 i = 0; i < nParties; i++) {
    if (i != myIdx) {
      zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
    }
  }
  //  choice a random number a_i and compute g^(a_i) send it to the server
  auto *mK = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
  auto *mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
  // crypto_core_ristretto255_scalar_random(mK);
  prng1.SetSeed(toBlock(myIdx, myIdx));
  prng1.implGet(mK, crypto_core_ristretto255_BYTES);

  crypto_scalarmult_ristretto255_base(mG_K, mK);  // g^ai

  macoro::sync_wait(chl.send(mG_K));
  // receive parameters of OKVS result vector
  size_t size = 0;
  macoro::sync_wait(chl.recv(size));
  Matrix<block> pax(size, Len);
  Matrix<block> deval(setSize, Len);
  macoro::sync_wait(chl.recv((pax)));

#ifdef Debug
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " decode start");
#endif

  // OKVS Decode for parties inputs value
  paxos.decode<block>(inputs, deval, pax, numThreads);

#ifdef Debug
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " decode end");
#endif

  Matrix<block> allpx(setSize, Len);
  std::vector<block> allkey(setSize);

#ifdef Debug
  PrintLine('-');
  std::cout << "sender decode value myIdx=" << myIdx << std::endl;
  for (u64 i = 0; i < setSize; i++) {
    for (u64 j = 0; j < Len; j++) {
      std::cout << deval[i][j] << " ";
    }
    std::cout << "\n";
  }
  PrintLine('-');
#endif
  auto compute = [&](u64 idx) {
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1) {
      endlen = setSize;
    }
    for (auto i = startlen; i < endlen; i++) {
      auto *g_a = new unsigned char[crypto_core_ristretto255_BYTES];
      auto *g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
      g_a = Block_to_Ristretto225(deval[i][0], deval[i][1]);
      auto g_f = decKey.decBlock((Block256(g_a)));
      g_a = g_f.data();
      crypto_scalarmult_ristretto255(g_ab, mK, g_a);  // NOLINT

      /*
      When the number of participants is two, shorter data can be
      intercepted keyLength=40+log(setSize*setSize) But there are some
      issues that still need to be dealt with, so here's a uniform 128bit
      intercept
       */
      allkey[i] = toBlock(g_ab);
      if (malicious) {
        oc::RandomOracle hash(sizeof(block));
        hash.Update(allkey[i]);
        hash.Final(allkey[i]);
      }
      for (u64 j = 0; j < nParties; j++) {
        allkey[i] = allkey[i] ^ zeroValue[j];
      }
    }
  };
  thrds.resize(numThreads);
  for (u64 i = 0; i < thrds.size(); i++) {
    thrds[i] = std::thread([=] { compute(i); });
  }
  for (auto &thrd : thrds) {
    thrd.join();
  }

  // OKVS encode for (inputs and g^(a_i*b_i) \xor (zeroshare values))
  std::vector<block> pax2(paxos.size());

#ifdef Debug
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " encode start");
#endif

  paxos.solve<block>(inputs, allkey, pax2, &prng, numThreads);

#ifdef Debug
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " encode end");
#endif

  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax2)));

#ifdef Debug
  PrintLine('-');
  std::cout << "sender encode allpx myIdx=" << myIdx << std::endl;
  for (u64 i = 0; i < setSize; i++) {
    std::cout << allkey[i] << "\n";
  }
  PrintLine('-');
#endif

  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " end");

  macoro::sync_wait(chl.flush());
}

void miniMPSISender_Ris::sendMonty(std::vector<PRNG> &mseed, Socket &chl,
                                   u64 numThreads) {
  std::vector<block> zeroValue(nParties);
  u64 leaderParty = nParties - 1;
  PRNG prng;

  prng.SetSeed(toBlock(myIdx, myIdx));

  std::vector<std::thread> thrds(nParties);
  using Block = typename Rijndael256Enc::Block;
  const std::uint8_t userKeyArr[] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };
  Block userKey = Block256(userKeyArr);
  Rijndael256Dec decKey(userKey);
  // std::mutex mtx;
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " start");

  // if malicious mode is enabled
  if (malicious) {
    oc::RandomOracle hash(sizeof(block));
    for (auto i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      block hh;
      hash.Final(hh);
      inputs[i] = hh;
    }
    setTimePoint("miniMPSI::sender hash_input");
  }

  paxos.init(setSize, 1 << 14, 3, stasecParam, PaxosParam::GF128, block(1, 1));
  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);

  for (u64 i = 0; i < nParties; i++) {
    if (i != myIdx) {
      zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
    }
  }

  block seed = oc::sysRandomSeed();
  prng.SetSeed(seed);
  Scalar25519 mK(prng);

  Monty25519 mG_k = {Monty25519::wholeGroupGenerator * mK};
  // send g^a
  macoro::sync_wait(chl.send(mG_k));
  // receive parameters of OKVS result vector
  size_t size = 0;
  macoro::sync_wait(chl.recv(size));
  Matrix<block> pax(size, Len);
  Matrix<block> deval(setSize, Len);
  macoro::sync_wait(chl.recv((pax)));

#ifdef Debug
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " decode start");
#endif

  // OKVS Decode for parties inputs value
  paxos.decode<block>(inputs, deval, pax, numThreads);

#ifdef Debug
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " decode end");
#endif

  Matrix<block> allpx(setSize, Len);
  std::vector<block> allkey(setSize);

#ifdef Debug
  PrintLine('-');
  std::cout << "sender decode value myIdx=" << myIdx << std::endl;
  for (u64 i = 0; i < setSize; i++) {
    for (u64 j = 0; j < Len; j++) {
      std::cout << deval[i][j] << " ";
    }
    std::cout << "\n";
  }
  PrintLine('-');
#endif

  auto compute = [&](u64 idx) {
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1) {
      endlen = setSize;
    }
    for (auto i = startlen; i < endlen; i++) {
      auto *g_a = new unsigned char[crypto_scalarmult_BYTES];

      mempcpy(g_a, &deval[i][0], sizeof(block));
      mempcpy(g_a + sizeof(block), &deval[i][1], sizeof(block));
      auto g_f = decKey.decBlock((Block256(g_a)));
      g_a = g_f.data();
      Monty25519 g_bi;
      g_bi.fromBytes(g_a);
      Monty25519 g_bia = g_bi * mK;

      /*
      When the number of participants is two, shorter data can be
      intercepted keyLength=40+log(setSize*setSize) But there are some
      issues that still need to be dealt with, so here's a uniform 128bit
      intercept
       */
      allkey[i] = toBlock((u8 *)&g_bia);
      if (malicious) {
        oc::RandomOracle hash(sizeof(block));
        hash.Update(allkey[i]);
        hash.Final(allkey[i]);
      }
      for (u64 j = 0; j < nParties; j++) {
        allkey[i] = allkey[i] ^ zeroValue[j];
      }
    }
  };
  thrds.resize(numThreads);
  for (u64 i = 0; i < thrds.size(); i++) {
    thrds[i] = std::thread([=] { compute(i); });
  }
  for (auto &thrd : thrds) {
    thrd.join();
  }

  // OKVS encode for (inputs and g^(a_i*b_i) \xor (zeroshare values))
  std::vector<block> pax2(paxos.size());

#ifdef Debug
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " encode start");
#endif

  paxos.solve<block>(inputs, allkey, pax2, &prng, numThreads);

#ifdef Debug
  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " encode end");
#endif

  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax2)));

#ifdef Debug
  PrintLine('-');
  std::cout << "sender encode allpx myIdx=" << myIdx << std::endl;
  for (u64 i = 0; i < setSize; i++) {
    std::cout << allkey[i] << "\n";
  }
  PrintLine('-');
#endif

  setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " end");

  macoro::sync_wait(chl.flush());
}

}  // namespace volePSI
