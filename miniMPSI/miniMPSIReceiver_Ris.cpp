// Copyright 2023 xiansongq.

#include "miniMPSI/miniMPSIReceiver_Ris.h"

#include <sodium/crypto_core_ristretto255.h>
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
#define Debug
#define Len 2
namespace volePSI {

std::vector<block> miniMPSIReceiver_Ris::receive(std::vector<PRNG> &mseed,
                                                 std::vector<Socket> &chl,
                                                 u64 numThreads) {
  // define variables
  std::vector<block> zeroValue(nParties);
  u64 leaderParty = nParties - 1;
  PRNG prng;
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

  std::vector<unsigned char *> allSeeds(setSize);
  Matrix<block> vals(setSize, 2);
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
    for (auto i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      block hh;
      hash.Final(hh);
      inputs[i] = hh;
    }
    setTimePoint("miniMPSI::receiver hash_input");
  }

  paxos.init(setSize, 1 << 14, 3, stasecParam, PaxosParam::GF128, block(0, 0));

  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);
  for (u64 i = 0; i < nParties; i++) {
    if (myIdx != i)
      zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
  }

#ifdef Debug
  setTimePoint("miniMPSI::reciver ris start");
#endif

  auto *mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
  for (u64 i = 0; i < setSize; i++) {
    allSeeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];
    prng1.implGet(allSeeds[i], crypto_core_ristretto255_BYTES);
    // crypto_core_ristretto255_scalar_random(allSeeds[i]);
    crypto_scalarmult_ristretto255_base(mG_K, allSeeds[i]);  // g^k
    auto permute_ctxt = encKey.encBlock(Block256(mG_K));
    vals[i][0] = toBlock(permute_ctxt.data());
    vals[i][1] = toBlock(permute_ctxt.data() + sizeof(block));
  }

#ifdef Debug
  setTimePoint("miniMPSI::reciver ris end");
#endif

  std::vector<unsigned char *> randomAk(nParties);
  for (u64 i = 0; i < nParties - 1; i++) {
    auto *point = new unsigned char[crypto_core_ristretto255_BYTES];
    macoro::sync_wait(chl[i].recv(point));
    randomAk[i] = point;
  }

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
  Matrix<block> pax(paxos.size(), 2);
  paxos.solve<block>(inputs, vals, pax, &prng, numThreads);

  // send parameters of OKVS encode results
  // #pragma omp parallel for num_threads(numThreads)
  for (u64 i = 0; i < nParties - 1; i++) {
    macoro::sync_wait(chl[i].send(paxos.size()));
    macoro::sync_wait(chl[i].send(coproto::copy(pax)));  // NOLINT
  }

  std::vector<block> allpx(setSize);

  thrds.resize(nParties - 1);
  for (auto idx = 0; idx < thrds.size(); idx++) {
    thrds[idx] = std::thread([&, idx]() {
      size_t size = 0;
      macoro::sync_wait(chl[idx].recv(size));
      std::vector<block> pax2(size);
      macoro::sync_wait(chl[idx].recv(pax2));
      std::vector<block> val3(setSize);
      paxos.decode<block>(inputs, val3, pax2, numThreads);

#ifdef Debug
      PrintLine('-');
      std::cout << "receiver decode allpx sender idx=" << idx << std::endl;
      for (u64 i = 0; i < setSize; i++) {
        std::cout << val3[i] << "\n";
      }
      PrintLine('-');
#endif

      for (u64 j = 0; j < setSize; j++) {
        allpx[j] = allpx[j] ^ val3[j];
      }
    });
  }
  for (u64 i = 0; i < thrds.size(); i++) {
    thrds[i].join();
  }

#ifdef Debug
  std::cout << "receiver allpx xor\n";
  for (u64 j = 0; j < setSize; j++) {
    std::cout << "allpx: " << allpx[j] << "\n";
  }
#endif

  // std::unordered_multiset<std::string> result(setSize);
  std::unordered_multiset<block> result(setSize);

  // The following multi-threaded program may fail to execute PSI when set >
  // 2^20
  thrds.resize(numThreads);
  auto computeAllKey = [&](u64 idx) {
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1) {
      endlen = setSize;
    }
    for (u64 i = startlen; i < endlen; i++) {
      for (u64 j = 0; j < nParties; j++) {
        allpx[i] = allpx[i] ^ zeroValue[j];
      }

      std::vector<block> allkey(nParties-1);
      for (u64 j = 0; j < nParties - 1; j++) {
        auto *g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
        crypto_scalarmult_ristretto255(g_ab, allSeeds[i],  // NOLINT
                                       randomAk[j]);

        /*
        When the number of participants is two, shorter data can be intercepted
        keyLength=40+log(setSize*setSize)
        But there are some issues that still need to be dealt with, so here's a
        uniform 128bit intercept
        */
        // auto *temp = new unsigned char[keyLength];
        // mempcpy(temp, g_ab, keyLength);
        allkey[j] = toBlock(g_ab);
        if (malicious) {
          oc::RandomOracle hash(sizeof(block));
          hash.Update(allkey[j]);
          hash.Final(allkey[j]);
        }
      }
      if (nParties > 2) {
        for (u64 k = 1; k < nParties-1; k++) {
          allkey[0] = allkey[0] ^ allkey[k];
        }
      }

#ifdef Debug
      std::cout << "userkey1: " << allkey[0] << std::endl;
#endif
      if (numThreads > 1) {
        std::lock_guard<std::mutex> lock(mtx);
        result.insert(allkey[0]);
      } else {
        result.insert(allkey[0]);
      }
    }
  };
  thrds.resize(numThreads);
  for (u64 i = 0; i < thrds.size(); i++) {
    thrds[i] = std::thread([=] { computeAllKey(i); });
  }
  for (auto &thrd : thrds) {
    thrd.join();
  }

  for (u64 i = 0; i < setSize; i++) {
    auto it = result.find(allpx[i]);
    if (it != result.end()) {
      outputs.push_back(reinputs[i]);
    }
  }
  setTimePoint("miniMPSI::reciver end");
  return outputs;
}
void miniMPSIReceiver_Ris::init(u64 secParam, u64 stasecParam, u64 nParties,
                                u64 myIdx, u64 setSize, u64 bitSize,
                                std::vector<block> inputs,  // NOLINT
                                bool malicious, u64 numThreads) {
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
}  // namespace volePSI
