// Copyright 2023 xiansongq.

#include "frontend/miniMPSI_Ris.h"
#include "coproto/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "frontend/tools.h"
#include "macoro/sync_wait.h"
#include "macoro/thread_pool.h"
#include <boost/asio.hpp>
#include <boost/asio/execution_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/thread.hpp>
#include <cstddef>
#include <iostream>
#include <macoro/when_all.h>
#include <ostream>
#include <string>
// #define Debug
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

void miniMPSISender_Ris::send(std::vector<PRNG> &mseed,
                              std::vector<Socket> &chl, u64 numThreads) {
  // define variables
  std::vector<block> zeroValue(nParties);

  PRNG prng;
  prng.SetSeed(toBlock(myIdx, myIdx));

  std::vector<std::thread> thrds(nParties);
  // std::mutex mtx;   // global mutex
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " start");

  // if malicious mode is enabled
  if (malicious == true) {
    // thrds.clear();
    thrds.resize(setSize);
    for (auto idx = 0; idx < thrds.size(); idx++) {
      thrds[idx] = std::thread([&, idx]() {
        u64 datalen = setSize / thrds.size();
        u64 startlen = idx * datalen;
        u64 endlen = (idx + 1) * datalen;
        if (idx == thrds.size() - 1)
          endlen = setSize;
        oc::RandomOracle hash(sizeof(block));
        for (auto i = startlen; i < endlen; i++) {
          hash.Reset();
          hash.Update(inputs[i]);
          block hh;
          hash.Final(hh);
          inputs[i] = hh;
        }
      });
    }
    for (auto &thread : thrds)
      thread.join();
  }
  paxos.init(setSize, 128, 3, stasecParam, PaxosParam::GF128, block(0, 0));
  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);
#pragma omp parallel for num_threads(numThreads)
  for (u64 i = 0; i < nParties; i++) {
    if (i != myIdx)
      zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
  }
  //  choice a random number a_i and compute g^(a_i) send it to the server
  mK = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
  mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
  crypto_core_ristretto255_scalar_random(mK);
  crypto_scalarmult_ristretto255_base(mG_K, mK); // g^k
  macoro::sync_wait(chl[0].send(mG_K));

  // receive parameters of OKVS result vector
  size_t size = 0;
  macoro::sync_wait(chl[0].recv(size));
  std::vector<block> pax(size), deval(setSize);
  //  receive vector of OKVS result
  macoro::sync_wait(chl[0].recv((pax)));
// OKVS Decode for parties inputs value
#ifdef Debug
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) +
                     " decode start");
#endif
  paxos.decode<block>(inputs, deval, pax, numThreads);
#ifdef Debug
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) +
                     " decode end");
#endif
  std::vector<block> allpx(setSize);
#ifdef Debug
  PrintLine('-');
  std::cout << "sender receive receiver encode size: " << size << std::endl;
  std::cout << "sender decode value myIdx=" << myIdx << std::endl;
  for (auto a : deval) {
    std::cout << a << std::endl;
  }
  PrintLine('-');
#endif
  auto compute = [&](u64 idx) {
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1)
      endlen = setSize;
    for (auto i = startlen; i < endlen; i++) {
      unsigned char *g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
      crypto_scalarmult_ristretto255_base(g_ab, mK);           // g^k
      { allpx[i] = deval[i] + unsignend_char_to_block(g_ab); } // NOLINT
      for (u64 j = 0; j < nParties; j++)
        allpx[i] = allpx[i] ^ zeroValue[j];
    }
  };
  thrds.resize(numThreads);
  for (u64 i = 0; i < thrds.size(); i++) {
    thrds[i] = std::thread([=] { compute(i); });
  }
  for (auto &thrd : thrds)
    thrd.join();

  // OKVS encode for (inputs and g^(a_i*b_i) \xor (zeroshare values))
  std::vector<block> pax2(paxos.size());
#ifdef Debug
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) +
                     " encode start");
#endif
  paxos.solve<block>(inputs, allpx, pax2, &prng, numThreads);
#ifdef Debug
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) +
                     " encode end");
#endif

  macoro::sync_wait(chl[0].send(paxos.size()));
  macoro::sync_wait(chl[0].send(coproto::copy(pax2)));
#ifdef Debug
  PrintLine('-');
  std::cout << "sender encode allpx myIdx=" << myIdx << std::endl;
  for (auto a : allpx) {
    std::cout << a << std::endl;
  }
  PrintLine('-');
#endif
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " end");
  std::cout << timer << std::endl;
  for (u64 i = 0; i < chl.size(); i++) {
    if (i != myIdx) {
      macoro::sync_wait(chl[i].flush());
      chl[i].close();
    }
  }
  return;
}
std::vector<block> miniMPSIReceiver_Ris::receive(std::vector<PRNG> &mseed,
                                                 std::vector<Socket> &chl,
                                                 u64 numThreads) {
  // define variables
  std::vector<block> zeroValue(nParties);
  PRNG prng;
  std::vector<unsigned char *> allPoints;
  std::vector<unsigned char *> allSeeds;
  std::vector<block> val(setSize);
  prng.SetSeed(toBlock(myIdx, myIdx));

  std::vector<std::thread> thrds(nParties);
  std::vector<block> reinputs(setSize); // save original input
  std::mutex mtx;                       // global mutex
  reinputs = inputs;
  timer.setTimePoint("miniMPSI::reciver start");
  // if malicious mode is enabled
  if (malicious == true) {
    thrds.resize(setSize);
    for (auto idx = 0; idx < thrds.size(); idx++) {
      thrds[idx] = std::thread([&, idx]() {
        u64 datalen = setSize / thrds.size();
        u64 startlen = idx * datalen;
        u64 endlen = (idx + 1) * datalen;
        if (idx == thrds.size() - 1)
          endlen = setSize;
        oc::RandomOracle hash(sizeof(block));
        for (auto i = startlen; i < endlen; i++) {
          hash.Reset();
          hash.Update(inputs[i]);
          block hh;
          hash.Final(hh);
          inputs[i] = hh;
        }
      });
    }
    for (auto &thread : thrds)
      thread.join();
  }
  paxos.init(setSize, 128, 3, stasecParam, PaxosParam::GF128, block(0, 0));

  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);
  // #pragma omp parallel for num_threads(numThreads)
  for (u64 i = 1; i < nParties; i++) {
    zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
  }
#ifdef Debug
  timer.setTimePoint("miniMPSI::reciver ris start");
#endif
  for (u64 i = 0; i < setSize; i++) {
    unsigned char *mK = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
    unsigned char *mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_scalar_random(mK);
    crypto_scalarmult_ristretto255_base(mG_K, mK); // g^k
    allSeeds.push_back(mK);
    allPoints.push_back(mG_K);
    val[i] = unsignend_char_to_block(mG_K);
  }
#ifdef Debug
  timer.setTimePoint("miniMPSI::reciver ris end");
#endif
  std::vector<unsigned char *> randomAk(nParties);
  for (u64 i = 1; i < nParties; i++) {
    unsigned char *point = new unsigned char[crypto_core_ristretto255_BYTES];
    macoro::sync_wait(chl[i].recv(point));
    randomAk[i] = point;
  }
#ifdef Debug
  PrintLine('-');
  std::cout << "receiver encode value myIdx=" << myIdx << std::endl;
  for (auto a : val) {
    std::cout << a << std::endl;
  }
  PrintLine('-');
#endif

  //  OKVS encode for (inputs, g_(a_i))
  std::vector<block> pax(paxos.size());
  paxos.solve<block>(inputs, val, pax, &prng, numThreads);
// send parameters of OKVS encode results
#pragma omp parallel for num_threads(numThreads)
  for (u64 i = 1; i < nParties; i++) {
    macoro::sync_wait(chl[i].send(paxos.size()));
    macoro::sync_wait(chl[i].send(coproto::copy(pax))); // NOLINT
  }

  std::vector<block> allpx(setSize);
  thrds.resize(nParties);

  for (auto idx = 1; idx < thrds.size(); idx++) {
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
      for (auto a : val3) {
        std::cout << a << std::endl;
      }
      PrintLine('-');
#endif
      for (u64 j = 0; j < setSize; j++) {
        allpx[j] = allpx[j] ^ val3[j];
      }
    });
  }
  for (u64 i = 1; i < thrds.size(); i++) {
    thrds[i].join();
  }
  std::unordered_multiset<block> result(setSize);
  // The following multi-threaded program may fail to execute PSI when set >
  // 2^10
  thrds.resize(numThreads);
  auto computeAllKey = [&](u64 idx) {
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1)
      endlen = setSize;
    for (u64 i = startlen; i < endlen; i++) {
      for (u64 j = 0; j < nParties; j++)
        allpx[i] = allpx[i] ^ zeroValue[j];}
    for (u64 i = startlen; i < endlen; i++) {

      std::vector<block> userkey(nParties);
      for (u64 j = 1; j < nParties; j++) {
        unsigned char *g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
        crypto_scalarmult_ristretto255_base(g_ab, allSeeds[i]);  // g^k
        userkey[j] = unsignend_char_to_block(randomAk[j]) +
                     unsignend_char_to_block(g_ab);
      }
      if (nParties > 2) {
        for (u64 k = 2; k < nParties; k++) {
          userkey[1] = userkey[1] ^ userkey[k];
        }
      }
      result.insert((userkey[1]));
    }
  };
  thrds.resize(numThreads);
  for (u64 i = 0; i < thrds.size(); i++) {
    thrds[i] = std::thread([=] { computeAllKey(i); });
  }
  for (auto &thrd : thrds)
    thrd.join();
  for (u64 i = 0; i < setSize; i++) {
    auto it = result.find(((allpx[i])));
    if (it != result.end())
      outputs.push_back(reinputs[i]);
  }
  timer.setTimePoint("miniMPSI::reciver end");
  std::cout << timer << std::endl;
  return outputs;
}
void miniMPSIReceiver_Ris::init(u64 secParam, u64 stasecParam, u64 nParties,
                                u64 myIdx, u64 setSize, u64 bitSize,
                                std::vector<block> inputs, // NOLINT
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
} // namespace volePSI
