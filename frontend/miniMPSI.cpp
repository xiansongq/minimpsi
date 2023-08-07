// Copyright 2023 xiansongq.

#include <macoro/when_all.h>
#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>
#include "frontend/miniMPSI.h"
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
// #define Debug
namespace volePSI {

void miniMPSISender::init(u64 secParam, u64 stasecParam, u64 nParties,
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

void miniMPSISender::send(std::vector<PRNG> &mseed, std::vector<Socket> &chl,
                          u64 numThreads) {
  // define variables
  std::vector<block> zeroValue(nParties);
  REllipticCurve mCrurve;
  REllipticCurve::Point mG;
  PRNG prng;
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
  // paxos.setInput(inputs);
  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);
#pragma omp parallel for num_threads(numThreads)
  for (u64 i = 0; i < nParties; i++) {
    if (i != myIdx)
      zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
  }
  //  choice a random number a_i and compute g^(a_i) send it to the server
  prng.SetSeed(toBlock(myIdx, myIdx));
  mG = mCrurve.getGenerator();
  ai.randomize(prng);
  g_ai = mG * ai;
  std::vector<u8> points = REccPoint_to_Vector(g_ai);
  timer.setTimePoint("miniMPSI::sender online start");
  macoro::sync_wait(chl[0].send(coproto::copy(points)));

  // receive parameters of OKVS result vector
  size_t size = 0;
  macoro::sync_wait(chl[0].recv(size));
  std::vector<block> pax(size), deval(setSize);
  //  receive vector of OKVS result
  macoro::sync_wait(chl[0].recv((pax)));
  // OKVS Decode for parties inputs value
  timer.setTimePoint("miniMPSI::sender "+std::to_string(myIdx)+" decode start");

  paxos.decode<block>(inputs, deval, pax, numThreads);
  timer.setTimePoint("miniMPSI::sender "+std::to_string(myIdx)+" decode end");

  std::vector<block> allpx(setSize);
#ifdef Debug
  PrintLine('-');
  std::cout << "sender decode value myIdx=" << myIdx << std::endl;
  for (auto a : deval) {
    std::cout << a << std::endl;
  }
  PrintLine('-');
#endif
  auto compute = [&](u64 idx) {
    REllipticCurve mCrurve;
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1)
      endlen = setSize;
    for (auto i = startlen; i < endlen; i++) {
      REccPoint npoint(mCrurve);
      npoint = mG * ai;
      { allpx[i] = deval[i] + REccPoint_to_block(npoint); } // NOLINT
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
  timer.setTimePoint("miniMPSI::sender "+std::to_string(myIdx)+" encode start");
  paxos.solve<block>(inputs, allpx, pax2, &prng, numThreads);
  timer.setTimePoint("miniMPSI::sender "+std::to_string(myIdx)+" encode end");

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
std::vector<block> miniMPSIReceiver::receive(std::vector<PRNG> &mseed,
                                             std::vector<Socket> &chl,
                                             u64 numThreads) {
  // define variables
  std::vector<block> zeroValue(nParties);
  REllipticCurve mCrurve;
  REllipticCurve::Point mG;
  PRNG prng;
  REccPoint tempPoint;
  std::vector<REccNumber> nSeeds(nParties);
  std::vector<REccPoint> mypoint(nParties);
  std::vector<std::thread> thrds(nParties);
  std::vector<block> reinputs(setSize);   // save original input
  std::mutex mtx;                         // global mutex
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
  // paxos.setInput(inputs);

  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);
  // #pragma omp parallel for num_threads(numThreads)
  for (u64 i = 1; i < nParties; i++) {
    zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
  }
  std::vector<REccPoint> akrandom(nParties);

  // receive g_ai values from other parties
  prng.SetSeed(toBlock(myIdx, myIdx));
  mG = mCrurve.getGenerator();

  std::vector<block> val(setSize);
  // Create collection setSize elliptical curve points
  for (u64 i = 0; i < setSize; i++) {
    nSeeds.emplace_back(mCrurve);
    nSeeds[i].randomize(prng);
    mypoint.emplace_back(mCrurve);
    mypoint[i] = mG * nSeeds[i];
    val[i] = REccPoint_to_block(mypoint[i]);
  }
  timer.setTimePoint("miniMPSI::reciver online start");
  for (u64 i = 1; i < nParties; i++) {
    tempPoint = mCrurve;
    std::vector<u8> points(g_ai.sizeBytes());
    macoro::sync_wait(chl[i].recv((points)));
    tempPoint.fromBytes(points.data());
    akrandom.emplace_back(mCrurve);
    akrandom[i] = tempPoint;
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
  // paxos.init(setSize, 128, 3, stasecParam, PaxosParam::GF128, block(0, 0));
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

  timer.setTimePoint("miniMPSI::receiver calculation all kyes start");
  thrds.resize(numThreads);
  auto computeAllKey = [&](u64 idx) {
    REllipticCurve mCrurve;
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1)
      endlen = setSize;
    for (u64 i = startlen; i < endlen; i++) {
      for (u64 j = 0; j < nParties; j++)
        allpx[i] = allpx[i] ^ zeroValue[j];
      std::vector<block> userkey(nParties);
      for (u64 j = 1; j < nParties; j++) {
        userkey[j] = REccPoint_to_block(akrandom[j]) +
                     REccPoint_to_block(mG * nSeeds[i]);
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

  // boost::asio::thread_pool pool(4);
  // for (u64 h = 0; h < numThreads; h++) {
  //   boost::asio::post(
  //       pool,
  //       [&, h]() {
  //         REllipticCurve mCrurve;
  //         u64 datalen = setSize / thrds.size();
  //         u64 startlen = h * datalen;
  //         u64 endlen = (h + 1) * datalen;
  //         if (h == thrds.size() - 1)
  //           endlen = setSize;
  //         for (u64 i = startlen; i < endlen; i++) {
  //           for (u64 j = 0; j < nParties; j++)
  //             allpx[i] = allpx[i] ^ zeroValue[j];
  //           std::vector<block> userkey(nParties);
  //           for (u64 j = 1; j < nParties; j++) {
  //             userkey[j] = REccPoint_to_block(akrandom[j]) +
  //                          REccPoint_to_block(mG * nSeeds[i]);
  //           }
  //           if (nParties > 2) {
  //             for (u64 k = 2; k < nParties; k++) {
  //               userkey[1] = userkey[1] ^ userkey[k];
  //             }
  //           }
  //           result.insert((userkey[1]));
  //         }
  //       },
  //       h);
  // }
  // pool.wait();
  timer.setTimePoint("miniMPSI::receiver calculation all kyes end");
  std::cout << "numThreads： " << numThreads << std::endl;
  for (u64 i = 0; i < setSize; i++) {
    auto it = result.find(((allpx[i])));
    if (it != result.end())
      outputs.push_back(reinputs[i]);
  }
  timer.setTimePoint("miniMPSI::reciver end");
  std::cout << timer << std::endl;
  return outputs;
}
void miniMPSIReceiver::init(u64 secParam, u64 stasecParam, u64 nParties,
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
}   // namespace volePSI
