#include "miniMPSI_re.h"
#include "tools.h"
#include <coproto/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <cstddef>
#include <iostream>
#include <macoro/sync_wait.h>
#include <string>

namespace volePSI {
// std::vector<std::thread> getThread(u64 numthreads, u64 setSize) {
//   std::vector<std::thread> threads;
//   if (numthreads > setSize)
//     threads.resize(setSize);
//   else
//     threads.resize(numthreads);
// }
void miniMPSISender_re::init(u64 secParam, u64 stasecParam, u64 nParties,
                             u64 myIdx, u64 setSize, std::vector<block> inputs,
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

void miniMPSISender_re::send(std::vector<PRNG> &mseed, std::vector<Socket> &chl,
                             u64 numThreads) {
  // define variables
  std::vector<block> zeroValue(nParties);
  REllipticCurve mCrurve;
  REllipticCurve::Point mG;
  PRNG prng;

  std::vector<std::thread> thrds(nParties);
  std::mutex mtx; // global mutex
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
  macoro::sync_wait(chl[0].send(coproto::copy(points)));

  // receive parameters of OKVS result vector
  //  first parameter vector rows size
  size_t size = 0;
  macoro::sync_wait(chl[0].recv(size));
  // second parameter vector column size
  std::vector<block> pax(size), deval(setSize);
  //  receive vector of OKVS result
  macoro::sync_wait(chl[0].recv((pax)));
  // OKVS Decode for parties inputs value
  paxos.init(setSize, 128, 3, stasecParam, PaxosParam::Binary, block(0, 0));
  paxos.decode<block>(inputs, deval, pax, numThreads);
  // compute g_(a_i*b_i)
  std::vector<block> allpx(setSize);
  // thrds.resize(numThreads);

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
      {
        // std::lock_guard<std::mutex> lock(mtx); // 加锁
        allpx[i] = deval[i] + REccPoint_to_block(npoint);
      } // 自动释放锁
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

  // OKVS encode for (inouts and g^(a_i*b_i) \xor (zeroshare values))
  std::vector<block> pax2(paxos.size());
  paxos.solve<block>(inputs, allpx, pax2, &prng, numThreads);
  // Sending paxos.size() directly will block if it doesn't work. I don't know
  // why
  // PrintLine('-');
  // std::cout << "sender send val3 idx: " << myIdx << std::endl;
  // for (auto a : allpx) {
  //   std::cout << a << std::endl;
  // }
  // PrintLine('-');
  size = paxos.size();
  macoro::sync_wait(chl[0].send(size));
  macoro::sync_wait(chl[0].send(coproto::copy(pax2)));
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " end");
  std::cout << timer << std::endl;
  for (u64 i = 0; i < chl.size(); i++) {
    if (i != myIdx) {
      macoro::sync_wait(chl[i].flush());
      chl[i].close();
    }
  }
  return;
};
std::vector<block> miniMPSIReceiver_re::receive(std::vector<PRNG> &mseed,
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
  timer.setTimePoint("miniMPSI::reciver start");
  std::vector<block> reinputs(setSize); // save original input
  std::mutex mtx;                       // global mutex
  reinputs = inputs;
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
  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);
#pragma omp parallel for num_threads(numThreads)
  for (u64 i = 1; i < nParties; i++) {
    zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
  }
  std::vector<REccPoint> akrandom(nParties);

  // receive g_ai values from other parties
  prng.SetSeed(toBlock(myIdx, myIdx));
  mG = mCrurve.getGenerator();
  // ai.randomize(prng);
  // g_ai = mG * ai;
  // akrandom.resize(nParties);
  // akrandom.emplace_back(mCrurve);
  // akrandom[0] = g_ai;
  // thrds.resize(nParties);
  // auto recvPoint = [&](u64 idx) {
  //   REllipticCurve mCrurve;
  //   tempPoint = mCrurve;

  //   akrandom.emplace_back(mCrurve); // 粒度 还有待验证
  //   {
  //   std::vector<u8> points(g_ai.sizeBytes());
  //     macoro::sync_wait(chl[idx].recv((points)));
  //     tempPoint.fromBytes(points.data());
  //     std::lock_guard<std::mutex> lock(mtx);
  //     akrandom[idx] = tempPoint;
  //   }
  // };
  // for (u64 i = 1; i < thrds.size(); i++) {
  //   thrds[i] = std::thread([=] { recvPoint(i); });
  // }
  // for (u64 i = 1; i < thrds.size(); i++)
  //   thrds[i].join();

  for (u64 i = 1; i < nParties; i++) {
    tempPoint = mCrurve;
    std::vector<u8> points(g_ai.sizeBytes());
    macoro::sync_wait(chl[i].recv((points)));
    tempPoint.fromBytes(points.data());
    akrandom.emplace_back(mCrurve);
    akrandom[i] = tempPoint;
  }
  std::vector<block> val(setSize);
  // Create collection sized elliptical curve points
  // #pragma omp parallel for num_threads(numThreads)
  for (u64 i = 0; i < setSize; i++) {
    // REllipticCurve mCrurve;
    nSeeds.emplace_back(mCrurve);
    nSeeds[i].randomize(prng);
    mypoint.emplace_back(mCrurve);
    mypoint[i] = mG * nSeeds[i]; // g^ri
    val[i] = REccPoint_to_block(mypoint[i]);
  }

  //  OKVS encode for (inputs, g_(a_i))
  paxos.init(setSize, 128, 3, stasecParam, PaxosParam::Binary, block(0, 0));
  std::vector<block> pax(paxos.size());
  paxos.solve<block>(inputs, val, pax, &prng, numThreads);
// send parameters of OKVS encode results
#pragma omp parallel for num_threads(numThreads)
  for (u64 i = 1; i < nParties; i++) {
    size_t size = paxos.size();
    macoro::sync_wait(chl[i].send(size));
    macoro::sync_wait(chl[i].send(coproto::copy(pax)));
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
      // PrintLine('-');
      // std::cout << "receiver received val3 idx: " << idx << std::endl;
      // for (auto a : val3) {
      //   std::cout << a << std::endl;
      // }
      // PrintLine('-');
      for (u64 j = 0; j < setSize; j++) {
        allpx[j] = allpx[j] ^ val3[j];
      }
    });
  }

  for (u64 i = 1; i < thrds.size(); i++) {
    thrds[i].join();
  }

  std::unordered_multiset<block> result(setSize);

  // The final result of the XOR operation is saved in the second row of allpx
  // Insert the XOR operation result into the bloom filter
  // The time cost of using bloom filter is almost equal to that of using
  // unordered_multiset
  // xor zerovalue

  // for (u64 i = 0; i < setSize; i++) {
  //   for (u64 j = 0; j < nParties; j++)
  //     allpx[i] = allpx[i] ^ zeroValue[j];
  // }
  // 下面的多线程部分还有问题没解决 当参与方大于3 的时候 有问题
  // thrds.resize(numThreads);
  // auto computeAllKey = [&](u64 idx) {
  //   REllipticCurve mCrurve;
  //   u64 datalen = setSize / thrds.size();
  //   u64 startlen = idx * datalen;
  //   u64 endlen = (idx + 1) * datalen;
  //   if (idx == thrds.size() - 1)
  //     endlen = setSize;

  //   for (u64 i = startlen; i < endlen; i++) {
  //     for (u64 j = 0; j < nParties; j++)
  //       allpx[i] = allpx[i] ^ zeroValue[j];
  //     std::vector<block> userkey(nParties);
  //     for (u64 j = 1; j < nParties; j++) {

  //       userkey[j] = REccPoint_to_block(akrandom[j]) +
  //                    REccPoint_to_block(mG * nSeeds[i]);
  //       if (nParties > 2) {
  //         for (u64 k = 2; k < nParties; k++) {
  //           userkey[1] = userkey[1] ^ userkey[k];
  //         }
  //       }
  //     }
  //     std::cout << "userkey: " << userkey[1] << std::endl;
  //     result.insert((userkey[1]));
  //   }
  // };
  // thrds.resize(numThreads);
  // for (u64 i = 0; i < thrds.size(); i++) {
  //   thrds[i] = std::thread([=] { computeAllKey(i); });
  // }
  // for (auto &thrd : thrds)
  //   thrd.join();


  for (u64 i = 0; i < setSize; i++) {
    for (u64 j = 0; j < nParties; j++)
      allpx[i] = allpx[i] ^ zeroValue[j];
  }

  for (u64 i = 0; i < setSize; i++) {
    std::vector<block> userkey(nParties);
    for (u64 j = 1; j < nParties; j++) {
      userkey[j] =
          REccPoint_to_block(akrandom[j]) + REccPoint_to_block(mG *
          nSeeds[i]);
    }
    if (nParties > 2) {
      for (u64 k = 2; k < nParties; k++) {
        userkey[1] = userkey[1] ^ userkey[k];
      }
    }
    result.insert((userkey[1]));
  }

  for (u64 i = 0; i < setSize; i++) {
    auto it = result.find(((allpx[i])));
    if (it != result.end())
      outputs.push_back(reinputs[i]);
  }

  timer.setTimePoint("miniMPSI::reciver end");
  std::cout << timer << std::endl;
  // for (u64 i = 0; i < outputs.size(); i++) {
  //   std::cout << outputs[i] << std::endl;
  // }
  // macoro::sync_wait(macoro::suspend_always{});
  // for (u64 i = 0; i < chl.size(); i++)
  // {
  //     if (i != myIdx)
  //     {
  //         (chl[i].flush());
  //         chl[i].close();
  //     }
  // }
  return outputs;
};
void miniMPSIReceiver_re::init(u64 secParam, u64 stasecParam, u64 nParties,
                               u64 myIdx, u64 setSize,
                               std::vector<block> inputs, bool malicious,
                               u64 numThreads) {
  this->secParam = secParam;
  this->stasecParam = stasecParam;
  this->nParties = nParties;
  this->myIdx = myIdx;
  this->setSize = setSize;
  this->inputs = inputs;
  this->malicious = malicious;
  this->numThreads = numThreads;
}
} // namespace volePSI