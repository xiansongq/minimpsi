#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <macoro/sync_wait.h>

#include <boost/mpl/aux_/na_fwd.hpp>

#include "../minimpsi/minimpsi.h"
#include "coproto/Socket/AsioSocket.h"
using namespace osuCrypto;
using namespace volePSI;

void test(oc::CLP &cmd) {
  u64 nParties = cmd.getOr("n", 3);
  u64 setSize = 1 << cmd.getOr("m", 2);
  u64 num_Threads = cmd.getOr("nt", 1);
  u64 myIdx = cmd.get<u64>("p");
  bool malicious = cmd.getOr("r", false);
  // CurveType type =
  //     (cmd.get<u64>("ct") == 1) ? CurveType::curve25519 : CurveType::fourq;
  u64 StaParam = 40;
  u64 leaderParter = nParties - 1;
  std::mutex mtx;

  u64 expectedIntersection = setSize / 2;
  std::vector<coproto::Socket> chls(nParties);
  std::vector<std::thread> threads(nParties);
  for (u64 idx = 0; idx < threads.size(); idx++) {
    threads[idx] = std::thread([&, idx]() {
      if (idx < myIdx) {
        u32 port = 1200 + idx * 100 + myIdx;
        std::string ip = "localhost:" + std::to_string(port);
        chls[idx] = coproto::asioConnect(ip, 0);
      } else if (idx > myIdx) {
        u32 port =
            1200 + myIdx * 100 + idx;  // get the same port; i=2 & pIdx=1
                                       // =>port=102 chls[i].resize(numThreads);
        std::string ip = "localhost:" + std::to_string(port);
        chls[idx] = coproto::asioConnect(ip, 1);
      }
    });
  }
  for (auto &thrd : threads) {
    thrd.join();
  }

  std::vector<PRNG> mPrngs(nParties);
  PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
  PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
  // save random seeds
  std::vector<std::vector<block>> zsSeeds(nParties);
  Timer stimer;
  // std::vector<Timer> rtimers(nParties);
  // Generate nParties random seeds for each user
  for (u64 i = 0; i < nParties; i++) {
    zsSeeds[i].resize(nParties);
    for (u64 j = 0; j < nParties; j++) {
      if (i <= j) {
        zsSeeds[i][j] = prng0.get<block>();
      } else {
        zsSeeds[i][j] = zsSeeds[j][i];
      }
    }
  }
  mPrngs.resize(nParties);
  for (u64 i = 0; i < nParties; i++) {
    mPrngs[i].SetSeed(zsSeeds[myIdx][i]);
  }

  std::vector<block> inputs(setSize);
  for (u64 i = 0; i < expectedIntersection; i++)
    inputs[i] = prngSet.get<block>();
  prng1.SetSeed(block(myIdx, myIdx));
  for (u64 i = expectedIntersection; i < setSize; i++)
    inputs[i] = prng1.get<block>();
  std::vector<block> zeroValue(nParties);

  std::vector<miniMpsiReceiver> receiver(nParties);
  // std::vector<std::vector<block>> outputs(nParties,
  // std::vector<block>(setSize));
  std::vector<Timer> timers(nParties);
  miniMpsiSender sender;

  if (myIdx != leaderParter) {
    sender.init(setSize, StaParam, nParties, malicious, myIdx, num_Threads);
    sender.setTimer(stimer);
  } else {
    zeroValue[0] = oc::toBlock(0, 0);
    for (u64 i = 0; i < nParties; i++) {
      if (myIdx != i) {
        zeroValue[i] = zeroValue[i] ^ mPrngs[i].get<block>();
      }
    }
    std::vector<std::thread> pThrds(nParties - 1);
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
      pThrds[pIdx] = std::thread([&, pIdx]() {
        receiver[pIdx].init(setSize, StaParam, nParties, malicious, myIdx,
                            num_Threads);
        receiver[pIdx].setTimer(timers[pIdx]);
      });
    }
    for (auto &pThrd : pThrds) {
      pThrd.join();
    }
  }

  std::vector<block> allpx2(setSize);

  std::vector<std::vector<block>> ans(2, std::vector<block>(setSize));
  oc::Matrix<block> allpx(setSize, nParties);
  std::vector<block> allKey(setSize);
  std::vector<block> alloprf(setSize);
  for (auto i = 0; i < setSize; i++)
    alloprf[i] = osuCrypto::ZeroBlock, allKey[i] = oc::ZeroBlock;
  // mMatrix<block> outputs(nParties,setSize);
  oc::Matrix<block> tep(1, setSize);
  PRNG prng(oc::toBlock(leaderParter, leaderParter));
  std::unordered_multiset<block> result;
  if (myIdx != leaderParter) {
    (sender.send(mPrngs, prng, inputs, chls[leaderParter]));
    std::cout << sender.getTimer() << std::endl;
  } else {
    std::vector<std::thread> pThrds(nParties - 1);
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
      pThrds[pIdx] = std::thread([&, pIdx]() {
        std::vector<block> sOprfVal(setSize);
        std::vector<block> outputs(setSize);
        receiver[pIdx].receive(mPrngs, prng, inputs, outputs, sOprfVal,
                               chls[pIdx]);
        if (nParties > 2) {
          for (u64 j = 0; j < setSize; j++) {
            alloprf[j] = alloprf[j] ^ outputs[j];
            allKey[j] = allKey[j] ^ sOprfVal[j];
          }
        } else {
          alloprf = outputs;
          allKey = sOprfVal;
        }
      });
    }
    for (auto &pThrd : pThrds) {
      pThrd.join();
    }
  }

  if (myIdx == leaderParter) {
    std::vector<std::thread> pThrds(num_Threads);
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
      pThrds[pIdx] = std::thread([&, pIdx]() {
        u64 datalen = setSize / pThrds.size();
        u64 startlen = pIdx * datalen;
        u64 endlen = (pIdx + 1) * datalen;
        if (pIdx == pThrds.size() - 1) {
          endlen = setSize;
        }
        for (u64 i = startlen; i < endlen; ++i) {
          for (u64 j = 0; j < nParties; j++) {
            allKey[i] = allKey[i] ^ zeroValue[j];
          }
          if (num_Threads > 1) {
            std::lock_guard<std::mutex> lock(mtx);
            result.insert(alloprf[i]);
          } else {
            result.insert(alloprf[i]);
          }
        }
        //  timers[pIdx].setTimePoint("minimpsi:receiver check zeoro share
        //  end");
      });
    }
    for (auto &pThrd : pThrds) {
      pThrd.join();
    }

    std::vector<block> ans;
    for (u64 i = 0; i < setSize; i++) {
      auto it = result.find(allKey[i]);
      if (it != result.end()) {
        ans.push_back(inputs[i]);
      }
    }
    std::cout << "ans size: " << ans.size() << std::endl;
    timers[0].setTimePoint("miniMPSI::receiver  end");
    std::cout << timers[0] << std::endl;
    // intersection success rate
    if (ans.size() != expectedIntersection) {
      std::cout << "excute PSI error" << std::endl;
      std::cout << "instersection size is " << ans.size() << std::endl;

      return;
    }
    u64 len = 0;
    for (u64 i = 0; i < expectedIntersection; i++) {
      if (inputs[i] == ans[i]) len++;
    }
    std::cout << "instersection size is " << ans.size() << std::endl;
    std::cout << "intersection success rate " << std::fixed
              << std::setprecision(2)
              << static_cast<double>(len) / expectedIntersection * 100 << "%"
              << std::endl
              << std::endl;
  }
}

int main(int argc, char **argv) {
  oc::CLP cmd(argc, argv);
  std::vector<std::thread> pThrds(cmd.getOr("n", 3));
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx] = std::thread([&, pIdx]() {
      oc::CLP threadCmd = cmd;
      threadCmd.setDefault("p", pIdx);
      test(threadCmd);
    });
  }
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx].join();
  }
  return 0;
}