// Copyright 2023 xiansongq.

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/block.h>

#include <iostream>
// #include <stdarg.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Timer.h>
#include <macoro/sync_wait.h>

#include <ostream>
#include <thread>  // NOLINT
#include <vector>

#include "cPSI/cPsiReceiver.h"
#include "cPSI/cPsiSender.h"
#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/IOService.h"
#include "frontend/messagePassingExample.h"
#include "frontend/networkSocketExample.h"
#include "frontend/perf.h"
#include "miniMPSI/miniMPSIReceiver_Ris.h"
#include "miniMPSI/miniMPSISender_Ris.h"
#include "miniMPSI/tools.h"
#include "tests/Common.h"
#include "tests/Paxos_Tests.h"
#include "tests/UnitTests.h"
#include "volePSI/Paxos.h"
#include "volePSI/RsCpsi.h"
#include "volePSI/fileBased.h"
using namespace osuCrypto;  // NOLINT
using namespace volePSI;    // NOLINT
// #define Debug
void printParamInfo(u64 nParties, u64 setSize, u64 numThreads, u64 cSecParam,
                    u64 StaParam, bool malicious) {
  std::cout << "number of parties: " << nParties << std::endl
            << "set size: " << setSize << std::endl
            << "numThreads: " << numThreads << std::endl
            << "computation security parameters: " << cSecParam << std::endl
            << "statistical security parameters: " << StaParam << std::endl
            << "malicious model?  " << (malicious == 1 ? "yes" : "no")
            << std::endl
            << std::endl;
}
void printInfo() {
  std::cout << oc::Color::Green
            << "###############################################################"
               "######\n"
            << "###############################################################"
               "######\n"
            << "#                                                              "
               "     #\n"
            << "#                             miniMSPI                         "
               "     #\n"
            << "#                                                              "
               "     #\n"
            << "###############################################################"
               "######\n"
            << "###############################################################"
               "######\n"
            << oc::Color::Default;
  std::cout << oc::Color::Blue << "Parameter description: \n"
            << oc::Color::Green << "-mpsi: Run the multiparity mini PSI.\n"
            << "      -n: number of parties.\n"
            << "      -m: input set size ( 2^m ).\n"
            << "      -mm: input set size ( mm ).\n"
            << "      -p: the party ID (must be a continuous integer of 1-( "
               "n-1 ) ) Local Multi-Terminal Time Input.\n"
            << "      -t: number of threads.\n"
            << "      -r: 0 is semihonest model, 1 is malicous model.\n"
            // << "      -u: Run unit test.\n"
            << "-cpsi: Run the circuit psi.\n"
            << "      -m <value>: the log2 size of the sets.\n"
            << "      -st: ValueShareType (1 xor,0 add32).\n"
            << "      -nt: number of threads.\n"
            << "-volepsi: Run the volePSI.\n"
            << "      -m <value>: the log2 size of the sets.\n"
            << "      -malicious: run with malicious security.\n"
            << "      -nt: number of threads.\n"
            << oc::Color::Default;
}

void party(u64 nParties, u64 setSize, u64 myIdx, u64 num_Threads,
           bool malicious, u64 flag) {
  // Initialize calculation of security parameters and statistical security
  // parameters
  u64 SecParam = 128;
  u64 StaParam = 40;
  u64 bitSize = 128;
  u64 leaderParter = nParties - 1;
  std::mutex mtx;

  if (flag == 1 || (flag == 0 && myIdx == 0)) {
    printParamInfo(nParties, setSize, num_Threads, SecParam, StaParam,
                   malicious);
  }
  u64 expectedIntersection = setSize / 2;
  std::vector<oc::Socket> chls(nParties);
  // std::vector<std::vector<Socket>> chls(nParties);
  std::vector<std::thread> threads(nParties);
  for (auto idx = 0; idx < threads.size(); idx++) {
    threads[idx] = std::thread([&, idx]() {
      if (idx < myIdx) {
        u32 port = 1200 + idx * 100 + myIdx;
        std::string ip = "localhost:" + std::to_string(port);
        // std::cout << "ip: " << ip << std::endl;
        // chls[idx].resize(num_Threads);
        // for (u64 i = 0; i < num_Threads; i++)
        //   chls[idx][i] = coproto::asioConnect(ip, 0);
        chls[idx] = coproto::asioConnect(ip, 0);
      } else if (idx > myIdx) {
        u32 port =
            1200 + myIdx * 100 + idx;  // get the same port; i=2 & pIdx=1
                                       // =>port=102 chls[i].resize(numThreads);
        std::string ip = "localhost:" + std::to_string(port);
        // std::cout << "ip: " << ip << std::endl;
        chls[idx] = coproto::asioConnect(ip, 1);
        // chls[idx].resize(num_Threads);
        // for (u64 i = 0; i < num_Threads; i++)
        //   chls[idx][i] = coproto::asioConnect(ip, 0);
      }
    });
  }
  for (auto& thrd : threads) {
    thrd.join();
  }

  std::vector<PRNG> mPrngs(nParties);
  PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
  PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
  // save random seeds
  std::vector<std::vector<block>> zsSeeds(nParties);

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

  std::vector<miniMPSIReceiver_Ris> receiver(nParties);
  std::vector<Timer> timers(nParties);
  miniMPSISender_Ris sender;

  if (myIdx != leaderParter) {
    sender.init(128, 40, nParties, myIdx, setSize, bitSize, inputs, malicious,
                num_Threads);
    Timer timer;
    sender.setTimer(timer);
  } else {
    zeroValue[0] = toBlock(0, 0);
    for (u64 i = 0; i < nParties; i++) {
      if (myIdx != i) zeroValue[i] = zeroValue[i] ^ mPrngs[i].get<block>();
    }
    std::vector<std::thread> pThrds(nParties - 1);
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
      pThrds[pIdx] = std::thread([&, pIdx]() {
        receiver[pIdx].init(128, 40, nParties, myIdx, setSize, bitSize, inputs,
                            malicious, num_Threads);
        // if(receiver[pIdx].mTimer)
        //     {
        // Timer timer;
        receiver[pIdx].setTimer(timers[pIdx]);
        // }
      });
    }
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) pThrds[pIdx].join();
  }

  std::vector<block> allpx2(setSize);
  std::vector<block> keys(setSize);
  std::unordered_multiset<block> result;
  if (myIdx != leaderParter) {
    sender.send(mPrngs, chls[leaderParter], num_Threads);
    std::cout << sender.getTimer() << std::endl;
  } else {
    std::vector<std::thread> pThrds(nParties - 1);
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
      pThrds[pIdx] = std::thread([&, pIdx]() {
        auto ans = receiver[pIdx].receive(mPrngs, chls[pIdx], num_Threads);
        if (nParties > 2) {
          for (u64 j = 0; j < setSize; j++) {
            allpx2[j] = allpx2[j] ^ ans[0][j];
            keys[j] = keys[j] ^ ans[1][j];
          }
        } else {
          allpx2 = ans[0];
          keys = ans[1];
        }
      });
    }
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) pThrds[pIdx].join();
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
            allpx2[i] = allpx2[i] ^ zeroValue[j];
          }
          if (num_Threads > 1) {
            std::lock_guard<std::mutex> lock(mtx);
            result.insert(keys[i]);
          } else {
            result.insert(keys[i]);
          }
        }
      });
    }
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) pThrds[pIdx].join();
    std::vector<block> outputs;
    for (u64 i = 0; i < setSize; i++) {
      auto it = result.find(allpx2[i]);
      if (it != result.end()) {
        outputs.push_back(inputs[i]);
      }
    }
    timers[0].setTimePoint("miniMPSI::receiver  end");
    std::cout << timers[0] << std::endl;
    // intersection success rate
    if (outputs.size() != expectedIntersection) {
      std::cout << "excute PSI error" << std::endl;
      return;
    }
    u64 len = 0;
    for (auto i = 0; i < expectedIntersection; i++) {
      if (inputs[i] == outputs[i]) len++;
    }
    std::cout << "instersection size is " << outputs.size() << std::endl;
    std::cout << "intersection success rate " << std::fixed
              << std::setprecision(2)
              << static_cast<double>(len) / expectedIntersection * 100 << "%"
              << std::endl;
    std::cout << std::endl;
  }

  // if (myIdx == leaderParter) {
  //   // create input sets
  //   std::vector<block> inputs(setSize);
  //   // The first element cannot be an intersection element
  //   for (u64 i = 0; i < expectedIntersection; i++)
  //     inputs[i] = prngSet.get<block>();
  //   prng1.SetSeed(block(myIdx, myIdx));
  //   for (u64 i = expectedIntersection; i < setSize; i++)
  //     inputs[i] = prng1.get<block>();

  //   volePSI::miniMPSIReceiver_Ris receiver;
  //   Timer timer;
  //   receiver.setTimer(timer);
  //   receiver.init(128, 40, nParties, myIdx, setSize, bitSize, inputs,
  //   malicious,
  //                 num_Threads);
  //   std::vector<block> ans = (receiver.receive(mPrngs, chls, num_Threads));
  //   std::cout << receiver.getTimer() << std::endl;
  //   // intersection success rate
  //   if (ans.size() != expectedIntersection) {
  //     std::cout << "excute PSI error" << std::endl;
  //     return;
  //   }
  //   u64 len = 0;
  //   for (auto i = 0; i < expectedIntersection; i++) {
  //     if (inputs[i] == ans[i]) len++;
  //   }
  //   std::cout << "instersection size is " << ans.size() << std::endl;
  //   std::cout << "intersection success rate " << std::setprecision(2)
  //             << static_cast<double>(len) / expectedIntersection * 100 << "%"
  //             << std::endl;
  //   std::cout << std::endl;
  // } else {
  //   std::vector<block> inputs(setSize);
  //   for (u64 i = 0; i < expectedIntersection; i++)
  //     inputs[i] = prngSet.get<block>();
  //   prng1.SetSeed(block(myIdx, myIdx));
  //   for (u64 i = expectedIntersection; i < setSize; i++)
  //     inputs[i] = prng1.get<block>();
  //   volePSI::miniMPSISender_Ris sender;
  //   Timer timer;
  //   sender.setTimer(timer);
  //   sender.init(128, 40, nParties, myIdx, setSize, bitSize, inputs,
  //   malicious,
  //               num_Threads);
  //   (sender.send(mPrngs, chls, num_Threads));
  //   std::cout << sender.getTimer() << std::endl;
  // }
}

void cpsi(const oc::CLP& cmd) {
  u64 setSize = 1 << cmd.getOr("m", 10);
  ValueShareType type =
      (cmd.getOr("st", 1) == 1) ? ValueShareType::Xor : ValueShareType::add32;
  u64 numThreads = cmd.getOr("nt", 1);
  printParamInfo(2, setSize, numThreads, 128, 40, 0);
  std::vector<block> recvSet(setSize);
  std::vector<block> sendSet(setSize);
  PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
  u64 expeIntersection = setSize / 2;
  for (u64 i = 0; i < expeIntersection; i++) {
    sendSet[i].set<u64>(0, i);
    recvSet[i].set<u64>(0, i);
  }
  for (u64 i = expeIntersection; i < setSize; i++) {
    recvSet[i] = prng1.get<block>();
    sendSet[i] = prng1.get<block>();
  }
  auto sockets = coproto::LocalAsyncSocket::makePair();

  RsCpsiReceiver recver;
  RsCpsiSender sender;

  auto byteLength = sizeof(block);
  oc::Matrix<u8> senderValues(sendSet.size(), sizeof(block));
  std::memcpy(senderValues.data(), sendSet.data(),
              sendSet.size() * sizeof(block));
  std::memcpy(senderValues[7].data(), recvSet[8].data(), sizeof(block));
  Timer timer1;
  Timer timer2;

  recver.setTimer(timer1);
  recver.init(setSize, setSize, byteLength, 40, prng0.get(), numThreads);
  sender.setTimer(timer2);

  sender.init(setSize, setSize, byteLength, 40, prng0.get(), numThreads);

  RsCpsiReceiver::Sharing rShare;
  RsCpsiSender::Sharing sShare;

  auto p0 = recver.receive(recvSet, rShare, sockets[0]);
  auto p1 = sender.send(sendSet, senderValues, sShare, sockets[1]);

  eval(p0, p1);

  bool failed = false;
  std::vector<u64> intersection;
  for (u64 i = 0; i < recvSet.size(); ++i) {
    auto k = rShare.mMapping[i];

    if (rShare.mFlagBits[k] ^ sShare.mFlagBits[k]) {
      intersection.push_back(i);

      if (type == ValueShareType::Xor) {
        auto rv = *(block*)&rShare.mValues(k, 0);
        auto sv = *(block*)&sShare.mValues(k, 0);
        auto act = (rv ^ sv);
        std::cout << recvSet[i] << " " << rv << " " << sv << "\n";
        if (recvSet[i] != act) {
          if (!failed)
            std::cout << i << " ext " << recvSet[i] << ", act " << act << " = "
                      << rv << " " << sv << std::endl;
          failed = true;
          // throw RTE_LOC;
        }
      } else {
        for (u64 j = 0; j < 4; ++j) {
          auto rv = (u32*)&rShare.mValues(i, 0);
          auto sv = (u32*)&sShare.mValues(i, 0);

          if (recvSet[i].get<u32>(j) != (sv[j] + rv[j])) {
            throw RTE_LOC;
          }
        }
      }
    }
  }

  std::cout << sender.getTimer() << std::endl;
  std::cout << recver.getTimer() << std::endl;

  std::cout << "intersection  size: " << intersection.size() << std::endl;
}

void volepsi(const oc::CLP& cmd) {
  auto sockets = coproto::LocalAsyncSocket::makePair();
  u64 setSize = 1 << cmd.getOr("m", 10);
  bool malicious = cmd.getOr("-malicious", 0) == 0 ? false : true;
  u64 numThreads = cmd.getOr("nt", 1);
  printParamInfo(2, setSize, numThreads, 128, 40, malicious);

  std::vector<block> recvSet(setSize);
  std::vector<block> sendSet(setSize);
  PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
  u64 expeIntersection = setSize / 2;
  for (u64 i = 0; i < expeIntersection; i++) {
    sendSet[i].set<u64>(0, i);
    recvSet[i].set<u64>(0, i);
  }
  for (u64 i = expeIntersection; i < setSize; i++) {
    recvSet[i] = prng1.get<block>();
    sendSet[i] = prng1.get<block>();
  }

  RsPsiReceiver recver;
  RsPsiSender sender;
  Timer timer1;
  Timer timer2;

  recver.setTimer(timer1);
  recver.init(sendSet.size(), recvSet.size(), 40, prng0.get(), malicious,
              numThreads, false);
  sender.setTimer(timer2);

  sender.init(sendSet.size(), recvSet.size(), 40, prng0.get(), malicious,
              numThreads, false);

  auto p0 = recver.run(recvSet, sockets[0]);
  auto p1 = sender.run(sendSet, sockets[1]);

  eval(p0, p1);

  std::cout << recver.getTimer() << std::endl;
  std::cout << sender.getTimer() << std::endl;
  std::cout << "intersection size: " << recver.mIntersection.size()
            << std::endl;
}

void mycPSI(u64 myIdx) {
  std::cout << "myIdx: " << myIdx << std::endl;
  u64 setSize = 1 << 3;
  volePSI::ValueShareType type = ValueShareType::Xor;
  std::vector<block> recvSet(setSize);
  std::vector<block> sendSet(setSize);
  PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
  PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
  u64 expeIntersection = setSize / 2;
  for (u64 i = 0; i < expeIntersection; i++) {
    sendSet[i].set<u64>(0, i);
    recvSet[i].set<u64>(0, i);
    // sendSet[i]=prngSet.get<block>();
    // recvSet[i]=prngSet.get<block>();
  }
  for (u64 i = expeIntersection; i < setSize; i++) {
    recvSet[i] = prng1.get<block>();
    sendSet[i] = prng1.get<block>();
  }
  for (u64 i = 0; i < setSize; i++) {
    std::cout << sendSet[i] << std::endl;
    std::cout << recvSet[i] << std::endl;
  }
  oc::Matrix<u8> senderValues(sendSet.size(), sizeof(block));
  std::memcpy(senderValues.data(), sendSet.data(),
              sendSet.size() * sizeof(block));
  auto sockets = coproto::LocalAsyncSocket::makePair();
  std::vector<std::thread> pThrds(2);
  cPsiReceiver receive;
  cPsiReceiver::Sharing rShare;
  cPsiSender sender;
  cPsiSender::Sharing sShare;
  // if (myIdx == 0) {
  //   cPsiReceiver receive;
  //   cPsiReceiver::Sharing rShare;
  //   (receive.receive(recvSet, rShare, sockets[0]));

  // } else {
  //   cPsiSender sender;
  //   cPsiSender::Sharing sShare;
  //   (sender.send(sendSet, senderValues, sShare, sockets[1]));
  // }
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx] = std::thread([&, pIdx]() {
      if (pIdx == 0) {
        receive.init(setSize, setSize, sizeof(block), 40, 1, toBlock(1, 1),
                     receive.ValueShareType::Xor);
        (receive.receive(recvSet, rShare, sockets[0]));
      } else {
        sender.init(setSize, setSize, sizeof(block), 40, 1, toBlock(1, 1),
                    sender.ValueShareType::Xor);

        (sender.send(sendSet, senderValues, sShare, sockets[1]));
      }
    });
  }
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx].join();
  }
  bool failed = false;
  std::vector<u64> intersection;
  for (u64 i = 0; i < recvSet.size(); ++i) {
    auto k = rShare.mMapping[i];
    if (rShare.mFlagBits[k] ^ sShare.mFlagBits[k]) {
      intersection.push_back(i);

      if (type == ValueShareType::Xor) {
        auto rv = *(block*)&rShare.mValues(k, 0);
        auto sv = *(block*)&sShare.mValues(k, 0);
        auto act = (rv ^ sv);
        std::cout << recvSet[i] << " " << rv << " " << sv << "\n";
        if (recvSet[i] != act) {
          if (!failed)
            std::cout << i << " ext " << recvSet[i] << ", act " << act << " = "
                      << rv << " " << sv << std::endl;
          failed = true;
          // throw RTE_LOC;
        }
      } else {
        for (u64 j = 0; j < 4; ++j) {
          auto rv = (u32*)&rShare.mValues(i, 0);
          auto sv = (u32*)&sShare.mValues(i, 0);

          if (recvSet[i].get<u32>(j) != (sv[j] + rv[j])) {
            throw RTE_LOC;
          }
        }
      }
    }
  }
}

int main(int argc, char** argv) {
  oc::CLP cmd(argc, argv);
  // u64 myIdx = atoi(argv[2]);
  // mycPSI(myIdx);
  if (cmd.isSet("cpsi")) {
    cpsi(cmd);
  } else if (cmd.isSet("volepsi")) {
    volepsi(cmd);
  } else if (cmd.isSet("mpsi")) {
    u64 nParties, setSize, pIdx, numthreads;
    bool malicious = false;
    switch (argc) {
      case 12:
        if (argv[2][0] == '-' && argv[2][1] == 'n') {
          nParties = atoi(argv[3]);
        } else {
          printInfo();
        }
        if (strcmp(argv[4], "-m") == 0) {
          setSize = 1 << atoi(argv[5]);
        } else if (strcmp(argv[4], "-mm") == 0) {
          setSize = atoi(argv[5]);
        } else {
          printInfo();
        }
        if (argv[6][0] == '-' && argv[6][1] == 'p') {
          pIdx = atoi(argv[7]);
        } else {
          printInfo();
        }
        if (argv[8][0] == '-' && argv[8][1] == 't') {
          numthreads = atoi(argv[9]);
        } else {
          printInfo();
        }
        if (strcmp(argv[10], "-r") == 0) {
          malicious = strcmp(argv[11], "1") == 0;
          party(nParties, setSize, pIdx, numthreads, malicious, 1);
        } else {
          printInfo();
        }
        break;
      case 10:
        if (strcmp(argv[2], "-n") == 0) {
          nParties = atoi(argv[3]);
        } else {
          printInfo();
        }
        if (strcmp(argv[4], "-m") == 0) {
          setSize = 1 << atoi(argv[5]);
        } else {
          printInfo();
        }
        if (strcmp(argv[6], "-t") == 0) {
          numthreads = atoi(argv[7]);
        } else {
          printInfo();
        }
        if (strcmp(argv[8], "-r") == 0) {
          malicious = atoi(argv[9]);
          std::vector<std::thread> pThrds(nParties);
          for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
            pThrds[pIdx] = std::thread([&, pIdx]() {
              party(nParties, setSize, pIdx, numthreads, malicious, 0);
            });
          }
          for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
            pThrds[pIdx].join();
          }
        } else {
          printInfo();
        }
        break;
      // case 2:
      //   if (argv[1][0] == '-' && argv[1][1] == 'u') {
      //     nParties = 3;
      //     setSize = 1 << 3;
      //     numthreads = 4;
      //     malicious = 0;
      //     std::vector<std::thread> pThrds(nParties);
      //     for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
      //       pThrds[pIdx] = std::thread([&, pIdx]() {
      //         party(nParties, setSize, pIdx, numthreads, malicious, 0);
      //       });
      //     }
      //     for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
      //     pThrds[pIdx].join();
      //   }
      //   break;
      default:
        printInfo();
        break;
    }
  } else
    printInfo();

  return 0;
}
