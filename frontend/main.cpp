#include "perf.h"
#include "tests/UnitTests.h"

#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/IOService.h"
#include "messagePassingExample.h"
#include "networkSocketExample.h"
#include "tests/Paxos_Tests.h"
#include "volePSI/fileBased.h"
#include <iostream>
#include <stdarg.h>
#include <thread>
#include <vector>

#include "cryptoTools/Common/Matrix.h"

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/Rijndael256.h"
#include "miniMPSI.h"
#include "tools.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto;
using namespace volePSI;

void PrintParamInfo(u64 nParties, u64 setSize, u64 SecParam, u64 StaParam,
                    bool malicious) {

  std::cout << oc::Color::Red << "number of parties: " << nParties << std::endl
            << "set size: " << setSize << std::endl
            << "computational security parameters: " << SecParam << std::endl
            << "statistical security parameters: " << StaParam << std::endl
            << "malicious model? " << (malicious == 1 ? "yes" : "no")
            << oc::Color::Default << std::endl;
}
// 多终端执行代码
void party(u64 nParties, u64 setSize, u64 myIdx, u64 num_Threads,
           bool malicious, u64 flag) {
  // 初始化计算安全参数和 统计安全参数
  u64 SecParam = 128, StaParam = 40;
  if (flag == 1 || (flag == 0 && myIdx == 0))
    PrintParamInfo(nParties, setSize, SecParam, StaParam, malicious);
  u64 expectedIntersection = setSize / 2;
  std::vector<oc::Socket> chls(nParties);
  std::vector<std::thread> threads(nParties);
  for (auto idx = 0; idx < threads.size(); idx++) {
    threads[idx] = std::thread([&, idx]() {
      if (idx < myIdx) {
        u32 port = 1200 + idx * 100 + myIdx;
        std::string ip = "localhost:" + std::to_string(port);
        // std::cout << "ip: " << ip << std::endl;
        chls[idx] = coproto::asioConnect(ip, 0);
      } else if (idx > myIdx) {
        u32 port =
            1200 + myIdx * 100 + idx; // get the same port; i=2 & pIdx=1
                                      // =>port=102 chls[i].resize(numThreads);
        std::string ip = "localhost:" + std::to_string(port);
        // std::cout << "ip: " << ip << std::endl;
        chls[idx] = coproto::asioConnect(ip, 1);
      }
    });
  }
  for (auto &thrd : threads)
    thrd.join();

  // 首先生成 零共享值
  std::vector<PRNG> mPrngs(nParties);
  std::mutex mtx;
  PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
  PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
  std::vector<std::vector<block>> zsSeeds(nParties); // 存储随机种子

  // 为每个用户生成nparties个随机种子
  for (u64 i = 0; i < nParties; i++) {
    zsSeeds[i].resize(nParties);
    for (u64 j = 0; j < nParties; j++) {
      if (i <= j) {
        zsSeeds[i][j] = prng0.get<block>();
      } else
        zsSeeds[i][j] = zsSeeds[j][i];
    }
  }
  mPrngs.resize(nParties);
  for (u64 i = 0; i < nParties; i++) {
    mPrngs[i].SetSeed(zsSeeds[myIdx][i]);
  }
  if (myIdx == 0) {
    // create input sets
    std::vector<block> inputs(setSize);
    // The first element cannot be an intersection element
    for (u64 i = 1; i < expectedIntersection + 1; i++)
      inputs[i] = prngSet.get<block>();
    prng1.SetSeed(block(myIdx, myIdx));
    for (u64 i = expectedIntersection + 1; i < setSize; i++)
      inputs[i] = prng1.get<block>();
    inputs[0] = prng1.get<block>();

    volePSI::miniMPSIReceiver receiver;
    receiver.init(128, 40, nParties, myIdx, setSize, inputs, malicious,
                  num_Threads);
    std::vector<block> ans = (receiver.receive(mPrngs, chls, num_Threads));
    // intersection success rate
    if (ans.size() != expectedIntersection)
      std::cout << "excute PSI error" << std::endl;
    u64 len = 0;
    for (auto i = 1; i < expectedIntersection + 1; i++) {
      if (inputs[i] == ans[i - 1])
        len++;
    }
    std::cout << "instersection size is " << ans.size() << std::endl;
    std::cout << "intersection success rate " << std::setprecision(2)
              << (double)len / expectedIntersection * 100 << "%" << std::endl;
  } else {
    std::vector<block> inputs(setSize);
    for (u64 i = 1; i < expectedIntersection + 1; i++)
      inputs[i] = prngSet.get<block>();
    prng1.SetSeed(block(myIdx, myIdx));
    for (u64 i = expectedIntersection + 1; i < setSize; i++)
      inputs[i] = prng1.get<block>();
    inputs[0] = prng1.get<block>();
    volePSI::miniMPSISender sender;
    sender.init(128, 40, nParties, myIdx, setSize, inputs, malicious,
                num_Threads);
    (sender.send(mPrngs, chls, num_Threads));
  }
}
void PrintInfo() {
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
               "######\n";
  std::cout
      << oc::Color::Green << "Parameter description: \n"
      << oc::Color::Blue << "   -n: number of parties.\n"
      << "   -m: input set size ( 2^m ).\n"
      << "   -mm: input set size ( mm ).\n"
      << "   -p: the party ID (must be a continuous integer of 1-( n-1 ) ).\n"
      << "   -t: number of threads.\n"
      << "   -r: 0 is semihonest model, 1 is malicous model.\n"
      << "   -u: Run unit test.\n\n"
      << oc::Color::Default;
}

int main(int argc, char **argv) {
  u64 nParties, setSize, pIdx, numthreads;
  bool malicious = false;
  switch (argc) {
  case 11:
    if (argv[1][0] == '-' && argv[1][1] == 'n') {
      nParties = atoi(argv[2]);
    } else
      PrintInfo();
    if (strcmp(argv[3], "-m") == 0) {
      setSize = 1 << atoi(argv[4]);
    } else if (strcmp(argv[3], "-mm") == 0) {
      setSize = atoi(argv[4]);
    } else
      PrintInfo();
    if (argv[5][0] == '-' && argv[5][1] == 'p') {
      pIdx = atoi(argv[6]);
    } else
      PrintInfo();
    if (argv[7][0] == '-' && argv[7][1] == 't') {
      numthreads = atoi(argv[8]);
    } else
      PrintInfo();
    if (strcmp(argv[9], "-r") == 0) {
      if (strcmp(argv[10], "1") == 0)
        malicious = true;
      else
        malicious = false;
      party(nParties, setSize, pIdx, numthreads, malicious, 1);
    } else
      PrintInfo();
    break;
  case 7:
    if (strcmp(argv[1], "-n") == 0)
      nParties = atoi(argv[2]);
    else
      PrintInfo();
    if (strcmp(argv[3], "-m") == 0)
      setSize = 1 << atoi(argv[4]);
    else
      PrintInfo();
    if (strcmp(argv[5], "-r") == 0) {
      malicious = atoi(argv[6]);
      std::vector<std::thread> pThrds(nParties);
      for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
        pThrds[pIdx] = std::thread(
            [&, pIdx]() { party(nParties, setSize, pIdx, 16, malicious, 0); });
      }
      for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        pThrds[pIdx].join();
    } else
      PrintInfo();
    break;
  case 2:
    if (argv[1][0] == '-' && argv[1][1] == 'u') {
      nParties = 60;
      setSize = 1 << 6;
      numthreads = 4;
      malicious = 0;
      std::vector<std::thread> pThrds(nParties);
      for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
        pThrds[pIdx] = std::thread([&, pIdx]() {
          party(nParties, setSize, pIdx, numthreads, malicious, 0);
        });
      }
      for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        pThrds[pIdx].join();
    }
    break;
  default:
    PrintInfo();
    break;
  }
  return 0;
}