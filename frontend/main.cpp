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

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/Rijndael256.h"
#include "tools.h"
#include "volePSI/Paxos.h"
#include "coproto/Socket/AsioSocket.h"
#include "miniMPSI.h"
using namespace osuCrypto;
using namespace volePSI;
void PrintParamInfo(u64 nParties, u64 setSize, u64 SecParam, u64 StaParam, bool malicious)
{

  std::cout << std::left << std::setw(15) << "参与方数量：" << nParties << std::endl;
  std::cout << std::left << std::setw(15) << "集合大小：" << setSize << std::endl;
  std::cout << std::left << std::setw(15) << "计算安全参数：" << SecParam << std::endl;
  std::cout << std::left << std::setw(15) << "统计安全参数：" << StaParam << std::endl;
  std::cout << std::left << std::setw(15) << "是否恶意安全：" << (malicious == 1 ? "是" : "否") << std::endl;
}
void tparty(u64 nParties, u64 setSize, u64 myIdx, u64 num_Threads)
{
  // 初始化计算安全参数和 统计安全参数
  u64 SecParam = 180,
      StaParam = 40;
  bool malicious = 0;
  std::string name("psi");
  if (myIdx == 0)
    PrintParamInfo(nParties, setSize, SecParam, StaParam, malicious);
  IOService ios(0);
  u64 numThreads = num_Threads;
  u64 leadIdx = 0;
  // 期望交集
  u64 expectedIntersection = 200;
  std::vector<oc::Socket> chls(nParties);
  for (u64 i = 0; i < nParties; ++i)
  {
    if (i < myIdx)
    {
      u32 port = 1200 + i * 100 + myIdx;
      // chls[i].resize(numThreads);
      std::string ip = "localhost:" + std::to_string(port);
      // std::cout << "ip: " << ip << std::endl;
      //  chls[i] = coproto::asioConnect(ip, 1);
      //  chls[i].resize(numThreads);
      chls[i] = coproto::asioConnect(ip, 0);
      /*       for (u64 j = 0; j < numThreads; j++)
            {
              try
              {
                chls[i][j] = coproto::asioConnect(ip, 0);
              }
              catch (const std::exception &e)
              {
                std::cout << "error" << std::endl;
              }
            } */
    }
    else if (i > myIdx)
    {
      u32 port = 1200 + myIdx * 100 + i; // get the same port; i=2 & pIdx=1 =>port=102
                                         // chls[i].resize(numThreads);
      std::string ip = "localhost:" + std::to_string(port);
      // std::cout << "ip: " << ip << std::endl;
      //  chls[i] = coproto::asioConnect(ip, 0);
      chls[i] = coproto::asioConnect(ip, 1);
      /*       chls[i].resize(numThreads);
            for (u64 j = 0; j < numThreads; j++)
            {
              try
              {
                chls[i][j] = coproto::asioConnect(ip, 1);
              }
              catch (const std::exception &e)
              {
                std::cout << "error" << std::endl;
              }
            } */
    }
  }
  // 首先生成 零共享值
  std::vector<PRNG> mPrngs(nParties);
  std::mutex mtx;
  PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
  PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
  std::vector<std::vector<block>> zsSeeds(nParties); // 存储随机种子

  // 为每个用户生成nparties个随机种子
  for (u64 i = 0; i < nParties; i++)
  {
    zsSeeds[i].resize(nParties);
    for (u64 j = 0; j < nParties; j++)
    {
      if (i <= j)
      {
        zsSeeds[i][j] = prng0.get<block>();
      }
      else
        zsSeeds[i][j] = zsSeeds[j][i];
    }
  }
  mPrngs.resize(nParties);
  for (u64 i = 0; i < nParties; i++)
  {
    mPrngs[i].SetSeed(zsSeeds[myIdx][i]);
  }
  if (myIdx == 0)
  {
    // 创建集合
    std::vector<block> inputs(setSize);
    for (u64 i = 1; i < expectedIntersection + 1; i++)
      inputs[i] = prngSet.get<block>();
    prng1.SetSeed(block(myIdx, myIdx));
    for (u64 i = expectedIntersection + 1; i < setSize; i++)
      inputs[i] = prng1.get<block>();
    inputs[0] = prng1.get<block>();

    // std::cout << "inputs" << std::endl;
    // for (auto a : inputs)
    // {
    //   std::cout << a << std::endl;
    // }
    volePSI::miniMPSIReceiver receiver;
    receiver.init(128, 40, nParties, myIdx, setSize, inputs, false, numThreads);
    macoro::sync_wait(receiver.receive(mPrngs, chls, numThreads));
  }
  else
  {

    std::vector<block> inputs(setSize);
    for (u64 i = 1; i < expectedIntersection + 1; i++)
      inputs[i] = prngSet.get<block>();
    prng1.SetSeed(block(myIdx, myIdx));
    for (u64 i = expectedIntersection + 1; i < setSize; i++)
      inputs[i] = prng1.get<block>();
    inputs[0] = prng1.get<block>();

    // std::cout << "inputs" << std::endl;
    // for (auto a : inputs)
    // {
    //   std::cout << a << std::endl;
    // }
    volePSI::miniMPSISender sender;
    sender.init(128, 40, nParties, myIdx, setSize, inputs, false, numThreads);
    macoro::sync_wait(sender.send(mPrngs, chls, numThreads));
  }
}

// #include "volepsi/volePSI/Paxos.h"
void PrintInfo()
{
  std::cout << oc::Color::Green << "#####################################################################\n"
            << "#####################################################################\n"
            << "#                                                                   #\n"
            << "#                             miniMSPI                              #\n"
            << "#                                                                   #\n"
            << "#####################################################################\n"
            << "#####################################################################\n";
  std::cout << oc::Color::Green << "Parameter description: \n"
            << oc::Color::Blue
            << "   -n: number of parties.\n"
            << "   -m: input set size ( 2^m ).\n"
            << "   -mm: input set size ( mm ).\n"
            << "   -p: the party id (must be a continuous integer of 1-( n-1 ) ).\n"
            << "   -t: number of threads.\n"
            << "   -u: Run unit test.\n\n";
}
int main(int argc, char **argv)
{
  u64 nParties, setSize, pIdx, numthreads;
  switch (argc)
  {
  case 9:
    if (argv[1][0] == '-' && argv[1][1] == 'n')
    {
      nParties = atoi(argv[2]);
    }
    else
      PrintInfo();
    if (strcmp(argv[3], "-m") == 0)
    {
      setSize = 1 << atoi(argv[4]);
    }
    else if (strcmp(argv[3], "-mm") == 0)
    {
      setSize = atoi(argv[4]);
    }
    else
      PrintInfo();
    if (argv[5][0] == '-' && argv[5][1] == 'p')
    {
      pIdx = atoi(argv[6]);
    }
    else
      PrintInfo();
    if (argv[7][0] == '-' && argv[7][1] == 't')
    {
      numthreads = atoi(argv[8]);
      tparty(nParties, setSize, pIdx, numthreads);
    }
    else
      PrintInfo();

    break;
  case 2:
    if (argv[1][0] == '-' && argv[1][1] == 'u')
    {
      nParties = 32;
      setSize = 1 << 9;
      numthreads = 6;
      std::vector<std::thread> pThrds(nParties);
      for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
      {
        pThrds[pIdx] =
            std::thread([&, pIdx]()
                        { tparty(nParties, setSize, pIdx, numthreads); });
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

/* int main(int argc, char** argv)
{
    oc::CLP cmd(argc, argv);

    //std::ofstream file("./set.csv");
    //for (oc::u64 i = 0; i < 10000000; ++i)
    //    file << std::setfill('0') << std::setw(32) << i << "\n";
    //return 0;
    if (cmd.isSet("in"))
    {
        volePSI::doFilePSI(cmd);
    }
    else if (cmd.isSet("messagePassing"))
    {
        messagePassingExample(cmd);
    }
    else if (cmd.isSet("net"))
    {
        networkSocketExample(cmd);
    }
    else if (cmd.isSet("exp"))
    {
        Paxos_experiment(cmd);
    }
    else if (cmd.isSet("perf"))
    {
        perf(cmd);
    }
    else if (cmd.isSet("balls"))
    {
        overflow(cmd);
    }
    else if(cmd.isSet("u"))
    {
        auto r = volePSI_Tests::Tests.runIf(cmd);
        return r == oc::TestCollection::Result::failed;
    }
    else
    {

        std::cout << oc::Color::Green << "File based PSI Parameters:\n" <<
oc::Color::Default
            << "   -in <value>: The path to the party's set. Should either be a
binary file containing 16 byte elements with a .bin extension. "
            << "Otherwise the path should have a .csv extension and have one
element per row, 32 char hex rows are preferred. \n"

            << "   -r <value>: value should be in { 0, 1 } where 0 means PSI
sender.\n"

            << "   -out <value>: The output file path. Will be written in the
same format as the input. (Default = in || \".out\")\n"
            << "   -quiet: print less info.\n"
            << "   -v: print more info.\n"
            << "   -indexSet: output the index set of the intersection instead
of the set element itself\n"
            << "   -noSort: do not require the output to be in the same order
and the input (slightly faster)."
            << "   -malicious: run the protocol with malicious security\n"
            << "   -useSilver: run the protocol with the Silver Vole encoder
(experimental, default is expand accumulate)\n"
            << "   -useQC: run the protocol with the QuasiCyclic Vole encoder
(default is expand accumulate)\n"
            << "   -ssp: Statistical Security parameter, default = 40.\n\n"

            << "   -ip <value>: IP address and port of the server = PSI
receiver. (Default = localhost:1212)\n"
            << "   -server <value>: Value should be in {0, 1} and indicates if
this party should be the IP server. (Default = r)\n"
            << "   -tls: run the protocol with TLS. Must also set -CA,-sk,-pk\n"
            << "   -CA <value>: if tls, then this must be the path to the CA
cert file in pem format\n"
            << "   -pk <value>: if tls, then this must be the path to this
parties public key cert file in pem format\n"
            << "   -sk <value>: if tls, then this must be the path to this
parties private key file in pem format\n\n"

            << "   -bin: Optional flag to always interpret the input file as
binary.\n"
            << "   -csv: Optional flag to always interpret the input file as a
CSV.\n"
            << "   -receiverSize <value>: An optional parameter to specify the
receiver's set size.\n"
            << "   -senderSize <value>: An optional parameter to specify the
sender's set size.\n\n"

            ;


        std::cout << oc::Color::Green << "Example programs: \n" <<
oc::Color::Default
            << "   -messagePassing: Runs the message passing example program.
This example shows how to manually pass messages between the PSI parties. Same
parameters as File base PSI can be used.\n"
            << "   -net: Run the network socket (TCP/IP or TLS) example program.
This example shows how to run the protocol on the coproto network socket. Same
parameters as File base PSI can be used.\n\n"

            ;


        std::cout << oc::Color::Green << "Benchmark programs: \n" <<
oc::Color::Default
            << "   -perf: required flag to run benchmarking\n"
            << "   -psi: Run the PSI benchmark.\n"
            << "      -nn <value>: the log2 size of the sets.\n"
            << "      -t <value>: the number of trials.\n"
            << "      -malicious: run with malicious security.\n"
            << "      -v: verbose.\n"
            << "      -nt: number of threads.\n"
            << "      -fakeBase: use fake base OTs.\n"
            << "      -nc: do not compress the OPRF outputs.\n"
            << "      -useSilver: run the protocol with the Silver Vole encoder
(experimental, default is expand accumulate)\n"
            << "      -useQC: run the protocol with the QuasiCyclic Vole encoder
(default is expand accumulate)\n"
            << "      -bs: the okvs bin size.\n"
            << "   -cpsi: Run the circuit psi benchmark.\n"
            << "      -nn <value>: the log2 size of the sets.\n"
            << "      -t <value>: the number of trials.\n"
            << "      -v: verbose.\n"
            << "      -nt: number of threads.\n"
            << "   -paxos: Run the okvs benchmark.\n"
            << "      -n <value>: The set size. Can also set n using -nn wher
n=2^nn.\n"
            << "      -t <value>: the number of trials.\n"
            << "      -b <value>: The bitcount of the index type. Must by a
multiple of 8 and greater than 1.3*n.\n"
            << "      -v: verbose.\n"
            << "      -w <value>: The okvs weight.\n"
            << "      -ssp <value>: statistical security parameter.\n"
            << "      -binary: binary okvs dense columns.\n"
            << "      -cols: The size of the okvs elemenst in multiples of 16
bytes. default = 1.\n"
            << "   -baxos: The the bin okvs benchmark. Same parameters as -paxos
plus.\n"
            << "      -lbs <value>: the log2 bin size.\n"
            << "      -nt: number of threads.\n"

            ;





        std::cout << oc::Color::Green << "Unit tests: \n" << oc::Color::Default
            << "   -u: Run all of the unit tests.\n"
            << "   -u -list: List run all of the unit tests.\n"
            << "   -u 10 15: Run unit test 10 and 15.\n"
            << "   -u 10..15: Run unit test 10 to 15 (exclusive).\n"
            << "   -u psi: Run unit test that contain \"psi\" is the title.\n\n"
            ;
    }

    return 0;
} */