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
using namespace osuCrypto;
using namespace volePSI;
void tparty(u64 nParties, u64 setSize, u64 myIdx)
{
  // 初始化计算安全参数和 统计安全参数
  u64 SecParam = 180, StaParam = 40;
  std::string name("psi");
  IOService ios(0);
  u64 numThreads = 1;
  u64 leadIdx = 0;
  // 期望交集
  u64 expectedIntersection = 10;
  std::vector<Endpoint> ep(nParties);

  for (u64 i = 0; i < nParties; ++i)
  {
    if (i < myIdx)
    {
      u32 port = 1200 + i * 100 + myIdx;
      // std::cout<<"i: "<<i<<" pidx: "<<pIdx<<" port:"<<port<<std::endl; // get
      // the same port; i=1 & pIdx=2 =>port=102
      ep[i].start(ios, "localhost", port, SessionMode::Client,
                  name); // channel bwt i and pIdx, where i is sender
    }
    else if (i > myIdx)
    {
      u32 port =
          1200 + myIdx * 100 + i; // get the same port; i=2 & pIdx=1 =>port=102
      // std::cout<<"i: "<<i<<" pidx: "<<pIdx<<" port:"<<port<<std::endl; // get
      // the same port; i=1 & pIdx=2 =>port=102

      ep[i].start(ios, "localhost", port, SessionMode::Server,
                  name); // channel bwt i and pIdx, where i is receiver
    }
  }
  std::vector<std::vector<Channel>> chls(nParties);
  for (u64 i = 0; i < nParties; ++i)
  {

    if (i != myIdx)
    {
      chls[i].resize(numThreads);
      for (u64 j = 0; j < numThreads; ++j)
      {
        chls[i][j] = ep[i].addChannel(name, name);
      }
    }
  }
  u64 num_threads =
      nParties - 1; // except  my
                    //  std::vector<std::thread> pThrds(num_threads);

  // 首先生成 零共享值
  std::vector<PRNG> mPrngs(nParties);

  // std::vector<std::thread> thrds(chls.size());
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
  // 不同用户编号执行不同部分
  if (myIdx == 0)
  {
    // 接收所有其他参与方的零共享值
    std::vector<std::vector<u8>> zeroValue(nParties);
    // leader 生成零共享值
    zeroValue[0].resize(nParties);
    zeroValue[0][0] = 0;
    for (u64 i = 1; i < nParties; i++)
    {
      zeroValue[0][i] = zeroValue[0][i] ^ mPrngs[i].get<u8>();
    }
    for (u64 i = 1; i < nParties; i++)
    {
      zeroValue[i].resize(nParties);
      std::vector<u8> zero_value(nParties);
      chls[i][0].recv(zero_value.data(), zero_value.size());
      zeroValue[i] = zero_value;
    }
    u64 sum = 0;

    // 接收 g^a_i
    REllipticCurve mCurve;
    std::vector<REccPoint> akrandom;
    PRNG prng;
    prng.SetSeed(toBlock(myIdx, myIdx));
    // auto curveParam = Curve25519;
    block mCurveSeed = prng.get<block>();
    // EllipticCurve mCurve(curveParam, OneBlock);
    // REccPoint mG(mCurve);
    auto const mG = mCurve.getGenerator();
    REccNumber eccnum;
    eccnum.randomize(prng);
    REccPoint eccpoint = mCurve;
    eccpoint = mG * eccnum;
    akrandom.emplace_back(mCurve);
    for (u64 i = 1; i < nParties; i++)
    {
      REccPoint eccpoint = mCurve;
      u8 *temp = new u8[eccpoint.sizeBytes()];
      chls[i][0].recv(temp);
      eccpoint.fromBytes(temp);
      akrandom.emplace_back(mCurve);
      akrandom[i] = eccpoint;
    }
    // 创建集合
    std::vector<block> inputs(setSize);
    for (u64 i = 0; i < expectedIntersection; i++)
      inputs[i] = prngSet.get<block>();
    for (u64 i = expectedIntersection; i < setSize; i++)
      inputs[i] = prng1.get<block>();
    // std::cout << "发送方inputs[0]:" << inputs[0] << std::endl;
    // 为leadIdx 创建集合大小的椭圆曲线点
    std::vector<REccNumber> nSeeds;
    std::vector<REccPoint> mypoint;
    std::vector<block> values(setSize);
    // 接收 Eccpoint 的方法
    for (int i = 0; i < setSize; i++)
    {
      nSeeds.emplace_back(mCurve);
      nSeeds[i].randomize(prng);
      mypoint.emplace_back(mCurve);
      mypoint[i] = mG * nSeeds[i]; // g^ri
      values[i] = Eccpoint_to_block(mypoint[i]);
    }

    // OKVS 打包
    Baxos paxos;
    paxos.init(setSize, 64, 3, 40, PaxosParam::GF128, block(0, 0));
    std::vector<block> pax(paxos.size());
    //std::vector<REccPoint> pax(paxos.size());
    // 好像 可以直接 使用 REccpoint 类型为value 后续再看
    paxos.solve<block>(inputs, values, pax, nullptr, 0);
    //paxos.solve<REccPoint>(inputs, mypoint, pax, nullptr, 0);
    // paxos.decode<block>(inputs, values1, pax, 0);
    std::cout << paxos.size() << std::endl;
    // 发送 paxos 的Seed ...
    //  发送 paxos 向量的大小
    for (u64 i = 1; i < nParties; i++)
      chls[i][0].asyncSend(paxos.size());
    // 发送 paxos 向量
    // for (u64 i = 1; i < nParties; i++)
    // {
    //   for (u64 j = 0; j < paxos.size(); j++)
    //   {
    //     u8 *temp = new u8[eccpoint.sizeBytes()];
    //     pax[j].toBytes(temp);
    //     chls[i][0].asyncSend(std::move(temp));
    //   }
    // }

    // // 发送数据集给接收方进行解码成功性测试
    // for(u64 i=1;i<nParties;i++)
    //   chls[i][0].asyncSend(values.data(),values.size());
  }
  else
  {
    // 生成零共享值 并发送给 leaderIdx 方
    std::vector<u8> zero_value(nParties);
    zero_value[0] = 0;
    for (u64 i = 0; i < nParties; i++)
    {
      if (i != myIdx)
      {
        zero_value[i] = zero_value[i] ^ mPrngs[i].get<u8>();
      }
    }
    chls[0][0].send(zero_value.data(), zero_value.size());
    /* 执行 AKOPRF */
    // 1、选择随机数 a_i
    PRNG prng;
    prng.SetSeed(toBlock(myIdx, myIdx));
    u64 aPidx = prng.get<u64>();
    // 计算 g^a  使用 Curve 25519
    // auto curveParam = Curve25519;
    block mCurveSeed = prng.get<block>();
    REllipticCurve mCurve;
    auto const mG = mCurve.getGenerator();
    REccNumber eccnum = mCurve; // a_i
    eccnum.randomize(prng);
    REccPoint eccpoint = mCurve;
    eccpoint = mG * eccnum;
    // send g^a_i
    u8 *temp = new u8[eccpoint.sizeBytes()];
    eccpoint.toBytes(temp);
    chls[0][0].asyncSend(std::move(temp));
    // 接收 paxos seed
    // block seed;
    // chls[0][0].recv(&seed, sizeof(block));
    // std::cout << "接收数据。。。。" << std::endl;
    // std::cout << "接收到的paxos seed: " << seed << std::endl;
    // 接收 paxos 向量大小
    size_t size = 0;
    chls[0][0].recv(size);
    // 接收paxos 向量
    std::vector<block> pax(size);
    // for (u64 i = 0; i < size; i++)
    // {
    //   u8 *temp = new u8[eccpoint.sizeBytes()];
    //   chls[0][0].recv(temp);
    //   pax[i].fromBytes(temp);
    // }

    // chls[0][0].recv(pax.data(), size * sizeof(REccPoint));
    //  创建对应数据集 临时的
    std::vector<block> inputs(setSize);
    for (u64 i = 0; i < expectedIntersection; i++)
      inputs[i] = prngSet.get<block>();
    for (u64 i = expectedIntersection; i < setSize; i++)
      inputs[i] = prng1.get<block>();
    // 初始化 paxos
    Baxos paxos;
    paxos.init(setSize, 64, 3, 40, PaxosParam::GF128, block(0, 0));
    // paxos 解码 values 必须先设置 size
    std::vector<block> values(setSize);
    //std::vector<REccPoint> values(setSize);
    paxos.decode<block>(inputs, values, pax, 0);
    // 接收测试数据进行paxos解码测试
    // std::vector<block> temps(setSize);
    // chls[0][0].recv(temps.data(),temps.size());
    // // 检查解码后的元素是否相同
    // for (u64 i = 0; i < setSize; i++)
    // {
    //   if (temps[i] == values[i])
    //     std::cout << "i:" << i << " equal" << std::endl;
    //   else
    //     std::cout << "i:" << i << " not euqal" << std::endl;
    // }
    // okvs 解码后 再次计算椭圆曲线
    // 首先将okvs解码后的 block 解码为eccpoint
    //  std::vector<REccPoint> px(setSize);   // 存储 g^b_i
    //  for(u64 i=0;i<setSize;i++)
    //    px[i]=block_to_Eccpoint(values[i]);
    // //计算 g^(b_i*a_i)
    // REccPoint tempPoint=px[0]*eccnum;
    // std::cout<<"tempPoint: "<<tempPoint<<std::endl;
  }

  for (u64 i = 0; i < nParties; ++i)
  {
    if (i != myIdx)
    {
      for (u64 j = 0; j < numThreads; ++j)
      {
        chls[i][j].close();
      }
    }
  }

  for (u64 i = 0; i < nParties; ++i)
  {
    if (i != myIdx)
      ep[i].stop();
  }

  ios.stop();
}
// #include "volepsi/volePSI/Paxos.h"
void PrintInfo()
{
  /*
  -u		unit test which computes PSI of 5 paries, 2 dishonestly
  colluding, each with set size 2^12 in semihonest setting
  -n		number of parties
  -p		party ID
  -m		set size
  -t		number of corrupted parties (in semihonest setting)
  -a		run in augmented semihonest model. Table-based OPPRF is by
  default. 0: Table-based; 1: POLY-seperated; 2-POLY-combined; 3-BloomFilter -r
  optimized 3PSI when r = 1
*/

  printf("#####################################################################"
         "\n");
  printf("#####################################################################"
         "\n");
  printf("#                                                                   "
         "#\n");
  printf("#                         MiniMP                                    "
         "#\n");
  printf("#                                                                   "
         "#\n");
  printf("#####################################################################"
         "\n");
  printf("#####################################################################"
         "\n");
  printf("-n		number of parties\n");
  printf("-p		party ID\n");
  printf("-m		set size\n");
}
int main(int argc, char **argv)
{
  u64 nParties = 5, setSize, pIdx;
  switch (argc)
  {
  case 7:
    if (argv[1][0] == '-' && argv[1][1] == 'n')
    {
      nParties = atoi(argv[2]);
    }
    else
      PrintInfo();
    if (argv[3][0] == '-' && argv[3][1] == 'm')
    {
      setSize = 1 << atoi(argv[4]);
    }
    else
      PrintInfo();
    if (argv[5][0] == '-' && argv[5][1] == 'p')
    {
      pIdx = atoi(argv[6]);
      tparty(nParties, setSize, pIdx);
    }

    else
      PrintInfo();
    break;
  case 2:
    if (argv[1][0] == '-' && argv[1][1] == 't')
    {
      nParties = 5;
      setSize = 1 << 5;
      std::cout << nParties << " " << setSize << " " << 0 << std::endl;

      std::vector<std::thread> pThrds(nParties);
      for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
      {
        pThrds[pIdx] =
            std::thread([&, pIdx]()
                        { tparty(nParties, setSize, pIdx); });
      }
      for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
        pThrds[pIdx].join();
    }
    break;
  }
  // std::cout << nParties << " " << setSize << " " << pIdx << std::endl;
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