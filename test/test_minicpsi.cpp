// #include <macoro/sync_wait.h>
#include <volePSI/RsOprf.h>

#include <thread>

// #include "../common/defines.h"
#include "../cpsi/cpsi.h"
#include "../frontend/Common.h"
#include "volePSI/Defines.h"
// #include "Dhoprf.h"

// using namespace taihang;
using namespace volePSI;
void cpsi(oc::CLP& cmd) {
  u64 setSize = 1 << cmd.getOr("m", 4);
  u64 numThreads = cmd.getOr("nt", 1);
  u64 t = cmd.getOr("st", 1);
  valueShareType type = (t == 1) ? valueShareType::Xor : valueShareType::add32;
  std::vector<block> recvSet(setSize);
  std::vector<block> sendSet(setSize);
  PRNG prngSet(_mm_set_epi32(4253465, 3434565, 234435, 0));
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
  oc::Matrix<u8> senderValues(sendSet.size(), sizeof(block));
  std::memcpy(senderValues.data(), sendSet.data(),
              sendSet.size() * sizeof(block));
  auto sockets = coproto::LocalAsyncSocket::makePair();
  std::vector<std::thread> pThrds(2);
  minicpsiReceiver receive;
  minicpsiSender sender;

  minicpsiReceiver::Sharing rShare;
  minicpsiSender::Sharing sShare;
  Timer timer;
  receive.setTimer(timer);
  Timer timer1;
  sender.setTimer(timer1);

  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx] = std::thread([&, pIdx]() {
      if (pIdx == 0) {
        receive.init(setSize, setSize, sizeof(block), 40, numThreads, type);
        macoro::sync_wait(receive.receive(recvSet, rShare, sockets[0]));
      } else {
        sender.init(setSize, setSize, sizeof(block), 40, numThreads, type);
        macoro::sync_wait(
            sender.send(sendSet, senderValues, sShare, sockets[1]));
      }
    });
  }
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx].join();
  }

  /*   receive.init(setSize, setSize, sizeof(block), 40, numThreads, type);
    sender.init(setSize, setSize, sizeof(block), 40, numThreads, type);

    Proto p1 = receive.receive(recvSet, rShare, sockets[0]);
    Proto p2 = sender.send(sendSet, senderValues, sShare, sockets[1]);

    eval(p1, p2); */
  /*
      RsOprfSender senders;
      RsOprfReceiver recvers;

      auto sockets = coproto::LocalAsyncSocket::makePair();
      u64 n = 4000;
      PRNG prng0(block(0, 0));
      PRNG prng2(block(0, 1));

      std::vector<block> vals(n), recvOut(n);

      prng0.get(vals.data(), n);
      std::cout << "rsoprf start\n";
      auto p0 = senders.send(n, prng0, sockets[0]);
      auto p1 = recvers.receive(vals, recvOut, prng2, sockets[1]);


      eval(p0, p1);
      std::cout <<  "rsoprf end\n";
      std::vector<block> vv(n);
      senders.eval(vals, vv);

      u64 count = 0;
      for (u64 i = 0; i < n; ++i)
      {
          auto v = senders.eval(vals[i]);
          if (recvOut[i] != v || recvOut[i]  != vv[i])
          {
              if (count < 10)
                  std::cout << i << " " << recvOut[i] << " " <<v <<" " << vv[i]
     << std::endl; else break;

              ++count;
          }
      }
      if (count)
          throw RTE_LOC; */

  std::cout << sender.getTimer() << std::endl;
  std::cout << receive.getTimer() << std::endl;

  bool failed = false;
  std::vector<u64> intersection;
  for (u64 i = 0; i < recvSet.size(); ++i) {
    auto k = rShare.mMapping[i];
    if (rShare.mFlagBits[k] ^ sShare.mFlagBits[k]) {
      intersection.push_back(i);

      if (type == valueShareType::Xor) {
        auto rv = *(block*)&rShare.mValues(k, 0);
        auto sv = *(block*)&sShare.mValues(k, 0);
        auto act = (rv ^ sv);
        // std::cout << recvSet[i] << " " << rv << " " << sv << "\n";
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
  std::cout << "intersection  size: " << intersection.size() << std::endl;
}

int main(int argc, char** argv) {
  oc::CLP cmd(argc, argv);
  cpsi(cmd);
  return 0;
}