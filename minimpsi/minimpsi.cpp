/**
* @description: minimpsi.cpp
* @author: XianSong Qian
* @date: 2024/06/08
*/
#include "minimpsi.h"

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/SodiumCurve.h>
#include <macoro/coro_frame.h>
#include <macoro/sync_wait.h>

#include "Dhoprf.h"

// #define debug
namespace volePSI {

void miniMpsiSender::send(std::vector<PRNG> &mseed, PRNG &prng,
                          std::vector<block> inputs, Socket &chl) {
  setTimePoint("minimpsi:sender " + std::to_string(myIdx) + " start");
  std::vector<block> zeroValue(nParties);
  zeroValue[0] = oc::toBlock(0, 0);

  for (u64 i = 0; i < nParties; i++) {
    if (i != myIdx) {
      zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
    }
  }

  dhOprfReceiver receiver;
  if (mTimer) receiver.setTimer(*mTimer);
  std::vector<block> outputs;

  receiver.init(setSize, numThreads, malicious, stasecParam, myIdx);
  macoro::sync_wait(receiver.receive(inputs, outputs, prng, chl));

#ifdef debug
  for (auto a : outputs) std::cout << "sender oprf: " << a << std::endl;
#endif

  for (u64 i = 0; i < outputs.size(); i++) {
    for (u64 j = 0; j < nParties; j++) {
      outputs[i] = outputs[i] ^ zeroValue[j];
    }
  }

#ifdef debug
  for (auto a : outputs) std::cout << "sender oprf(zs): " << a << std::endl;
#endif

  Baxos paxos;
  auto hash = oc::RandomOracle(sizeof(block));
  if (malicious) {
    for (u64 i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      hash.Final(inputs[i]);
    }
  }
  paxos.init(setSize, 1 << 14, 3, stasecParam, PaxosParam::GF128, block(1, 1));
  std::vector<block> pax2(paxos.size());
  paxos.solve<block>(inputs, outputs, pax2, &prng, numThreads);
  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax2)));
  macoro::sync_wait(chl.flush());
  setTimePoint("minimpsi:sender " + std::to_string(myIdx) + " end");
};

void miniMpsiReceiver::receive(std::vector<PRNG> &mseed, PRNG &prng,
                               std::vector<block> inputs,
                               std::vector<block> &outputs,
                               std::vector<block> &sOprfVal, Socket &chl) {
  setTimePoint("minimpsi:receiver start");
  oc::Matrix<block> values(setSize, 2);
  outputs.resize(setSize);

  dhOprfSender sender;
  if (mTimer) {
    sender.setTimer(*mTimer);
  }
  sender.init(setSize, numThreads, malicious, stasecParam, myIdx);
  std::vector<Scalar25519> ska(setSize);
  prng.SetSeed(oc::toBlock(myIdx, myIdx));
  macoro::sync_wait(sender.send(inputs, prng, chl));
  sender.eval(outputs);

#ifdef debug
  for (auto a : outputs) std::cout << "receiver oprf: " << a << std::endl;
#endif

  Baxos paxos;
  auto hash = oc::RandomOracle(sizeof(block));
  if (malicious) {
    for (u64 i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      hash.Final(inputs[i]);
    }
  }
  sOprfVal.resize(setSize);
  paxos.init(setSize, 1 << 14, 3, stasecParam, PaxosParam::GF128, block(1, 1));
  size_t size;
  macoro::sync_wait(chl.recv((size)));
  std::vector<block> pax2(size);
  macoro::sync_wait(chl.recv((pax2)));
  paxos.decode<block>(inputs, sOprfVal, pax2, numThreads);
  setTimePoint("minimpsi:receiver get oprf value end");
}
}  // namespace taihang