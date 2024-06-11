/**
 * @description: Dhoprf.cpp
 * @author: XianSong Qian
 * @date: 2024/04/11
 */
#include "Dhoprf.h"

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <macoro/macros.h>
#include <macoro/sync_wait.h>

#include <cassert>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include "cryptoTools/Crypto/SodiumCurve.h"
// #include "defines.h"
using namespace volePSI;
#define Len 2

namespace volePSI {
using Block = typename oc::Rijndael256Enc::Block;
void dhOprfSender::eval(std::vector<block> &outputs) {
  outputs.resize(setSize);
  std::vector<std::thread> pThrds(numThreads);
  for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
    pThrds[pIdx] = std::thread([&, pIdx]() {
      u64 datalen = setSize / pThrds.size();
      u64 startlen = pIdx * datalen;
      u64 endlen = (pIdx + 1) * datalen;
      if (pIdx == pThrds.size() - 1) {
        endlen = setSize;
      }
      for (u64 i = startlen; i < endlen; ++i) {
        Monty25519 g_ab = pkb * ska[i];
        outputs[i] = oc::toBlock((u8 *)&g_ab);
      }
    });
  }
  for (auto &pThrd : pThrds) pThrd.join();
};

Proto dhOprfSender::send(std::vector<block> inputs, PRNG &prng, Socket &chl) {
  MC_BEGIN(Proto, this, inputs, &prng, &chl, paxos = Baxos{},
           userKey = Block{userKeyArr}, encKey = oc::Rijndael256Enc(),
           point = Monty25519{}, permute_ctxt = Block{},
           values = oc::Matrix<block>{}, hash = oc::RandomOracle(sizeof(block)),
           pax = oc::Matrix<block>{}

  );
  setTimePoint("dhoprfSender start");
  encKey.setKey(userKey);
  values.resize(setSize, Len);
  ska.resize(setSize);
  // TODO:prng1 must is a new object
  prng1.SetSeed(oc::toBlock(myIdx, myIdx));

  for (u64 i = 0; i < setSize; i++) {
    ska[i].randomize(prng1);
    point = {Monty25519::wholeGroupGenerator * ska[i]};
    permute_ctxt = encKey.encBlock(Block256((u8 *)&point));
    values[i][0] = oc::toBlock(permute_ctxt.data());
    values[i][1] = oc::toBlock(permute_ctxt.data() + sizeof(block));
  }

  if (malicious) {
    for (u64 i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      hash.Final(inputs[i]);
    }
  }
  MC_AWAIT(chl.recv(pkb));

  // Baxos paxos;
  paxos.init(setSize, 1 << 14, 3, stasecParam, PaxosParam::GF128, block(1, 1));
  pax.resize(paxos.size(), Len);
  paxos.solve<block>(inputs, values, pax, &prng, numThreads);
  MC_AWAIT(chl.send(paxos.size()));
  MC_AWAIT(chl.send(coproto::copy(pax)));
  setTimePoint("dhoprfSender end");
  MC_END();
}
Proto dhOprfReceiver::receive(std::vector<block> inputs,
                              std::vector<block> &outputs, PRNG &prng,
                              Socket &chl) {
  MC_BEGIN(Proto, this, inputs, &outputs, &prng, &chl, paxos = Baxos{},
           userKey = Block{userKeyArr}, decKey = oc::Rijndael256Dec(),
           skb = Scalar25519{}, pkb = Monty25519{}, pax = oc::Matrix<block>{},
           paxosSize = size_t{}, deValues = oc::Matrix<block>(setSize, Len),
           threads = std::vector<std::thread>(numThreads),
           hash = oc::RandomOracle(sizeof(block)));
  setTimePoint("dhoprfReceiver start");
  decKey.setKey(userKey);
  skb.randomize(prng);
  pkb = {Monty25519::wholeGroupGenerator * skb};
  // send msg
  MC_AWAIT(chl.send(pkb));
  MC_AWAIT(chl.recv(paxosSize));
  pax.resize(paxosSize, Len);
  MC_AWAIT(chl.recv(pax));
  if (malicious) {
    for (u64 i = 0; i < setSize; i++) {
      hash.Reset();
      hash.Update(inputs[i]);
      hash.Final(inputs[i]);
    }
  }
  paxos.init(setSize, 1 << 14, 3, stasecParam, volePSI::PaxosParam::GF128,
             block(1, 1));
  paxos.decode<block>(inputs, deValues, pax, numThreads);

  //   compute oprf value
  outputs.resize(setSize);
  for (u64 idx = 0; idx < threads.size(); ++idx) {
    threads[idx] = std::thread([&, idx]() {
      u64 datalen = setSize / threads.size();
      u64 startlen = idx * datalen;
      u64 endlen = (idx + 1) * datalen;
      if (idx == threads.size() - 1) {
        endlen = setSize;
      }
      for (auto i = startlen; i < endlen; i++) {
        auto *g_a = new unsigned char[crypto_scalarmult_BYTES];
        mempcpy(g_a, &deValues[i][0], sizeof(block));
        mempcpy(g_a + sizeof(block), &deValues[i][1], sizeof(block));
        auto g_f = decKey.decBlock((Block256(g_a)));
        g_a = g_f.data();
        Monty25519 g_bi;
        g_bi.fromBytes(g_a);
        Monty25519 g_bia = g_bi * skb;
        /*
        When the number of participants is two, shorter data can be
        intercepted keyLength=40+log(setSize*setSize) But there are some
        issues that still need to be dealt with, so here's a uniform 128bit
        intercept
         */
        outputs[i] = oc::toBlock((u8 *)&g_bia);
      }
    });
  }
  for (auto &thread : threads) thread.join();
  setTimePoint("dhoprfReceiver end");
  MC_END();
};

}  // namespace taihang