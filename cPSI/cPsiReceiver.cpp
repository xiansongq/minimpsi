// Copyright 2023 xiansongq.

#include "cPsiReceiver.h"

#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/AES.h>
#include <macoro/sync_wait.h>

#include <cstddef>
#include <cstring>

#include "volePSI/Defines.h"
#include "volePSI/Paxos.h"
#include "volePSI/RsOpprf.h"
// using namespace osuCrypto;
// #define Debug

namespace volePSI {
void cPsiReceiver::init(u64 senderSize, u64 receiverSize, u64 mValueByteLength,
                        u64 mSsp, u64 numThreads, block seed,
                        valueShareType mType) {
  this->senderSize = senderSize;
  this->receiverSize = receiverSize;
  this->mValueByteLength = mValueByteLength;
  this->mSsp = mSsp;
  this->numThreads = numThreads;
  this->mPrng.SetSeed(seed);
  this->mType = mType;
}

void cPsiReceiver::receive(span<block> X, Sharing& ret, Socket& chl) {
  // recv data
  using Block = typename oc::Rijndael256Enc::Block;
  const std::uint8_t userKeyArr[] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };
  Block userKey = oc::Block256(userKeyArr);
  oc::Rijndael256Enc encKey(userKey);

  Monty25519 mG_a;
  std::vector<Scalar25519> allSeeds(receiverSize);

  Baxos paxos;
  PRNG prng;
  block seed = oc::sysRandomSeed();
  prng.SetSeed(seed);
  paxos.init(receiverSize, 1 << 14, 3, mSsp, PaxosParam::GF128, block(0, 0));
  Matrix<block> vals(receiverSize, 2);

  for (u64 i = 0; i < receiverSize; i++) {
    allSeeds[i].randomize(prng);
    Monty25519 point = {Monty25519::wholeGroupGenerator * allSeeds[i]};
    auto permute_ctxt = encKey.encBlock(oc::Block256((u8*)&point));
    vals[i][0] = oc::toBlock(permute_ctxt.data());
    vals[i][1] = oc::toBlock(permute_ctxt.data() + sizeof(block));
  }

  setTimePoint("cpsi:receiver start");

  macoro::sync_wait(chl.recv(mG_a));
  Matrix<block> pax(paxos.size(), 2);
  paxos.solve<block>(X, vals, pax, &mPrng, numThreads);
  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax)));  // NOLINT
  ret.mMapping.resize(X.size(), ~u64(0));

  std::vector<block> valx(receiverSize);
  oc::RandomOracle hash(sizeof(block));
  for (u64 i = 0; i < receiverSize; i++) {
    Monty25519 g_ab = mG_a * allSeeds[i];
    memcpy(&valx[i], &g_ab, sizeof(block));
    ret.mMapping[i] = i;
  }

  u64 keyBitLength = mSsp + oc::log2ceil(receiverSize * senderSize);
  u64 keyByteLength = oc::divCeil(keyBitLength, 8);
  
  Baxos paxos1;
  paxos1.init(receiverSize, 1 << 14, 3, mSsp, PaxosParam::Binary, block(0, 0));
  size_t size;
  macoro::sync_wait(chl.recv(size));
  Matrix<u8> pax2(size, keyByteLength + mValueByteLength);
  macoro::sync_wait(chl.recv(pax2));  // NOLINT
  Matrix<u8> r(receiverSize, keyByteLength + mValueByteLength);
  paxos1.decode<u8>(valx, r, pax2, numThreads);

  std::unique_ptr<Gmw> cmp = std::make_unique<Gmw>();
  BetaCircuit cir;
  cir = isZeroCircuit(keyBitLength);
  cmp->init(r.rows(), cir, numThreads, 0, mPrng.get());

  cmp->implSetInput(0, r, r.cols());

  macoro::sync_wait(cmp->run(chl));

  {
    auto ss = cmp->getOutputView(0);

    ret.mFlagBits.resize(receiverSize);
    std::copy(ss.begin(), ss.begin() + ret.mFlagBits.sizeBytes(),
              ret.mFlagBits.data());

    if (mValueByteLength) {
      ret.mValues.resize(receiverSize, mValueByteLength);

      for (u64 i = 0; i < receiverSize; ++i) {
        std::memcpy(&ret.mValues(i, 0), &r(i, keyByteLength), mValueByteLength);
      }
    }
  }
  setTimePoint("cpsi:receiver end");
}

}  // namespace volePSI