// Copyright 2023 xiansongq.

#include "cPsiSender.h"

#include <cryptoTools/Circuit/BetaCircuit.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <macoro/sync_wait.h>
#include <sodium/crypto_core_ristretto255.h>

#include <cstring>
#include <memory>

#include "miniMPSI/tools.h"
#include "volePSI/Defines.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto;
// #define Debug
namespace volePSI {

void cPsiSender::init(u64 senderSize, u64 receiverSize, u64 mValueByteLength,
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

void cPsiSender::send(span<block> Y, oc::MatrixView<u8> values, Sharing& s,
                      Socket& chl) {
  // choise a random curver value
  using Block = typename Rijndael256Enc::Block;
  const std::uint8_t userKeyArr[] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };
  Block userKey = Block256(userKeyArr);
  Rijndael256Dec decKey(userKey);
  PRNG prng;
  block seed = oc::sysRandomSeed();
  prng.SetSeed(seed);
  Scalar25519 mK(prng);

  Monty25519 mG_k = Monty25519::wholeGroupGenerator * mK;
  // send g^a
  setTimePoint("cpsi:sender start");
  macoro::sync_wait(chl.send(mG_k));
  Baxos paxos;
  paxos.init(senderSize, 1 << 14, 3, mSsp, PaxosParam::GF128, block(0, 0));
  size_t size;
  macoro::sync_wait(chl.recv(size));
  Matrix<block> pax(size, 2);

  macoro::sync_wait(chl.recv(pax));  
  Matrix<block> deval(receiverSize, 2);
  paxos.decode<block>(Y, deval, pax, numThreads);

#ifdef Debug
  std::cout << "sender decode\n";
  for (u64 i = 0; i < receiverSize; i++) {
    std::cout << "decode i: " << i << " " << deval[i][0] << " " << deval[i][1]
              << std::endl;
  }
#endif

  u64 keyBitLength = mSsp + oc::log2ceil(receiverSize* senderSize);
  u64 keyByteLength = oc::divCeil(keyBitLength, 8);
  Matrix<u8> Tv;
  std::vector<block> Ty;

  Matrix<u8> r;
  Matrix<u8>::iterator TvIter;
  Matrix<u8>::iterator rIter;
  std::vector<block>::iterator TyIter;
  Ty.resize(senderSize);
  Tv.resize(senderSize, keyByteLength + values.cols(),
            oc::AllocType::Uninitialized);
  r.resize(senderSize, keyByteLength, oc::AllocType::Uninitialized);
  s.mValues.resize(senderSize, values.cols(), oc::AllocType::Uninitialized);
  mPrng.get<u8>(s.mValues);
  mPrng.get<u8>(r);

  TvIter = Tv.begin();
  rIter = r.begin();
  TyIter = Ty.begin();

  oc::RandomOracle hash(sizeof(block));
  for (u64 i = 0; i < receiverSize; i++) {
    auto g_f = decKey.decBlock(Block256(deval[i][0],deval[i][1]));
    Monty25519 g_bi;
    g_bi.fromBytes(g_f.data());
    Monty25519 g_bia = g_bi * mK;

    // hash.Reset();
    // hash.Update(g_bia);
    // block hh=toBlock((u8 *)&g_bia);
    // hash.Final(hh);
    // memcpy(&hh,&g_bia,sizeof(block));
    Ty[i]=toBlock((u8 *)&g_bia);
    memcpy(&*TvIter, &*rIter, keyByteLength);
    TvIter += keyByteLength;

    if (values.size()) {
      memcpy(&*TvIter, &values(i, 0), values.cols());

      if (mType == valueShareType::Xor) {
        for (u64 k = 0; k < values.cols(); ++k) {
          TvIter[k] ^= s.mValues(i, k);
        }
      } else if (mType == valueShareType::add32) {
        assert(values.cols() % sizeof(u32) == 0);
        auto ss = values.cols() / sizeof(u32);
        auto tv = (u32*)TvIter;
        auto rr = (u32*)&s.mValues(i, 0);
        for (u64 k = 0; k < ss; ++k) tv[k] -= rr[k];
      } else
        throw RTE_LOC;
      TvIter += values.cols();
    }
    rIter += keyByteLength;
  }


  // auto opprf=std::make_unique<RsOpprfSender>() ;
  // macoro::sync_wait ( opprf->send(receiverSize,Ty,Tv,mPrng,numThreads,chl));
  
  Baxos paxos1;
  paxos1.init(senderSize, 1 << 14, 3, mSsp, PaxosParam::Binary, block(0, 0));
  Matrix<u8> pax2(paxos1.size(), keyByteLength + values.cols());
  paxos1.solve<u8>(Ty, Tv, pax2, &mPrng, numThreads);
  macoro::sync_wait(chl.send(paxos1.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax2)));            // NOLINT

  std::unique_ptr<Gmw> cmp = std::make_unique<Gmw>();
  BetaCircuit cir;
  cir = isZeroCircuit(keyBitLength);
  cmp->init(r.rows(), cir, numThreads, 1, mPrng.get());
  cmp->setInput(0, r);
  macoro::sync_wait(cmp->run(chl));

  {
    auto ss = cmp->getOutputView(0);
    s.mFlagBits.resize(senderSize);
    std::copy(ss.begin(), ss.begin() + s.mFlagBits.sizeBytes(),
              s.mFlagBits.data());
  }
  setTimePoint("cpsi:sender end");
}

}  // namespace volePSI