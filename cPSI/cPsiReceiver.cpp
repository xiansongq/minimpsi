#include "cPsiReceiver.h"

#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/AES.h>
#include <macoro/sync_wait.h>

#include <cstddef>

#include "volePSI/Defines.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto;
#define Debug
namespace volePSI {
void cPsiReceiver::init(u64 senderSize, u64 receiverSize, u64 mValueByteLength,
                        u64 mSsp, u64 numThreads, block seed,
                        ValueShareType mType) {
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
  auto *mg_k = new unsigned char[crypto_core_ristretto255_BYTES];
  macoro::sync_wait(chl.recv(mg_k));
    std::cout << "receiver mg_k: " << toBlock(mg_k) << " " << toBlock(mg_k + sizeof(block))
            << "\n";
  std::vector<unsigned char*> allSeeds(receiverSize);
  Baxos paxos;
  paxos.init(receiverSize, 1 << 14, 3, mSsp, PaxosParam::GF128, block(0, 0));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  auto* mk = new unsigned char[crypto_core_ristretto255_BYTES];
  Matrix<block> vals(receiverSize, 2);

  for (u64 i = 0; i < receiverSize; i++) {
    allSeeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];
    prng1.implGet(allSeeds[i], crypto_core_ristretto255_BYTES);
    std::cout<<"allSeeds i="<<i<<" "<<toBlock(allSeeds[i])<<" "<<toBlock(allSeeds[i]+sizeof(block))<<std::endl;
    // crypto_core_ristretto255_scalar_random(allSeeds[i]);
    crypto_scalarmult_ristretto255_base(mk, allSeeds[i]);  // g^k
    vals[i][0] = toBlock(mk);
    vals[i][1] = toBlock(mk + sizeof(block));
  }
    std::cout<<"receiver encode\n";
  for(u64 i =0;i<receiverSize;i++) {
    std::cout<<"encode i: "<<i<<" "<<vals[i][0]<<" "<<vals[i][1]<<std::endl;

  }
  Matrix<block> pax(paxos.size(), 2);
  paxos.solve<block>(X, vals, pax, &mPrng, numThreads);
  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax)));  // NOLINT
  // std::cout << "receiver pax" << std::endl;
  // for (u64 i = 0; i < paxos.size(); i++) {
  //   std::cout << pax(i, 0) << "  " << pax(i, 1) << std::endl;
  // }
  // std::cout << "---";
  // 计算 g^a^b
  ret.mMapping.resize(X.size(), ~u64(0));

  std::vector<block> valx(receiverSize);
  oc::RandomOracle hash(sizeof(block));
  Matrix<block> allkey(receiverSize, 2);
  for (u64 i = 0; i < receiverSize; i++) {
    auto* g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
    crypto_scalarmult_ristretto255(g_ab, allSeeds[i],  // NOLINT
                                   mg_k);
    // allkey[i][0] = toBlock(g_ab);
    // allkey[i][1] = toBlock(g_ab + sizeof(block));
    // memcpy(r[i].data(), &g_ab, sizeof(block));
    // memcpy(r[i].data() + sizeof(block), &g_ab + sizeof(block),
    // sizeof(block));
    std::cout<<"receiver i: "<<i<<" "<<toBlock(g_ab)<<" "<<toBlock(g_ab + sizeof(block))<<std::endl;
    // hash.Reset();
    // hash.Update(g_ab);
    // block hh;
    // hash.Final(hh);
    // std::cout <<"i: "<<i<<" "<< hh << "\n";
    valx[i] = toBlock(g_ab);
    ret.mMapping[i]=i;
  }
  // u64 keyBitLength = 2*sizeof(block);

  u64 keyBitLength = mSsp + oc::log2ceil(senderSize);
  u64 keyByteLength = oc::divCeil(keyBitLength, 8);
  // 接收 paxos size
  Baxos paxos1;
  paxos1.init(receiverSize, 1 << 14, 3, mSsp, PaxosParam::Binary, block(0, 0));

  size_t size, cols;
  macoro::sync_wait(chl.recv(size));
  macoro::sync_wait(chl.recv(cols));

  std::cout << "size: " << size << std::endl;
  std::cout << "cols: " << cols << std::endl;

  Matrix<u8> pax2(size, cols);

  macoro::sync_wait(chl.recv(pax2));  // NOLINT

  Matrix<u8> r(receiverSize, cols);
  paxos1.decode<u8>(valx, r, pax2, numThreads);
#ifdef Debug
  std::cout << "receiver pax2\n";
  for (u64 i = 0; i < size; i++) {
    for (auto a : pax2[i]) {
      std::cout << (int)a << " ";
    }
    std::cout << "\n";
  }
  std::cout << "receiver val\n";
  for (u64 i = 0; i < r.rows(); i++) {
    for (auto a : r[i]) {
      std::cout << (int)a << " ";
    }
    std::cout << "\n";
  }
#endif

  // ret.mMapping.resize(X.size());
  // for (auto& array : ret.mMapping) {
  //   array.fill(~u64(0));
  // }
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
}

}  // namespace volePSI