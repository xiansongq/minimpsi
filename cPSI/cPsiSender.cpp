#include "cPsiSender.h"

#include <cryptoTools/Circuit/BetaCircuit.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <macoro/sync_wait.h>
#include <sodium/crypto_core_ristretto255.h>

#include <memory>

#include "miniMPSI/tools.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto;
#define Debug
namespace volePSI {

void cPsiSender::init(u64 senderSize, u64 receiverSize, u64 mValueByteLength,
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

void cPsiSender::send(span<block> Y, oc::MatrixView<u8> values, Sharing& s,
                      Socket& chl) {
  // choise a random curver value
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

  auto *mk = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
  prng1.implGet(mk, crypto_core_ristretto255_BYTES);

  auto *mg_k = new unsigned char[crypto_core_ristretto255_BYTES];
  crypto_core_ristretto255_scalar_random(mk);
  crypto_scalarmult_ristretto255_base(mg_k, mk);
  macoro::sync_wait(chl.send(mg_k));
  Baxos paxos;
  paxos.init(senderSize, 1 << 14, 3, mSsp, PaxosParam::GF128, block(0, 0));
  size_t size;
  macoro::sync_wait(chl.recv(size));
  Matrix<block> pax(size, 2);

  macoro::sync_wait(chl.recv(pax));  // NOLINT
  // std::cout << "send pax\n";
  // for (u64 i = 0; i < paxos.size(); i++) {
  //   std::cout << pax(i, 0) << "  " << pax(i, 1) << "\n";
  // }
  // std::cout << "---";
  Matrix<block> deval(receiverSize, 2);
  paxos.decode<block>(Y, deval, pax, numThreads);
  // 计算 g^a^b
  // u64 keyBitLength = 2 * sizeof(block);
  std::cout << "sender decode\n";
  for (u64 i = 0; i < receiverSize; i++) {
    std::cout << "decode i: " << i << " " << deval[i][0] << " " << deval[i][1]
              << std::endl;
  }
  u64 keyBitLength = mSsp + oc::log2ceil(receiverSize);
  u64 keyByteLength = oc::divCeil(keyBitLength, 8);
  Matrix<block> allpx(receiverSize, 2);
  Matrix<u8> val(receiverSize, 2 * sizeof(block));
  Matrix<u8> Tv;
  std::vector<block> Ty;

  Matrix<u8> r;
  Matrix<u8>::iterator TvIter;
  Matrix<u8>::iterator rIter;
  std::vector<block>::iterator TyIter;
  // The OPPRF input value of the i'th input under the j'th cuckoo
  // hash function.
  Ty.resize(senderSize);

  // The value associated with the k'th OPPRF input
  Tv.resize(senderSize, keyByteLength + values.cols(),
            oc::AllocType::Uninitialized);

  // The special value assigned to the i'th bin.
  r.resize(senderSize, keyByteLength, oc::AllocType::Uninitialized);
  s.mValues.resize(senderSize, values.cols(), oc::AllocType::Uninitialized);
        mPrng.get<u8>(s.mValues);
        mPrng.get<u8>(r);

  TvIter = Tv.begin();
  rIter = r.begin();
  TyIter = Ty.begin();
  std::cout << "sender mg_k: " << toBlock(mg_k) << " " << toBlock(mg_k + sizeof(block))
            << "\n";

  oc::RandomOracle hash(sizeof(block));
  for (u64 i = 0; i < receiverSize; i++) {
    auto* g_a = new unsigned char[crypto_core_ristretto255_BYTES];
    auto* g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
    g_a = Block_to_Ristretto225(deval[i][0], deval[i][1]);
    std::cout << "g_a: " << toBlock(g_a) << " " << toBlock(g_a + sizeof(block))
              << "\n";
    crypto_scalarmult_ristretto255(g_ab, mk, g_a);  // NOLINT

    std::cout << "sender i: " << i << " " << toBlock(g_ab) << " "
              << toBlock(g_ab + sizeof(block)) << std::endl;
    // memcpy(val[i].data(), &g_ab, sizeof(block));
    // memcpy(val[i].data() + sizeof(block), &g_ab + sizeof(block),
    // sizeof(block));
    // hash.Reset();
    // hash.Update(g_ab);
    // block hh;
    // hash.Final(hh);
    // std::cout <<"i: "<<i<<" "<< hh << "\n";
    //  hash.Final(*TyIter);
    *TyIter = toBlock(g_ab);
    memcpy(&*TvIter, &*rIter, keyByteLength);
    TvIter += keyByteLength;
    if (values.size()) {
      memcpy(&*TvIter, &values(i, 0), values.cols());

      if (mType == ValueShareType::Xor) {
        for (u64 k = 0; k < values.cols(); ++k) {
          TvIter[k] ^= s.mValues(i, k);
        }
      } else if (mType == ValueShareType::add32) {
        assert(values.cols() % sizeof(u32) == 0);
        auto ss = values.cols() / sizeof(u32);
        auto tv = (u32*)TvIter;
        auto rr = (u32*)&s.mValues(i, 0);
        for (u64 k = 0; k < ss; ++k) tv[k] -= rr[k];
      } else
        throw RTE_LOC;
      TvIter += values.cols();
    }  // *TyIter=val[i].data();
    // hash.Update(val[i].data());
    ++TyIter;
    rIter += keyByteLength;
    // allpx[i][0] = toBlock(g_ab);
    // allpx[i][1] = toBlock(g_ab + sizeof(block));
  }
  std::cout<<"Ty values:\n";
  for(u64 i=0;i<senderSize;i++)
    std::cout<<Ty[i]<<std::endl;
  std::cout << "values cols: " << values.cols() << std::endl;
  Baxos paxos1;
  paxos1.init(senderSize, 1 << 14, 3, mSsp, PaxosParam::Binary, block(0, 0));
  Matrix<u8> pax2(paxos1.size(), keyByteLength + values.cols());
  paxos1.solve<u8>(Ty, Tv, pax2, &mPrng, numThreads);
  std::cout << "pax2 size: " << paxos.size() << std::endl;
  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(keyByteLength + values.cols()));  // NOLINT
  macoro::sync_wait(chl.send(coproto::copy(pax2)));            // NOLINT
#ifdef Debug
  std::cout << "sender pax2\n";
  for (u64 i = 0; i < size; i++) {
    for (auto a : pax2[i]) {
      std::cout << (int)a << " ";
    }
    std::cout << "\n";
  }
  std::cout << "sender val\n";
  for (u64 i = 0; i < Tv.rows(); i++) {
    for (auto a : Tv[i]) {
      std::cout << (int)a << " ";
    }
    std::cout << "\n";
  }
#endif
  // std::vector<block>::iterator TyIter;
  // Matrix<block>::iterator TvIter;
  // for (u64 i = 0; i < senderSize; i++) {
  // }

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
}

}  // namespace volePSI