#include "cPsiReceiver.h"

#include <macoro/sync_wait.h>

#include "volePSI/Defines.h"
using namespace osuCrypto;
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
  std::cout << "receiver" << std::endl;
  // recv data
  auto mg_k = new unsigned char[crypto_core_ristretto255_BYTES];
  macoro::sync_wait(chl.recv(mg_k));
  std::cout << "mgk: " << toBlock(mg_k) << " " << toBlock(mg_k + sizeof(block))
            << std::endl;
  std::vector<unsigned char*> allSeeds(receiverSize);
  Baxos paxos;
  paxos.init(receiverSize, 1 << 14, 3, mSsp, PaxosParam::GF128, block(0, 0));
  PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
  auto* mk = new unsigned char[crypto_core_ristretto255_BYTES];
  Matrix<block> vals(receiverSize, 2);

  for (u64 i = 0; i < receiverSize; i++) {
    allSeeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];
    prng1.implGet(allSeeds[i], crypto_core_ristretto255_BYTES);
    // crypto_core_ristretto255_scalar_random(allSeeds[i]);
    crypto_scalarmult_ristretto255_base(mk, allSeeds[i]);  // g^k
    vals[i][0] = toBlock(mk);
    vals[i][1] = toBlock(mk + sizeof(block));
  }
  Matrix<block> pax(paxos.size(), 2);
  std::cout << "paxos size: " << paxos.size() << std::endl;
  paxos.solve<block>(X, vals, pax, &mPrng, numThreads);
  macoro::sync_wait(chl.send(paxos.size()));
  macoro::sync_wait(chl.send(coproto::copy(pax)));  // NOLINT
  for (u64 i = 0; i < paxos.size(); i++) {
    std::cout << pax(i, 0) << "  " << pax(i, 1) << std::endl;
  }
  std::cout << "---";
  // 计算 g^a^b
  Matrix<block> allkey(receiverSize, 2);
  for (u64 i = 0; i < receiverSize; i++) {
    auto* g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
    crypto_scalarmult_ristretto255(g_ab, allSeeds[i],  // NOLINT
                                   mg_k);
    allkey[i][0] = toBlock(g_ab);
    allkey[i][1] = toBlock(g_ab + sizeof(block));
  }
}

}  // namespace volePSI