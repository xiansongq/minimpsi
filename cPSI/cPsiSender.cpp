#include "cPsiSender.h"

#include <macoro/sync_wait.h>
#include <sodium/crypto_core_ristretto255.h>
#include "miniMPSI/tools.h"
using namespace osuCrypto;
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
  std::cout << "Sending\n"
            << "  " << Y.size() << std::endl;
  auto mk = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
  auto mg_k = new unsigned char[crypto_core_ristretto255_BYTES];
  crypto_core_ristretto255_scalar_random(mk);
  crypto_scalarmult_ristretto255_base(mg_k, mk);
  macoro::sync_wait(chl.send(mg_k));
  std::cout << "send success:\n";
  Baxos paxos;

  paxos.init(senderSize, 1 << 14, 3, mSsp, PaxosParam::GF128, block(0, 0));
  size_t size;
  macoro::sync_wait(chl.recv(size));
  std::cout << "size: " << size << std::endl;
  Matrix<block> pax(size, 2);

  macoro::sync_wait(chl.recv(pax));  // NOLINT
  for (u64 i = 0; i < paxos.size(); i++) {
    std::cout << pax(i, 0) << "  " << pax(i, 1) << "\n";
  }
  std::cout << "---";
  Matrix<block> deval(receiverSize, 2);
  paxos.decode<block>(Y, deval, pax, numThreads);
  // 计算 g^a^b
  Matrix<block> allpx(receiverSize, 2);
  for (u64 i = 0; i < receiverSize; i++) {
    auto* g_a = new unsigned char[crypto_core_ristretto255_BYTES];
    auto* g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
    g_a = Block_to_Ristretto225(deval[i][0], deval[i][1]);
    crypto_scalarmult_ristretto255(g_ab, mg_k, g_a);  // NOLINT
    allpx[i][0] = toBlock(g_ab);
    allpx[i][1] = toBlock(g_ab + sizeof(block));
  }
  u64 keyBitLength = mSsp + oc::log2ceil(senderSize);
  u64 keyByteLength = oc::divCeil(keyBitLength, 8);
  std::vector<block>::iterator TyIter;
  Matrix<block>::iterator TvIter;
  for (u64 i = 0; i < senderSize; i++) {
  }
}

}  // namespace volePSI