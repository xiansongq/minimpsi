#include "cpsi.h"

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <macoro/macros.h>
#include <macoro/sync_wait.h>
#include <unistd.h>
#include <volePSI/RsOprf.h>

#include <system_error>

#include "Dhoprf.h"
// #include "defines.h"

// #define debug

namespace volePSI {

Proto minicpsiSender::send(std::vector<block> Y, oc::MatrixView<u8> values,
                           Sharing& s, Socket& chl) {
  MC_BEGIN(
      Proto, this, Y, values, &s, &chl, prng = PRNG(oc::sysRandomSeed()),
      oprfValues = std::vector<block>{}, keyBitLength = u64{},
      keyByteLength = u64{}, Ty = std::vector<block>{}, Tv = oc::Matrix<u8>{},
      r = oc::Matrix<u8>{}, TyIter = std::vector<block>::iterator{},
      TvIter = oc::Matrix<u8>::iterator{}, rIter = oc::Matrix<u8>::iterator{},
      cmp = std::make_unique<Gmw>(), cir = BetaCircuit{}, paxos = Baxos{},
      pax = oc::Matrix<u8>{}, cols = u64{0}, fork = Socket{}

  );

  if (mTimer) {
    receiver.setTimer(*mTimer);
  }

  receiver.init(senderSize, numThreads, 0, stasecParam, 0);
  oprfValues.resize(receiverSize);
  MC_AWAIT(receiver.receive(Y, oprfValues, prng, chl));
  // prng.SetSeed(oc::toBlock(1,1));
  // MC_AWAIT(rreceiver.receive(Y, oprfValues, prng, chl));

#ifdef debug
  std::cout << "sender oprfvalse\n";
  for (u64 i = 0; i < oprfValues.size(); i++) {
    std::cout << oprfValues[i] << "\n";
  }
  std::cout << "sender oprfvalues end\n";
#endif

  keyBitLength = stasecParam + oc::log2ceil(receiverSize);

  keyByteLength = oc::divCeil(keyBitLength, 8);

  Ty.resize(senderSize);

  Tv.resize(senderSize, keyByteLength + values.cols(),
            oc::AllocType::Uninitialized);

  r.resize(senderSize, keyByteLength, oc::AllocType::Uninitialized);

  s.mValues.resize(senderSize, values.cols(), oc::AllocType::Uninitialized);

  prng.get<u8>(s.mValues);
  prng.get<u8>(r);

  TvIter = Tv.begin();
  rIter = r.begin();
  TyIter = Ty.begin();

  for (int i = 0; i < senderSize; i++) {
    Ty[i] = oprfValues[i];
    // *TyIter = oprfValues[i];
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

    // ++TyIter;

    rIter += keyByteLength;
  }

  paxos.init(senderSize, 1 << 14, 3, stasecParam, PaxosParam::Binary,
             block(0, 0));
  pax.resize(paxos.size(), keyByteLength + values.cols());

  paxos.solve<u8>(Ty, Tv, pax, &prng, numThreads);

#ifdef debug
  std::cout << "sender pax\n";
  for (u64 i = 0; i < pax.rows(); i++) {
    std::cout << oc::toBlock(pax[i].data()) << " "
              << oc::toBlock(pax[i].data() + sizeof(block)) << std::endl;
  }
  std::cout << "sender pax end\n";
#endif

#ifdef debug
  std::cout << "----- sender r\n";
  for (auto i = 0; i < r.rows(); i++) {
    std::cout << oc::toBlock(r[i].data()) << " "
              << oc::toBlock(r[i].data() + sizeof(block)) << std::endl;
  }
  std::cout << "------ sender r end\n";
#endif

  MC_AWAIT(chl.send(paxos.size()));

  cols = keyByteLength + values.cols();
  MC_AWAIT(chl.send(cols));

  MC_AWAIT(chl.send(coproto::copy(pax)));

  if (mTimer) cmp->setTimer(*mTimer);

  cir = volePSI::isZeroCircuit(keyBitLength);
  cmp->init(r.rows(), cir, numThreads, 1, prng.get());
  cmp->setInput(0, r);
  MC_AWAIT(cmp->run(chl));

  {
    auto ss = cmp->getOutputView(0);
    std::cout << ss.rows() << std::endl;
    s.mFlagBits.resize(senderSize);
    std::copy(ss.begin(), ss.begin() + s.mFlagBits.sizeBytes(),
              s.mFlagBits.data());
  }
  setTimePoint("minicpsi::sender done");

  MC_END();
};

Proto minicpsiReceiver::receive(std::vector<block> X, Sharing& ret,
                                Socket& chl) {
  MC_BEGIN(Proto, this, X, &ret, &chl, Tx = std::vector<block>{},
           keyBitLength = u64{}, keyByteLength = u64{}, r = oc::Matrix<u8>{},
           cmp = std::make_unique<volePSI::Gmw>(), cir = volePSI::BetaCircuit{},
           prng = PRNG(oc::sysRandomSeed()), oprfValues = std::vector<block>{},
           paxos = Baxos{}, pax = oc::Matrix<u8>{}, size = size_t{},
           cols = u64{}, fork = Socket{});

  if (mTimer) {
    sender.setTimer(*mTimer);
  }

  // MC_AWAIT(ssender.send(senderSize, prng, chl));
  oprfValues.resize(senderSize);
  // ssender.eval(X, oprfValues);

  sender.init(receiverSize, numThreads, 0, stasecParam, 1);
  MC_AWAIT(sender.send(X, prng, chl));

  sender.eval(oprfValues);

  ret.mMapping.resize(X.size(), ~u64(0));
  for (int i = 0; i < receiverSize; i++) {
    ret.mMapping[i] = i;
  }

#ifdef debug
  std::cout << "receiver oprfvalse\n";
  for (u64 i = 0; i < oprfValues.size(); i++) {
    std::cout << oprfValues[i] << "\n";
  }
  std::cout << "receiver oprfvalse end\n";
#endif

  keyBitLength = stasecParam + oc::log2ceil(receiverSize);
  keyByteLength = oc::divCeil(keyBitLength, 8);
  paxos.init(receiverSize, 1 << 14, 3, stasecParam, PaxosParam::Binary,
             block(0, 0));

  MC_AWAIT(chl.recv(size));

  MC_AWAIT(chl.recv(cols));

  pax.resize(size, cols);

  MC_AWAIT(chl.recv(pax));

  r.resize(X.size(), cols, oc::AllocType::Uninitialized);
  paxos.decode<u8>(oprfValues, r, pax, numThreads);

#ifdef debug
  std::cout << "receiver pax\n";
  for (u64 i = 0; i < pax.rows(); i++) {
    std::cout << oc::toBlock(pax[i].data()) << " "
              << oc::toBlock(pax[i].data() + sizeof(block)) << std::endl;
  }
  std::cout << "receiver pax end\n";

#endif

  if (mTimer) cmp->setTimer(*mTimer);

#ifdef debug
  std::cout << "----- receiver r\n";
  for (auto i = 0; i < r.rows(); i++) {
    std::cout << oc::toBlock(r[i].data()) << +" "
              << oc::toBlock(r[i].data() + sizeof(block)) << std::endl;
  }
  std::cout << "------ receiver r end\n";
#endif

  cir = volePSI::isZeroCircuit(keyBitLength);
  cmp->init(r.rows(), cir, numThreads, 0, prng.get());

  cmp->implSetInput(0, r, r.cols());

  MC_AWAIT(cmp->run(chl));
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
  MC_AWAIT(chl.flush());
  setTimePoint("minicpsi::sender done");

  MC_END();
}

}  // namespace volePSI