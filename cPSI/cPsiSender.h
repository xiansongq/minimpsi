#pragma once
// Copyright 2023 xiansongq.

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/SodiumCurve.h"
#include "cryptoTools/Network/Channel.h"
#include "sodium.h"
#include "volePSI/Defines.h"
#include "shareType.h"
#include "volePSI/GMW/Gmw.h"
#include "volePSI/RsOpprf.h"
#include "volePSI/SimpleIndex.h"
#include "volePSI/config.h"
#include "volePSI/RsOpprf.h"

using osuCrypto::Sodium::Monty25519;
using osuCrypto::Sodium::Scalar25519;
namespace volePSI {
class cPsiSender : public oc::TimerAdapter {
 public:
  u64 senderSize, receiverSize;
  u64 mValueByteLength = 0;
  u64 mSsp = 0;
  u64 numThreads = 0;
  PRNG mPrng;
  valueShareType mType = valueShareType::Xor;
  struct Sharing {
    // The sender's share of the bit vector indicating that
    // the i'th row is a real row (1) or a row (0).
    oc::BitVector mFlagBits;

    // Secret share of the values associated with the output
    // elements. These values are from the sender.
    oc::Matrix<u8> mValues;

    // The mapping of the senders input rows to output rows.
    // Each input row might have been mapped to one of three
    // possible output rows.
    std::vector<std::array<u64, 3>> mMapping;
  };
  void init(u64 senderSize, u64 receiverSize, u64 mValueByteLength, u64 mSSp,
            u64 numThreads, block seed, valueShareType mType);
  void send(span<block> Y, oc::MatrixView<u8> values, Sharing& s, Socket& chl);
};

}  // namespace volePSI
