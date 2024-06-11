#pragma once
/**
 * @description: cpsi.h
 * @author: XianSong Qian
 * @date: 2024/06/08
 */

// #include "../common/defines.h"
#include "../dhoprf/Dhoprf.h"
#include "volePSI/RsOprf.h"
#include "volePSI/Defines.h"
#include "volePSI/GMW/Gmw.h"
#include "shareType.h"
// #include "../volepsi/RsOpprf.h"

namespace volePSI {
// enum valueShareType { Xor, add32 };

struct minicpsiParames {
  u64 senderSize, receiverSize;
  u64 mValueByteLength = 0;
  u64 stasecParam = 0;
  u64 numThreads = 0;
  valueShareType mType = valueShareType::Xor;

  void init(u64 senderSize, u64 receiverSize, u64 mValueByteLength,
            u64 stasecParam, u64 numThreads,
            valueShareType mType = valueShareType::Xor) {
    this->senderSize = senderSize;
    this->receiverSize = receiverSize;
    this->mValueByteLength = mValueByteLength;
    this->stasecParam = stasecParam;
    this->numThreads = numThreads;
    this->mType = mType;
  }
};

/* struct Sharing {
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
}; */

class minicpsiSender : public minicpsiParames, public TimerAdapter {
 public:
  struct Sharing {
    // The sender's share of the bit vector indicating that
    // the i'th row is a real row (1) or a row (0).
    BitVector mFlagBits;

    // Secret share of the values associated with the output
    // elements. These values are from the sender.
    oc::Matrix<u8> mValues;

    // The mapping of the senders input rows to output rows.
    // Each input row might have been mapped to one of three
    // possible output rows.
    std::vector<u64> mMapping;
  };
  dhOprfReceiver receiver;
  // volePSI::RsOprfReceiver rreceiver;
  Proto send(std::vector<block> Y, oc::MatrixView<u8> values, Sharing& s,
             Socket& chl);
};

class minicpsiReceiver : public minicpsiParames, public TimerAdapter {
 public:
  struct Sharing {
    // The sender's share of the bit vector indicating that
    // the i'th row is a real row (1) or a row (0).
    BitVector mFlagBits;

    // Secret share of the values associated with the output
    // elements. These values are from the sender.
    oc::Matrix<u8> mValues;

    // The mapping of the senders input rows to output rows.
    // Each input row might have been mapped to one of three
    // possible output rows.
    std::vector<u64> mMapping;
  };
  dhOprfSender sender;
  // volePSI::RsOprfSender ssender;
  Proto receive(std::vector<block> X, Sharing& ret, Socket& chl);
};
}  // namespace taihang