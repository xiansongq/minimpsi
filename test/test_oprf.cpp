
#include "volePSI/Defines.h"
#include "volePSI/RsOprf.h"
#include "../frontend/Common.h"
using namespace volePSI;
int main() {
  RsOprfSender senders;
  RsOprfReceiver recvers;

  auto sockets = coproto::LocalAsyncSocket::makePair();
  u64 n = 4000;
  PRNG prng0(block(0, 0));
  PRNG prng2(block(0, 1));

  std::vector<block> vals(n), recvOut(n);

  prng0.get(vals.data(), n);
  std::cout << "rsoprf start\n";
  auto p0 = senders.send(n, prng0, sockets[0]);
  auto p1 = recvers.receive(vals, recvOut, prng2, sockets[1]);

  eval(p0, p1);
  std::cout << "rsoprf end\n";
  std::vector<block> vv(n);
  senders.eval(vals, vv);

  u64 count = 0;
  for (u64 i = 0; i < n; ++i) {
    auto v = senders.eval(vals[i]);
    if (recvOut[i] != v || recvOut[i] != vv[i]) {
      if (count < 10)
        std::cout << i << " " << recvOut[i] << " " << v << " " << vv[i]
                  << std::endl;
      else
        break;

      ++count;
    }
  }
  if (count) throw RTE_LOC;
}