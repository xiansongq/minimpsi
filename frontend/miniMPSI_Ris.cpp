// Copyright 2023 xiansongq.

#include "frontend/miniMPSI_Ris.h"
#include "coproto/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "frontend/tools.h"
#include "macoro/sync_wait.h"
#include "macoro/thread_pool.h"
#include "volePSI/RsCpsi.h"
#include <cstddef>
#include <iostream>
#include <ostream>
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ristretto255.h>
#include <string>
 #define Debug
 #define Len 2
namespace volePSI {

void miniMPSISender_Ris::init(u64 secParam, u64 stasecParam, u64 nParties,
                              u64 myIdx, u64 setSize, u64 bitSize,
                              std::vector<block> inputs, bool malicious,
                              u64 numThreads) {
  this->secParam = secParam;
  this->stasecParam = stasecParam;
  this->nParties = nParties;
  this->myIdx = myIdx;
  this->setSize = setSize;
  this->bitSize = bitSize;
  this->inputs = inputs;
  this->malicious = malicious;
  this->numThreads = numThreads;
}

void miniMPSISender_Ris::send(std::vector<PRNG> &mseed,
                              std::vector<Socket> &chl, u64 numThreads) {
  // define variables
  std::vector<block> zeroValue(nParties);

  PRNG prng;
  prng.SetSeed(toBlock(myIdx, myIdx));

  std::vector<std::thread> thrds(nParties);
  using Block = typename Rijndael256Enc::Block;
  const std::uint8_t userKeyArr[] = {
      0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a, 0x95, 0x83, 0xff,
      0xa1, 0x59, 0xa5, 0x9d, 0x33, 0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c,
      0x75, 0xe1, 0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
  };
  Block userKey = Block256(userKeyArr);
  Rijndael256Dec decKey(userKey);
  // std::mutex mtx;   // global mutex
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " start");

  // if malicious mode is enabled
  if (malicious == true) {
    thrds.resize(setSize);
    for (auto idx = 0; idx < thrds.size(); idx++) {
      thrds[idx] = std::thread([&, idx]() {
        u64 datalen = setSize / thrds.size();
        u64 startlen = idx * datalen;
        u64 endlen = (idx + 1) * datalen;
        if (idx == thrds.size() - 1)
          endlen = setSize;
        oc::RandomOracle hash(sizeof(block));
        for (auto i = startlen; i < endlen; i++) {
          hash.Reset();
          hash.Update(inputs[i]);
          block hh;
          hash.Final(hh);
          inputs[i] = hh;
        }
      });
    }
    for (auto &thread : thrds)
      thread.join();
  }
  paxos.init(setSize, 1<<14, 3, stasecParam, PaxosParam::GF128, block(0, 0));
  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);
#pragma omp parallel for num_threads(numThreads)
  for (u64 i = 0; i < nParties; i++) {
    if (i != myIdx)
      zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
  }
  //  choice a random number a_i and compute g^(a_i) send it to the server
  mK = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
  mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
  crypto_core_ristretto255_scalar_random(mK);
  crypto_scalarmult_ristretto255_base(mG_K, mK); // g^ai
  macoro::sync_wait(chl[0].send(mG_K));
 
  // receive parameters of OKVS result vector
  size_t size = 0;
  macoro::sync_wait(chl[0].recv(size));
  Matrix<block> pax(size,2),deval(setSize,2);
  macoro::sync_wait(chl[0].recv((pax)));
// OKVS Decode for parties inputs value
#ifdef Debug
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) +
                     " decode start");
#endif
  paxos.decode<block>(inputs, deval, pax, numThreads);
#ifdef Debug
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) +
                     " decode end");
#endif
  Matrix<block> allpx(setSize,2);
#ifdef Debug
  PrintLine('-');
  std::cout << "sender decode value myIdx=" << myIdx << std::endl;
  for (u64 i = 0; i < setSize; i++) {
    for (u64 j = 0; j < Len; j++) {
      std::cout << deval[i][j] << " ";
    }
    std::cout << "\n";
  }
  PrintLine('-');
#endif
  auto compute = [&](u64 idx) {
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1)
      endlen = setSize;
    for (auto i = startlen; i < endlen; i++) {
      unsigned char *g_a = new unsigned char[crypto_core_ristretto255_BYTES];
      unsigned char *g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
      g_a = Block_to_Ristretto225(deval[i][0], deval[i][1]);
      auto g_f=decKey.decBlock((Block256(g_a)));
      g_a=g_f.data();
      RepresentativeToPublicKey2(g_a,g_a);
      std::cout<<"g_a recover: "<<toBlock(g_a)<<" "<<toBlock(g_a+sizeof(block))<<"\n";
      crypto_scalarmult_ristretto255(g_ab, mK, g_a);
      allpx[i][0]=toBlock(g_ab);
      allpx[i][1]=toBlock(g_ab+sizeof(block));
      for (u64 j = 0; j < nParties; j++){
        allpx[i][0] = allpx[i][0] ^ zeroValue[j];
        allpx[i][1] = allpx[i][1] ^ zeroValue[j];

      }
    }
  };
  thrds.resize(numThreads);
  for (u64 i = 0; i < thrds.size(); i++) {
    thrds[i] = std::thread([=] { compute(i); });
  }
  for (auto &thrd : thrds)
    thrd.join();

  //OKVS encode for (inputs and g^(a_i*b_i) \xor (zeroshare values))
  Matrix<block> pax2(paxos.size(),2);
#ifdef Debug
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) +
                     " encode start");
#endif
  paxos.solve<block>(inputs, allpx, pax2, &prng, numThreads);
#ifdef Debug
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) +
                     " encode end");
#endif

  macoro::sync_wait(chl[0].send(paxos.size()));
  macoro::sync_wait(chl[0].send(coproto::copy(pax2)));
#ifdef Debug
  PrintLine('-');
  std::cout << "sender encode allpx myIdx=" << myIdx << std::endl;
  for (u64 i = 0; i < setSize; i++) {
    for (u64 j = 0; j < Len; j++) {
      std::cout << allpx[i][j] << " ";
    }
    std::cout << "\n";
  }
  PrintLine('-');
#endif
  timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " end");
  std::cout << timer << std::endl;
  for (u64 i = 0; i < chl.size(); i++) {
    if (i != myIdx) {
      macoro::sync_wait(chl[i].flush());
      chl[i].close();
    }
  }
  return;
}
std::vector<block> miniMPSIReceiver_Ris::receive(std::vector<PRNG> &mseed,
                                                 std::vector<Socket> &chl,
                                                 u64 numThreads) {
  // define variables
  std::vector<block> zeroValue(nParties);
  PRNG prng;
  std::vector<unsigned char *> allPoints;
  std::vector<unsigned char *> allSeeds(setSize);
  std::vector<block> val(setSize);
  Matrix<block> vals(setSize,2);
  prng.SetSeed(toBlock(myIdx, myIdx));

  std::vector<std::thread> thrds(nParties);
  std::vector<block> reinputs(setSize); // save original input
  std::mutex mtx;                       // global mutex
  reinputs = inputs;
  using Block = typename Rijndael256Enc::Block;
		const std::uint8_t userKeyArr[] = {
			0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a,
			0x95, 0x83, 0xff, 0xa1, 0x59, 0xa5, 0x9d, 0x33,
			0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c, 0x75, 0xe1,
			0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
		};
		Block userKey = Block256(userKeyArr);
		Rijndael256Enc encKey(userKey);

  timer.setTimePoint("miniMPSI::reciver start");
  // if malicious mode is enabled
  if (malicious == true) {
    thrds.resize(setSize);
    for (auto idx = 0; idx < thrds.size(); idx++) {
      thrds[idx] = std::thread([&, idx]() {
        u64 datalen = setSize / thrds.size();
        u64 startlen = idx * datalen;
        u64 endlen = (idx + 1) * datalen;
        if (idx == thrds.size() - 1)
          endlen = setSize;
        oc::RandomOracle hash(sizeof(block));
        for (auto i = startlen; i < endlen; i++) {
          hash.Reset();
          hash.Update(inputs[i]);
          block hh;
          hash.Final(hh);
          inputs[i] = hh;
        }
      });
    }
    for (auto &thread : thrds)
      thread.join();
  }
  paxos.init(setSize, 1<<14, 3, stasecParam, PaxosParam::GF128, block(0, 0));

  // create zeroshare values
  zeroValue[0] = toBlock(0, 0);
  // #pragma omp parallel for num_threads(numThreads)
  for (u64 i = 1; i < nParties; i++) {
    zeroValue[i] = zeroValue[i] ^ mseed[i].get<block>();
  }
#ifdef Debug
  timer.setTimePoint("miniMPSI::reciver ris start");
#endif
  bool success;
    unsigned char *mK = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
    unsigned char *mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
		unsigned char pk[crypto_core_ristretto255_BYTES] = {};
  for (u64 i = 0; i < setSize; i++) {
    allSeeds[i]=new unsigned char[crypto_core_ristretto255_BYTES];
		// crypto_core_ristretto255_scalar_random(allSeeds[i]);
    // crypto_scalarmult_ristretto255_base(mG_K, allSeeds[i]); // g^k

    do {

				crypto_core_ristretto255_scalar_random(allSeeds[i]);
				success = ScalarBaseMult2(pk, mG_K, allSeeds[i]);
				//ristretto_ropoGroup2Field(g_sum, buffs, mfe25519_one);
			} while (!success);
      std::cout<<"g_a orgin: "<<toBlock(mG_K)<<" "<<toBlock(mG_K+sizeof(block))<<"\n";
		  auto permute_ctxt = encKey.encBlock(Block256(mG_K));
    //vals[i][0]=toBlock(mG_K);
   // vals[i][1]=toBlock(mG_K+sizeof(block));
   vals[i][0]=toBlock(permute_ctxt.data());
   vals[i][1]=toBlock(permute_ctxt.data()+sizeof(block));

  }


#ifdef Debug
  timer.setTimePoint("miniMPSI::reciver ris end");
#endif
  std::vector<unsigned char *> randomAk(nParties);
  for (u64 i = 1; i < nParties; i++) {
    unsigned char *point = new unsigned char[crypto_core_ristretto255_BYTES];
    macoro::sync_wait(chl[i].recv(point));
    randomAk[i] = point;
  }
#ifdef Debug
  PrintLine('-');
  std::cout<<"receiver encode value\n";
  for(u64 i=0;i<setSize;i++)
  {
    for(u64 j=0;j<Len;j++){
      std::cout<<vals[i][j]<<" ";
    }
    std::cout<<"\n";
  }
  PrintLine('-');
#endif

  //  OKVS encode for (inputs, g_(a_i))
  Matrix<block> pax(paxos.size(),2);
  paxos.solve<block>(inputs, vals, pax, &prng, numThreads);
// send parameters of OKVS encode results
#pragma omp parallel for num_threads(numThreads)
  for (u64 i = 1; i < nParties; i++) {
    macoro::sync_wait(chl[i].send(paxos.size()));
    macoro::sync_wait(chl[i].send(coproto::copy(pax))); // NOLINT
  }

  Matrix<block> allpx(setSize,2);
  thrds.resize(nParties);

  for (auto idx = 1; idx < thrds.size(); idx++) {
    thrds[idx] = std::thread([&, idx]() {
      size_t size = 0;
      macoro::sync_wait(chl[idx].recv(size));
      Matrix<block> pax2(size,2);
      macoro::sync_wait(chl[idx].recv(pax2));
      Matrix<block> val3(setSize,2);
      paxos.decode<block>(inputs, val3, pax2, numThreads);

#ifdef Debug
      PrintLine('-');
      std::cout << "receiver decode allpx sender idx=" << idx << std::endl;
      for (u64 i = 0; i < setSize; i++) {
        for (u64 j = 0; j < Len; j++) {
          std::cout << val3[i][j] << " ";
        }
        std::cout << "\n";
      }
      PrintLine('-');
#endif
     
      for (u64 j = 0; j < setSize; j++) {
        allpx[j][0] = allpx[j][0] ^ val3[j][0];
        allpx[j][1] = allpx[j][1] ^ val3[j][1];
      }
    });
  }
  for (u64 i = 1; i < thrds.size(); i++) {
    thrds[i].join();
  }

#ifdef Debug
  std::cout << "receiver allpx xor\n";
  for (u64 j = 0; j < setSize; j++) {
    std::cout << "allpx: " << allpx[j][0] << " " << allpx[j][1] << "\n";
  }
#endif

  std::unordered_multiset<std::string> result(setSize);

  // The following multi-threaded program may fail to execute PSI when set >
  // 2^10
  thrds.resize(numThreads);
  auto computeAllKey = [&](u64 idx) {
    u64 datalen = setSize / thrds.size();
    u64 startlen = idx * datalen;
    u64 endlen = (idx + 1) * datalen;
    if (idx == thrds.size() - 1)
      endlen = setSize;

    for (u64 i = startlen; i < endlen; i++) {
       for (u64 j = 0; j < nParties; j++){
        allpx[i][0] = allpx[i][0] ^ zeroValue[j];
        allpx[i][1] = allpx[i][1] ^ zeroValue[j];
      }
      Matrix<block> userkey(nParties,2);
      for (u64 j = 1; j < nParties; j++) {
        unsigned char *g_ab = new unsigned char[crypto_core_ristretto255_BYTES];
        crypto_scalarmult_ristretto255(g_ab, allSeeds[i], randomAk[j]);
        userkey[j][0] = toBlock(g_ab);
        userkey[j][1] = toBlock(g_ab + sizeof(block));
      }
      if (nParties > 2) {
        for (u64 k = 2; k < nParties; k++) {
          userkey[1][0] = userkey[1][0] ^ userkey[k][0];
          userkey[1][1] = userkey[1][1] ^ userkey[k][1];
        }
      }
#ifdef Debug
      std::cout << "userkey1: " << userkey[1][0] << " " << userkey[1][1]
                << std::endl;
#endif
      result.insert(Ristretto225_to_string(userkey[1][0], userkey[1][1]));
    }
  };
  thrds.resize(numThreads);
  for (u64 i = 0; i < thrds.size(); i++) {
    thrds[i] = std::thread([=] { computeAllKey(i); });
  }
  for (auto &thrd : thrds)
    thrd.join();

  for (u64 i = 0; i < setSize; i++) {
    auto it = result.find(Ristretto225_to_string(allpx[i][0], allpx[i][1]));
    if (it != result.end())
      outputs.push_back(reinputs[i]);
  }
  timer.setTimePoint("miniMPSI::reciver end");
  std::cout << timer << std::endl;
  return outputs;
}
void miniMPSIReceiver_Ris::init(u64 secParam, u64 stasecParam, u64 nParties,
                                u64 myIdx, u64 setSize, u64 bitSize,
                                std::vector<block> inputs, // NOLINT
                                bool malicious, u64 numThreads) {
  this->secParam = secParam;
  this->stasecParam = stasecParam;
  this->nParties = nParties;
  this->myIdx = myIdx;
  this->setSize = setSize;
  this->bitSize = bitSize;
  this->inputs = inputs;
  this->malicious = malicious;
  this->numThreads = numThreads;
}
} // namespace volePSI
