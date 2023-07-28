#pragma once
#include <iostream>
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/Rijndael256.h"
#include "tools.h"
#include "volePSI/Paxos.h"
#include "coproto/Socket/AsioSocket.h"
#include <thread>
using namespace osuCrypto;
using namespace volePSI;
namespace volePSI
{
    class miniMPSISender : public oc::TimerAdapter
    {
    public:
        u64 nParties;
        u64 numThreads;
        u64 myIdx;
        volePSI::Baxos paxos;
        bool malicious = false;
        std::vector<block> inputs;
        u64 setSize;
        REccNumber ai;
        REccPoint g_ai;
        Proto send(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads);
    };
    class miniMPSIReceiver : public oc ::TimerAdapter
    {
    public:
        u64 nParties;
        u64 numThreads;
        u64 myIdx;
        volePSI::Baxos paxos;
        bool malicious = false;
        std::vector<block> inputs;
        u64 setSize;
        REccNumber ai;
        REccPoint g_ai;
        Proto receive(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads);
    };
}