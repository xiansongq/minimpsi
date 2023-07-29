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
#include "tools.h"
#include <cassert>
#include <thread>
#include <unordered_set>
using namespace osuCrypto;
using namespace volePSI;
namespace volePSI
{
    class miniMPSISender : public oc::TimerAdapter
    {
    public:
        u64 secParam;
        u64 stasecParam;
        u64 nParties;
        u64 numThreads;
        u64 myIdx;
        volePSI::Baxos paxos;
        bool malicious = false;
        std::vector<block> inputs;
        u64 setSize;
        REccNumber ai;
        REccPoint g_ai;
        u8 *tempbuf;
        Proto send(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads);
        void init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize, std::vector<block> inputs, bool malicious);
    };
    class miniMPSIReceiver : public oc ::TimerAdapter
    {
    public:
        u64 secParam;
        u64 stasecParam;
        u64 nParties;
        u64 numThreads;
        u64 myIdx;
        volePSI::Baxos paxos;
        bool malicious = false;
        std::vector<block> inputs;
        u64 setSize;
        REccNumber ai;
        REccPoint g_ai;
        u8 *tempbuf;

        Proto receive(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads);
        void init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize, std::vector<block> inputs, bool malicious);
    };
}