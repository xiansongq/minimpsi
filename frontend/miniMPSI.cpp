#include "miniMPSI.h"

namespace volePSI
{

    Proto miniMPSISender::send(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads)
    {
        MC_BEGIN(Proto, this, &mseed, &chl, numThreads,
                 num = u64{0},
                 zeroValue = std::vector<u8>(nParties),
                 mCrurve = REllipticCurve{},
                 mG = REllipticCurve::Point{},
                 prng = PRNG{},
                 fork = Socket{});
        // 首先创建 零共享值
        // zeroValue.resize(nParties);

        zeroValue[0] = 0;
        for (u64 i = 1; i < nParties; i++)
        {
            zeroValue[i] = zeroValue[i] ^ mseed[i].get<u8>();
        }
        // 选择随机值 a_i 并生成 g^(a_i) 发送给leader
        prng.SetSeed(toBlock(myIdx, myIdx));
        mG = mCrurve.getGenerator();
        ai.randomize(prng);
        g_ai = mG * ai;
        // 发送 g_ai
        //MC_AWAIT(chl[0].send(g_ai));
       // std::cout << "接收数据" << std::endl;
        num = 100001;
        MC_AWAIT(chl[0].send(num));
        //std::cout << "num: " << num << std::endl;
        MC_END();
    };
    Proto miniMPSIReceiver::receive(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads)
    {
        MC_BEGIN(Proto, this, &mseed, &chl, numThreads,
                 mCrurve = REllipticCurve{},
                 mG = REllipticCurve::Point{},
                 prng = PRNG{},
                 num = u64{1000011},
                 fork = Socket{},
                 tempPoint = REccPoint{},
                 akrandom = std::vector<REccPoint>(nParties),
                 thrds = std::vector<std::thread>(nParties));

        // 接收 g_ai
        prng.SetSeed(toBlock(myIdx, myIdx));
        mG = mCrurve.getGenerator();
        ai.randomize(prng);
        g_ai = mG * ai;
        // akrandom.resize(nParties);
        akrandom.emplace_back(mCrurve);
        akrandom[0] = g_ai;
        for (u64 pIdx = 1; pIdx < thrds.size(); ++pIdx)
        {
            thrds[pIdx] = std::thread([&, pIdx]()
                                      { 
                                        //tempPoint
                                        macoro::sync_wait(chl[pIdx].recv(num));

                                       // macoro::sync_wait(chl[pIdx].recv(num));
                                        std::cout<<num<<std::endl; });
        }

        // Wait for all threads to finish
        for (u64 pIdx = 1; pIdx < thrds.size(); ++pIdx)
            thrds[pIdx].join();
        MC_END();
    };
}