#include "miniMPSI_re.h"

namespace volePSI
{
    void miniMPSISender_re::init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize, std::vector<block> inputs, bool malicious, u64 numThreads)
    {
        this->secParam = secParam;
        this->stasecParam = stasecParam;
        this->nParties = nParties;
        this->myIdx = myIdx;
        this->setSize = setSize;
        this->inputs = inputs;
        this->malicious = malicious;
        this->numThreads = numThreads;
    }

    void miniMPSISender_re::send(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads)
    {
        // define variables
        std::vector<u8> zeroValue(nParties);
        REllipticCurve mCrurve;
        REllipticCurve::Point mG;
        PRNG prng;
        oc::Matrix<u8> val;
        oc::Matrix<u8> pax;
        oc::Matrix<u8> pax2;
        size_t len = 0;
        size_t size = 0;
        std::vector<REccPoint> px(setSize);
        std::vector<REccPoint> npx(setSize);
        std::vector<std::vector<u8>> values(setSize);
        std::vector<std::thread> thrds(nParties);
        Socket fork;
        // if malicious mode is enabled
        if (malicious == true)
        {
            oc::RandomOracle hash(sizeof(block));
            // #pragma omp parallel for num_threads(numThreads)
            for (u64 i = 0; i < inputs.size(); i++)
            {
                hash.Reset();
                hash.Update(inputs[i]);
                block hh;
                hash.Final(hh);
                inputs[i] = hh;
            }
        }
        timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " start");
        // create zeroshare values
        zeroValue[0] = 0;
#pragma omp parallel for num_threads(numThreads)
        for (u64 i = 0; i < nParties; i++)
        {
            if (i != myIdx)
                zeroValue[i] = zeroValue[i] ^ mseed[i].get<u8>();
        }
        // choice a random number a_i and compute g^(a_i) send it to the server
        prng.SetSeed(toBlock(myIdx, myIdx));
        mG = mCrurve.getGenerator();
        ai.randomize(prng);
        g_ai = mG * ai;
        std::vector<u8> points = REccPoint_to_Vector(g_ai);
        macoro::sync_wait(chl[0].send(coproto::copy(points)));

        // receive parameters of OKVS result vector
        // first parameter vector rows size
        macoro::sync_wait(chl[0].recv(size));
        // second parameter vector column size
        macoro::sync_wait(chl[0].recv(len));
        pax.resize(size, len), val.resize(setSize, len);
        // receive vector of OKVS result
        macoro::sync_wait(chl[0].recv(pax));
        paxos.init(setSize, 128, 3, stasecParam, PaxosParam::Binary, block(0, 0));
        // OKVS Decode for parties inputs value
        paxos.decode<u8>(inputs, val, pax, numThreads);
        // compute g_(a_i*b_i)
        // #pragma omp parallel for num_threads(numThreads)
        for (u64 i = 0; i < setSize; i++)
        {
            std::vector<u8> vec(len);
            // #pragma omp parallel for num_threads(numThreads)
            for (u64 j = 0; j < len; j++)
                vec[j] = val[i][j];
            px.emplace_back(mCrurve);
            px[i] = vector_to_REccPoint(vec);
            npx.emplace_back(mCrurve);
            // compute g_(a_i*b_i)
            npx[i] = px[i] * ai;
            // XOR calculation results with zero shared values
            npx[i] = REccPoint_xor_u8(npx[i], zeroValue);
        }
        // OKVS encode for (inouts and g^(a_i*b_i) \xor (zeroshare values))
        paxos.init(setSize, 128, 3, stasecParam, PaxosParam::Binary, block(0, 0));
        pax2.resize(paxos.size(), len);
        // #pragma omp parallel for num_threads(6)
        for (u64 i = 0; i < setSize; i++)
        {
            values[i] = REccPoint_to_Vector(npx[i]);
            // #pragma omp parallel for num_threads(6)

            for (size_t j = 0; j < len; j++)
                val(i, j) = values[i][j];
        }
        paxos.solve<u8>(inputs, val, pax2, &prng, numThreads);
        // Sending paxos.size() directly will block if it doesn't work. I don't know why
        size = paxos.size();
        macoro::sync_wait(chl[0].send(size));
        macoro::sync_wait(chl[0].send(coproto::copy(pax2)));
        timer.setTimePoint("miniMPSI::sender " + std::to_string(myIdx) + " end");

        std::cout << timer << std::endl;
        macoro::sync_wait(macoro::suspend_always{});
        for (u64 i = 0; i < chl.size(); i++)
        {

            if (i != myIdx)
            {
                (chl[i].flush());
                chl[i].close();
            }
        }
        return;
    };
    std::vector<block> miniMPSIReceiver_re::receive(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads)
    {
        // define variables
        std::vector<u8> zeroValue(nParties);
        REllipticCurve mCrurve;
        REllipticCurve::Point mG;
        PRNG prng;
        Socket fork;
        REccPoint tempPoint;
        std::vector<REccPoint> akrandom(nParties);
        std::vector<REccNumber> nSeeds(nParties);
        std::vector<REccPoint> mypoint(nParties);
        std::vector<std::vector<u8>> values(setSize);
        oc::Matrix<u8> val;
        oc::Matrix<u8> val2;
        oc::Matrix<u8> pax;
        size_t len = 0;
        u64 size = 0;
        std::vector<oc::Matrix<u8>> allval;
        std::vector<REccPoint> px(setSize);
        std::vector<REccPoint> npx(setSize);
        std::vector<std::vector<REccPoint>> allpx(nParties);
        std::vector<u8> intersection_bit;
        std::vector<REccPoint> allkey;
        u64 intersection_size = 0;
        std::vector<std::thread> thrds(nParties);
        timer.setTimePoint("miniMPSI::reciver start");
        std::vector<block> reinputs(setSize); // save original input
        reinputs = inputs;
        // if malicious mode is enabled

        if (malicious == true)
        {
            oc::RandomOracle hash(sizeof(block));
            // #pragma omp parallel for num_threads(numThreads)

            for (u64 i = 0; i < inputs.size(); i++)
            {
                hash.Reset();
                hash.Update(inputs[i]);
                block hh;
                hash.Final(hh);
                inputs[i] = hh;
            }
        }
        // create zeroshare values

        zeroValue[0] = 0;
#pragma omp parallel for num_threads(numThreads)

        for (u64 i = 1; i < nParties; i++)
        {
            zeroValue[i] = zeroValue[i] ^ mseed[i].get<u8>();
        }

        // receive g_ai values from other parties
        prng.SetSeed(toBlock(myIdx, myIdx));
        mG = mCrurve.getGenerator();
        // ai.randomize(prng);
        // g_ai = mG * ai;
        // akrandom.resize(nParties);
        // akrandom.emplace_back(mCrurve);
        // akrandom[0] = g_ai;
        for (u64 i = 1; i < nParties; i++)
        {
            tempPoint = mCrurve;
            std::vector<u8> points(g_ai.sizeBytes());
            macoro::sync_wait(chl[i].recv((points)));
            tempPoint.fromBytes(points.data());
            akrandom.emplace_back(mCrurve);
            akrandom[i] = tempPoint;
        }
        // Create collection sized elliptical curve points
        for (u64 i = 0; i < setSize; i++)
        {
            nSeeds.emplace_back(mCrurve);
            nSeeds[i].randomize(prng);
            mypoint.emplace_back(mCrurve);
            mypoint[i] = mG * nSeeds[i]; // g^ri
            values[i] = REccPoint_to_Vector(mypoint[i]);
        }

        len = values[0].size();
        val.resize(setSize, len);
#pragma omp parallel for num_threads(numThreads)

        for (u64 i = 0; i < setSize; i++)
        {
            // Make sure the size of the vector in values[i] matches the number of columns 'n'
            COPROTO_ASSERT(values[i].size() == len);
            // Copy each element from the vector in values[i] to the corresponding row in the 'val' matrix
#pragma omp parallel for num_threads(numThreads)
            for (size_t j = 0; j < len; j++)
            {
                val(i, j) = values[i][j];
            }
        }

        //  OKVS encode for (inputs, g_(a_i))
        paxos.init(setSize, 128, 3, stasecParam, PaxosParam::Binary, block(0, 0));
        pax.resize(paxos.size(), len);
        paxos.solve<u8>(inputs, val, pax, &prng, numThreads);
        // send parameters of OKVS encode results
#pragma omp parallel for num_threads(numThreads)
        for (u64 i = 1; i < nParties; i++)
        {
            macoro::sync_wait(chl[i].send(paxos.size()));
            macoro::sync_wait(chl[i].send(len));
            macoro::sync_wait(chl[i].send(coproto::copy(pax)));
        }

        /*
            Homomorphism of XOR operations
            a^b^c=(a^c)^(b^c)
         */
        // #pragma omp parallel for num_threads(numThreads)
        for (u64 i = 1; i < nParties; i++)
        {
            size_t size = 0;
            macoro::sync_wait(chl[i].recv(size));
            oc::Matrix<u8> pax2(size, len);
            macoro::sync_wait(chl[i].recv(pax2));
            oc::Matrix<u8> val3(setSize, len);
            paxos.decode<u8>(inputs, val3, pax2, numThreads);
            // Convert a vector to ReccPoint and perform XOR operation
            allpx[i].resize(setSize);
            // #pragma omp parallel for num_threads(numThreads)
            for (u64 k = 0; k < val3.rows(); k++)
            {
                std::vector<u8> tem(val3.cols());
                for (u64 j = 0; j < val3.cols(); j++)
                {
                    tem[j] = val3[k][j];
                }
                allpx[i][k] = vector_to_REccPoint(tem);
            }
        }
        // The final result of the XOR operation is saved in the second row of allpx
        // Insert the XOR operation result into the bloom filter
        // The time cost of using bloom filter is almost equal to that of using unordered_multiset
        std::unordered_multiset<std::string> result(setSize);
        for (u64 j = 0; j < allpx[1].size(); j++)
        {
            // #pragma omp parallel for num_threads(numThreads)
            for (u64 i = 2; i < allpx.size(); i++)
            {
                allpx[1][j] = allpx[1][j] + allpx[i][j];
            }
            allpx[1][j] = REccPoint_xor_u8(allpx[1][j], zeroValue);
        }

        // create the key set for leader
        // This loop code has a high time cost and needs to be optimized 
        for (u64 i = 0; i < setSize; i++)
        {
            std::vector<REccPoint> userkey(nParties);
            userkey.emplace_back(mCrurve);
            for (u64 j = 1; j < nParties; j++)
            {
                userkey.emplace_back(mCrurve);
                userkey[j] = (akrandom[j] * nSeeds[i]);
            }
            // xor operation
            for (u64 k = 2; k < nParties; k++)
            {
                userkey[1] = userkey[1] + userkey[k];
            }
            result.insert(REccPoint_to_string(userkey[1]));
        }
        for (u64 i = 0; i < setSize; i++)
        {
            auto it = result.find(REccPoint_to_string(allpx[1][i]));
            if (it != result.end())
            {
                outputs.push_back(reinputs[i]);
            }
        }
        timer.setTimePoint("miniMPSI::reciver end");
        std::cout << timer << std::endl;
        // for (u64 i = 0; i < outputs.size(); i++)
        // {
        //     std::cout << outputs[i] << std::endl;
        // }
        // macoro::sync_wait(macoro::suspend_always{});
        // for (u64 i = 0; i < chl.size(); i++)
        // {
        //     if (i != myIdx)
        //     {
        //         (chl[i].flush());
        //         chl[i].close();
        //     }
        // }
        return outputs;
    };
    void miniMPSIReceiver_re::init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize, std::vector<block> inputs, bool malicious, u64 numThreads)
    {
        this->secParam = secParam;
        this->stasecParam = stasecParam;
        this->nParties = nParties;
        this->myIdx = myIdx;
        this->setSize = setSize;
        this->inputs = inputs;
        this->malicious = malicious;
        this->numThreads = numThreads;
    }
}