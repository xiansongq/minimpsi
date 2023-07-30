#include "miniMPSI.h"

namespace volePSI
{
    void miniMPSISender::init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize, std::vector<block> inputs, bool malicious)
    {
        this->secParam = secParam;
        this->stasecParam = stasecParam;
        this->nParties = nParties;
        this->myIdx = myIdx;
        this->setSize = setSize;
        this->inputs = inputs;
        this->malicious = malicious;
    }

    Proto miniMPSISender::send(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads)
    {
        MC_BEGIN(Proto, this, &mseed, &chl, numThreads,
                 num = u64{0},
                 zeroValue = std::vector<u8>(nParties),
                 mCrurve = REllipticCurve{},
                 mG = REllipticCurve::Point{},
                 prng = PRNG{},
                 val = oc::Matrix<u8>{},
                 val2 = oc::Matrix<u8>{},
                 pax = oc::Matrix<u8>{},
                 pax2 = oc::Matrix<u8>{},
                 len = size_t{0},
                 size = size_t{0},
                 px = std::vector<REccPoint>(setSize),
                 npx = std::vector<REccPoint>(setSize),
                 values = std::vector<std::vector<u8>>(setSize),
                 mvec = std::vector<u8>{},
                 thrds = std::vector<std::thread>(nParties),
                 fork = Socket{});
        // 首先创建 零共享值
        zeroValue[0] = 0;
        for (u64 i = 0; i < nParties; i++)
        {
            if (i != myIdx)
                zeroValue[i] = zeroValue[i] ^ mseed[i].get<u8>();
        }
        // for (u64 i = 0; i < nParties; i++)
        //     std::cout << (int)zeroValue[i] << " ";
        //  std::cout << std::endl;
        // 选择随机值 a_i 并生成 g^(a_i) 发送给leader
        prng.SetSeed(toBlock(myIdx, myIdx));
        mG = mCrurve.getGenerator();
        ai.randomize(prng);
        g_ai = mG * ai;
        // 发送 g_ai
        tempbuf = new u8[g_ai.sizeBytes()];
        g_ai.toBytes(tempbuf);
        MC_AWAIT(chl[0].send(tempbuf));
        // 接收 okvs 打包后向量
        // 先接受行大小
        MC_AWAIT(chl[0].recv(size));
        // 接收列大小
        MC_AWAIT(chl[0].recv(len));
        pax.resize(size, len), val.resize(setSize, len);
        MC_AWAIT(chl[0].recv(pax));

        // 解码测试
        val2.resize(setSize, len);
        // MC_AWAIT(chl[0].recv(val2));
        paxos.init(setSize, 64, 3, stasecParam, PaxosParam::Binary, block(0, 0));
        paxos.decode<u8>(inputs, val, pax, 0);
        // 接收val
        val2.resize(setSize, len);
        /*         if (myIdx == 1)
                {
                    {
                        for (u64 i = 0; i < setSize; i++)
                        {
                            bool flag = true;
                            for (u64 j = 0; j < val[i].size(); j++)
                            {
                                if (val[i][j] != val2[i][j])
                                {
                                    flag = false;
                                    break;
                                }
                            }
                            if (flag == true)
                                std::cout << "i: " << i << " queal" << std::endl;
                            else
                                std::cout << "i: " << i << " not equal" << std::endl;
                        }
                    }
                } */
        // 计算g_(a_i*b_i)
        // 先不进行零共享值异或 进行测试
        // Matrix_xor_Vector(val, zeroValue);
        for (u64 i = 0; i < setSize; i++)
        {
            std::vector<u8> vec;
            for (auto a : val[i])
                vec.push_back(a);
            px[i] = vector_to_REccPoint(vec);

            // 计算 g^(b_i*a_i)
            npx[i] = px[i] * ai;
            // 密钥k与 零共享值进行异或
            // npx[i] = REccPoint_xor_u8(npx[i], zeroValue);
        }
        // 进行新的一轮 OKVS打包
        paxos.init(setSize, 64, 3, stasecParam, PaxosParam::Binary, block(0, 0));
        /* 列的大小应该是不改变的 因为与REccPoint 的大小相关 */
        pax2.resize(paxos.size(), len);
        for (u64 i = 0; i < setSize; i++)
        {
            values[i] = REccPoint_to_Vector(npx[i]);
            for (size_t j = 0; j < len; j++)
                val(i, j) = values[i][j];
        }
        // 打包
        paxos.solve<u8>(inputs, val, pax2, nullptr);
        // 发送pax 行大小
        // 直接发送 paxos.size() 不行 会阻塞 不知道为什么
        size = paxos.size();
        MC_AWAIT(chl[0].send(size));
        // 发送 pax 向量
        MC_AWAIT(chl[0].send(coproto::copy(pax2)));
        MC_AWAIT(macoro::suspend_always{});
        for (u64 i = 0; i < chl.size(); i++)
        {
            if (i != myIdx)
            {
                (chl[i].flush());
                chl[i].close();
            }
        }
        MC_END();
    };
    Proto miniMPSIReceiver::receive(std::vector<PRNG> &mseed, std::vector<Socket> &chl, u64 numThreads)
    {
        MC_BEGIN(Proto, this, &mseed, &chl, numThreads,
                 zeroValue = std::vector<u8>(nParties),
                 mCrurve = REllipticCurve{},
                 mG = REllipticCurve::Point{},
                 prng = PRNG{},
                 num = u64{1000011},
                 fork = Socket{},
                 tempPoint = REccPoint{},
                 akrandom = std::vector<REccPoint>(nParties),
                 nSeeds = std::vector<REccNumber>(nParties),
                 mypoint = std::vector<REccPoint>(nParties),
                 values = std::vector<std::vector<u8>>(setSize),
                 val = oc::Matrix<u8>{},
                 val2 = oc::Matrix<u8>{},
                 pax = oc::Matrix<u8>{},
                 len = size_t{0},
                 size = u64{0},
                 allval = std::vector<oc::Matrix<u8>>{},
                 px = std::vector<REccPoint>(setSize),
                 npx = std::vector<REccPoint>(setSize),
                 allpx = std::vector<std::vector<REccPoint>>(nParties),
                 keymap = std::unordered_multiset<std::string>(setSize * nParties),
                 onevalue = oc::Matrix<u8>{},
                 mvec = std::vector<u8>{},
                 intersection_size = u64{0},
                 thrds = std::vector<std::thread>(nParties));

        // 生成零共享值
        zeroValue[0] = 0;
        for (u64 i = 1; i < nParties; i++)
        {
            zeroValue[i] = zeroValue[i] ^ mseed[i].get<u8>();
        }
        // 接收 g_ai
        prng.SetSeed(toBlock(myIdx, myIdx));
        mG = mCrurve.getGenerator();
        // ai.randomize(prng);
        // g_ai = mG * ai;
        // // akrandom.resize(nParties);
        // akrandom.emplace_back(mCrurve);
        // akrandom[0] = g_ai;
        for (u64 i = 1; i < nParties; i++)
        {
            tempPoint = mCrurve;
            tempbuf = new u8[g_ai.sizeBytes()];
            macoro::sync_wait(chl[i].recv(tempbuf));
            tempPoint.fromBytes(tempbuf);
            akrandom.emplace_back(mCrurve);
            akrandom[i] = tempPoint;
        }
        // 创建集合大小的 椭圆曲线点
        for (int i = 0; i < setSize; i++)
        {
            nSeeds.emplace_back(mCrurve);
            nSeeds[i].randomize(prng);
            mypoint.emplace_back(mCrurve);
            mypoint[i] = mG * nSeeds[i]; // g^ri
            values[i] = REccPoint_to_Vector(mypoint[i]);
        }
        // 测试一下 Point 与 vector 之间互转的成功性
        // for (u64 i = 0; i < setSize; i++)
        // {
        //     std::vector<u8> nm = REccPoint_to_Vector(mypoint[i]);
        //     REccPoint rc = vector_to_REccPoint(nm);
        //     if (rc == mypoint[i])
        //         std::cout << "True"
        //                   << " " << i << std::endl;
        //     else
        //         std::cout << "False"
        //                   << " " << i << std::endl;
        // }
        len = values[0].size();
        val.resize(setSize, len);
        for (int i = 0; i < setSize; i++)
        {
            // Make sure the size of the vector in values[i] matches the number of columns 'n'
            COPROTO_ASSERT(values[i].size() == len);
            // Copy each element from the vector in values[i] to the corresponding row in the 'val' matrix
            for (size_t j = 0; j < len; j++)
            {
                val(i, j) = values[i][j];
            }
        }

        // REccPoint_xor_Test(mypoint[1], zeroValue);
        //  OKVS 打包
        paxos.init(setSize, 64, 3, stasecParam, PaxosParam::Binary, block(0, 0));
        pax.resize(paxos.size(), len);
        paxos.solve<u8>(inputs, val, pax, nullptr);
        // 发送paxos 打包向量行大小
        for (u64 i = 1; i < nParties; i++)
            macoro::sync_wait(chl[i].send(paxos.size()));
        // 发送paxos 打包向量列大小
        for (u64 i = 1; i < nParties; i++)
            macoro::sync_wait(chl[i].send(len));
        for (u64 i = 1; i < nParties; i++)
            macoro::sync_wait(chl[i].send(coproto::copy(pax)));
        // for (u64 i = 1; i < nParties; i++)
        //     macoro::sync_wait(chl[i].send(coproto::copy(val)));
        // 创建一个全是1的Matrix
        onevalue.resize(setSize, len);
        for (u64 i = 0; i < setSize; i++)
            for (u64 j = 0; j < len; j++)
                onevalue(i, j) = 1;
        // 接收其他参与方的OKVS
        for (u64 i = 1; i < nParties; i++)
        {
            size_t size = 0;
            macoro::sync_wait(chl[i].recv(size));
            std::cout << "paxos size: " << size << std::endl;
            oc::Matrix<u8> pax2(size, len);
            // pax2.resize(size, len);
            macoro::sync_wait(chl[i].recv(pax2));
            std::cout << "recv pax2 value: " << (int)pax2(10, 10) << std::endl;
            std::cout << "recver pax size: " << pax2.rows() << " " << pax2.cols() << std::endl;

            /* 初始化 paxos */
            // val(setSize, len), val2(setSize, len);
            oc::Matrix<u8> val3(setSize, len);
            // Baxos paxos1;
            // paxos1.init(setSize, 64, 3, stasecParam, PaxosParam::Binary, block(0, 0));

            paxos.decode<u8>(inputs, val3, pax2, 0);
            // 将其转为REccPoint 再进行异或运算
            allpx[i].reserve(setSize);
            for (u64 k = 0; k < val3.rows(); k++)
            {
                std::vector<u8> tem(val3[k].size());
                for (u64 j = 0; j < val3.cols(); j++)
                {
                    tem[j] = val3[k][j];
                }
                allpx[i][k] = vector_to_REccPoint(tem);
            }
            // 进行异或运算
            // if (i == 1)
            //     val2 = Matrix_xor(onevalue, val3);
            // else
            // {
            //     val2 = Matrix_xor(val2, val3);
            // }
        }
        // 进行异或运算 最后的结果保存在 allpx 的第一行
        for (u64 j = 0; j < allpx[0].size(); j++) // 遍历每一列
        {
            for (u64 i = 1; i < allpx.size(); i++) // 从第二行开始遍历，跳过第一行
            {
                allpx[0][j] = allpx[0][j] + allpx[i][j]; // 将第 i 行第 j 列的元素加到第一行第 j 列上
            }
        }
        // 最后解码的结果 还需要异或上 零共享值
        /* 这一步主要是计算从所有其他参与方接收到的OKVS异或后的结果 再与leader 零共享值的异或 */
        // Matrix_xor_Vector(val2, zeroValue);
        //  先将matrix 恢复为REccPoint 在与 零共享值异或
        /* 打印一下zeroValue */
        /*       for (u64 i = 0; i < setSize; i++)
              {
                  std::vector<u8> vec;
                  for (auto a : val2[i])
                      vec.push_back(a);
                  px[i] = vector_to_REccPoint(vec);
                  // 计算 g^(b_i*a_i)
                  npx[i] = px[i] * ai;
                  // 密钥k与 零共享值进行异或
                  // npx[i] = REccPoint_xor_u8(npx[i], zeroValue);
                  // std::cout <<"i: "<<i<< npx[i] << std::endl;
              } */
        // 生成所有的密钥k 集合
        for (u64 i = 0; i < setSize; i++)
        {

            std::vector<REccPoint> userkey(nParties);
            for (u64 j = 1; j < nParties; j++)
            {
                userkey[j] = (akrandom[j] * nSeeds[i]);
            }
            // 进行异或运算
            for (u64 k = 2; k < userkey.size(); k++)
            {
                userkey[1] = userkey[1] + userkey[k];
            }
            // REccPoint tem;
            // for (u64 j = 1; j < userkey.size(); j++)
            // {
            //     if (j == 0)
            //         tem = REccPoint_xor(userkey[j], userkey[j + 1]);
            //     else
            //         tem = REccPoint_xor(userkey[j], tem);
            // }
            // std::cout << "tem i: " << i << "  " << tem << std::endl;
            // std::cout << "tem: " << i << "  " << REccPoint_to_string(tem) << std::endl;
            std::cout << "到这里一切正常" << std::endl;

            for (u64 j = 0; j < setSize; j++)
            {
                if (userkey[1] == allpx[0][j])
                    std::cout << "True" << std::endl;
                else
                    std::cout << "False" << std::endl;
            }
            keymap.insert(REccPoint_to_string(userkey[1]));
        }
        std::cout << "keymap size: " << keymap.size() << std::endl;
        // 求交集
        // for (u64 i = 0; i < allpx[0].size(); i++)
        // {
        //     std::string str;
        //     // std::vector<u8> rc(val2[i].size());
        //     // for (u64 j = 0; j < val2.cols(); j++)
        //     // {
        //     //     // str += std::to_string(val2(i, j));
        //     //     rc[j] = val2(i, j);
        //     // }
        //     // REccPoint po = vector_to_REccPoint(rc);
        //     // std::cout << "po i: " << i << "  " << po << std::endl;
        //     str = REccPoint_to_string(allpx[0][i]);
        //     // std::cout << "str: " << i << " " << str << std::endl;
        //     auto it = keymap.find(str);
        //     if (it != keymap.end())
        //     {
        //         intersection_size++;
        //         std::cout << "Found: " << *it << std::endl;
        //     }
        //     else
        //     {
        //         std::cout << "Not found" << std::endl;
        //     }
        // }
        // std::cout << "intersectionsize size=" << intersection_size << std::endl;
        for (u64 i = 0; i < chl.size(); i++)
        {
            if (i != myIdx)
            {
                (chl[i].flush());
                chl[i].close();
            }
        }
        MC_END();
    };
    void miniMPSIReceiver::init(u64 secParam, u64 stasecParam, u64 nParties, u64 myIdx, u64 setSize, std::vector<block> inputs, bool malicious)
    {
        this->secParam = secParam;
        this->stasecParam = stasecParam;
        this->nParties = nParties;
        this->myIdx = myIdx;
        this->setSize = setSize;
        this->inputs = inputs;
        this->malicious = malicious;
    }
}