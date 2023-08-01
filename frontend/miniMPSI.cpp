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
        // 选择随机值 a_i 并生成 g^(a_i) 发送给leader
        prng.SetSeed(toBlock(myIdx, myIdx));
        // mG(mCrurve);
        mG = mCrurve.getGenerator();
        ai.randomize(prng);
        g_ai = mG * ai;
        // 发送 g_ai
        tempbuf = new u8[g_ai.sizeBytes()];
        g_ai.toBytes(tempbuf);
        MC_AWAIT(chl[0].send(tempbuf));
        // 接收 okvs 打包后向量
        // 先接收行大小
        MC_AWAIT(chl[0].recv(size));
        // 接收列大小
        MC_AWAIT(chl[0].recv(len));
        pax.resize(size, len), val.resize(setSize, len);
        // 接收OKVS 向量
        MC_AWAIT(chl[0].recv(pax));
        // 解码
        val2.resize(setSize, len);
        val.resize(setSize, len);
        pax.resize(size, len);
        MC_AWAIT(chl[0].recv(val2));
        paxos.init(setSize, 128, 3, stasecParam, PaxosParam::Binary, block(0, 0));
        paxos.decode<u8>(inputs, val, pax, 0);
        PrintLine('-');
        if (myIdx == 1)
        {
            std::cout << "receiver 输出val2" << std::endl;
            for (u64 k = 0; k < setSize; k++)
            {

                for (u64 j = 0; j < len; j++)
                    std::cout << (int)val2(k, j) << " ";
                std::cout << std::endl;
            }
            PrintLine('-');
            std::cout << "输出 解码后的val" << std::endl;
            for (u64 k = 0; k < setSize; k++)
            {

                for (u64 j = 0; j < len; j++)
                    std::cout << (int)val(k, j) << " ";
                std::cout << std::endl;
            }
            PrintLine('-');

            std::cout << "解码测试" << std::endl;
            for (u64 i = 0; i < setSize; i++)
            {
                bool flag = true;
                for (u64 j = 0; j < len; j++)
                {
                    if ((int)val(i, j) != (int)val2(i, j))
                        flag = false;
                }
                if (flag == true)
                    std::cout << "i: " << i << " euqal" << std::endl;
                else
                    std::cout << "i: " << i << "not euqal" << std::endl;
            }
        }
        PrintLine('-');

        // 计算g_(a_i*b_i)
        // 先不进行零共享值异或 进行测试
        // Matrix_xor_Vector(val, zeroValue);
        for (u64 i = 0; i < setSize; i++)
        {
            std::vector<u8> vec(len);
            for (u64 j = 0; j < len; j++)
                vec[j] = val[i][j];
            px.emplace_back(mCrurve);
            px[i] = vector_to_REccPoint(vec);
            // 计算 g^(b_i*a_i)
            npx.emplace_back(mCrurve);
            npx[i] = px[i] * ai;
            // 密钥k与 零共享值进行异或
            npx[i] = REccPoint_xor_u8(npx[i], zeroValue);
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
        paxos.solve<u8>(inputs, val, pax2, &prng);
        // 发送pax 行大小
        // 直接发送 paxos.size() 不行 会阻塞 不知道为什么
        size = paxos.size();
        MC_AWAIT(chl[0].send(size));
        // 发送 pax 向量
        MC_AWAIT(chl[0].send(coproto::copy(pax2)));
        // 发送数据进行测试
        MC_AWAIT(chl[0].send(coproto::copy(val)));
        // 发送 val 给leader 进行解码测试
        // if (myIdx == 1)
        //     MC_AWAIT(chl[0].send(coproto::copy(val)));
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
        for (u64 i = 0; i < setSize; i++)
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
        for (u64 i = 0; i < setSize; i++)
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
        // prng1::SetSeed();
        paxos.solve<u8>(inputs, val, pax, &prng);
        // 发送paxos 打包向量行大小
        for (u64 i = 1; i < nParties; i++)
            macoro::sync_wait(chl[i].send(paxos.size()));
        // 发送paxos 打包向量列大小
        for (u64 i = 1; i < nParties; i++)
            macoro::sync_wait(chl[i].send(len));
        // 发送paxos 打包结果向量
        for (u64 i = 1; i < nParties; i++)
            macoro::sync_wait(chl[i].send(coproto::copy(pax)));
        // 发送数据给参与方进行解码测试
        for (u64 i = 1; i < nParties; i++)
            macoro::sync_wait(chl[i].send(coproto::copy(val)));
        std::cout << "sender 输出val" << std::endl;
        for (u64 k = 0; k < setSize; k++)
        {

            for (u64 j = 0; j < len; j++)
                std::cout << (int)val(k, j) << " ";
            std::cout << std::endl;
        }
        // 解码测试
        // paxos.decode<u8>(inputs, )
        // 创建一个全是1的Matrix
        onevalue.resize(setSize, len);
        for (u64 i = 0; i < setSize; i++)
            for (u64 j = 0; j < len; j++)
                onevalue(i, j) = 0;
        // 接收其他参与方的OKVS
        /*
            异或运算的同态性
            a^b^c=(a^c)^(b^c)
         */
        for (u64 i = 1; i < nParties; i++)
        {
            size_t size = 0;
            macoro::sync_wait(chl[i].recv(size));
            oc::Matrix<u8> pax2(size, len);
            // pax2.resize(size, len);
            macoro::sync_wait(chl[i].recv(pax2));
            /* 初始化 paxos */
            // val(setSize, len), val2(setSize, len);
            oc::Matrix<u8> val3(setSize, len);
            // Baxos paxos1;
            // paxos1.init(setSize, 64, 3, stasecParam, PaxosParam::Binary, block(0, 0));
            paxos.decode<u8>(inputs, val3, pax2, 0);
            val2.resize(setSize, len);
            macoro::sync_wait(chl[i].recv(val2));
            PrintLine('-');
            for (u64 i = 0; i < setSize; i++)
            {
                bool flag = true;
                for (u64 j = 0; j < len; j++)
                {
                    if (val2(i, j) != val3(i, j))
                        flag = false;
                }
                if (flag == true)
                    std::cout << "i: " << i << " equal" << std::endl;
                else
                    std::cout << "i: " << i << "not equal" << std::endl;
            }
            PrintLine('-');
            // 将其转为REccPoint 再进行异或运算
            allpx[i].resize(setSize);
            // allpx.emplace_back(mCrurve);

            for (u64 k = 0; k < val3.rows(); k++)
            {
                std::vector<u8> tem(val3.cols());
                for (u64 j = 0; j < val3.cols(); j++)
                {
                    tem[j] = val3[k][j];
                }
                // REccPoint poi(mCrurve);
                // allpx[i][k] = poi;
                // allpx[i].emplace_back(mCrurve);
                allpx[i][k] = vector_to_REccPoint(tem);
                // std::cout << allpx[i][k] << std::endl;
            }
            // 进行异或运算
            // if (i == 1)
            //     val2 = Matrix_xor(onevalue, val3);
            // else
            // {
            //     val2 = Matrix_xor(val2, val3);
            // }
        }
        // 进行异或运算 最后的结果保存在 allpx 的第二行
        for (u64 j = 0; j < allpx[1].size(); j++) // 遍历每一列
        {
            for (u64 i = 2; i < allpx.size(); i++) // 从第三行开始遍历，跳过第一、二行
            {
                allpx[1][j] = allpx[1][j] + allpx[i][j]; // 将第 i 行第 j 列的元素加到第二行第 j 列上
            }
        }
        // 异或运算
        for (u64 i = 0; i < setSize; i++)
        {
            allpx[1][i] = REccPoint_xor_u8(allpx[1][i], zeroValue);
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
            userkey.emplace_back(mCrurve);
            for (u64 j = 1; j < nParties; j++)
            {
                userkey.emplace_back(mCrurve);
                userkey[j] = (akrandom[j] * nSeeds[i]);
                if (i == 1)
                    std::cout << userkey[j] << std::endl;
            }
            // 进行异或运算
            for (u64 k = 2; k < nParties; k++)
            {
                userkey[1] = userkey[1] + userkey[k];
            }
            // std::cout << "add userkey 1" << userkey[1] << std::endl;

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
            // std::cout << userkey[1] << std::endl;
            for (u64 j = 0; j < setSize; j++)
            {

                if (userkey[1] == allpx[1][j])
                    intersection_size++;
                // else
            }
            // keymap.insert(REccPoint_to_string(userkey[1]));
        }
        Filter.init(setSize, stasecParam);
        Filter.Insert(allpx[1]);
        Filter.PrintInfo();
        for (u64 i = 0; i < allpx[1].size(); i++)
        {
            bool f = Filter.Contain(allpx[1][i]);
            std::cout << "check bloom: " << f << std::endl;
        }
        std::cout << "check bloom: " << Filter.Contain(allpx[2][1]) << std::endl;
        std::cout << "check bloom: " << Filter.Contain(allpx[2][2]) << std::endl;
        std::cout << "check bloom: " << Filter.Contain(allpx[2][3]) << std::endl;

        std::cout << "keymap size: " << keymap.size() << std::endl;
        std::cout << "输出allpx-------" << std::endl;
        std::cout << "allpx size: " << allpx.size() << "  " << allpx[1].size() << std::endl;
        for (u64 i = 0; i < allpx[1].size(); i++)
            std::cout << "allpx: " << allpx[1][i] << std::endl;
        //  求交集
        //  for (u64 i = 0; i < allpx[0].size(); i++)
        //  {
        //      std::string str;
        //      // std::vector<u8> rc(val2[i].size());
        //      // for (u64 j = 0; j < val2.cols(); j++)
        //      // {
        //      //     // str += std::to_string(val2(i, j));
        //      //     rc[j] = val2(i, j);
        //      // }
        //      // REccPoint po = vector_to_REccPoint(rc);
        //      // std::cout << "po i: " << i << "  " << po << std::endl;
        //      str = REccPoint_to_string(allpx[0][i]);
        //      // std::cout << "str: " << i << " " << str << std::endl;
        //      auto it = keymap.find(str);
        //      if (it != keymap.end())
        //      {
        //          intersection_size++;
        //          std::cout << "Found: " << *it << std::endl;
        //      }
        //      else
        //      {
        //          std::cout << "Not found" << std::endl;
        //      }
        //  }
        std::cout << "intersectionsize size=" << intersection_size << std::endl;
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