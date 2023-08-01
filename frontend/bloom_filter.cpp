#include "bloom_filter.h"

namespace volePSI
{
    // 00000001 00000010 00000100 00001000 00010000 00100000 01000000 10000000
    static const u8 bit_mask[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

// selection of keyed hash for bloom filter
#define FastKeyedHash LiteMurmurHash // an alternative choice is MurmurHash3

    /*
      Note:A distinct hash function need not be implementation-wise distinct.
      In the current implementation "seeding" a common hash function with different values seems to be adequate.
    */
    std::vector<u32> GenUniqueSaltVector(size_t hash_num, u32 random_seed)
    {
        const size_t predefined_salt_num = 128;
        static const u32 predefined_salt[predefined_salt_num] = {
            0xAAAAAAAA, 0x55555555, 0x33333333, 0xCCCCCCCC, 0x66666666, 0x99999999, 0xB5B5B5B5, 0x4B4B4B4B,
            0xAA55AA55, 0x55335533, 0x33CC33CC, 0xCC66CC66, 0x66996699, 0x99B599B5, 0xB54BB54B, 0x4BAA4BAA,
            0xAA33AA33, 0x55CC55CC, 0x33663366, 0xCC99CC99, 0x66B566B5, 0x994B994B, 0xB5AAB5AA, 0xAAAAAA33,
            0x555555CC, 0x33333366, 0xCCCCCC99, 0x666666B5, 0x9999994B, 0xB5B5B5AA, 0xFFFFFFFF, 0xFFFF0000,
            0xB823D5EB, 0xC1191CDF, 0xF623AEB3, 0xDB58499F, 0xC8D42E70, 0xB173F616, 0xA91A5967, 0xDA427D63,
            0xB1E8A2EA, 0xF6C0D155, 0x4909FEA3, 0xA68CC6A7, 0xC395E782, 0xA26057EB, 0x0CD5DA28, 0x467C5492,
            0xF15E6982, 0x61C6FAD3, 0x9615E352, 0x6E9E355A, 0x689B563E, 0x0C9831A8, 0x6753C18B, 0xA622689B,
            0x8CA63C47, 0x42CC2884, 0x8E89919B, 0x6EDBD7D3, 0x15B6796C, 0x1D6FDFE4, 0x63FF9092, 0xE7401432,
            0xEFFE9412, 0xAEAEDF79, 0x9F245A31, 0x83C136FC, 0xC3DA4A8C, 0xA5112C8C, 0x5271F491, 0x9A948DAB,
            0xCEE59A8D, 0xB5F525AB, 0x59D13217, 0x24E7C331, 0x697C2103, 0x84B0A460, 0x86156DA9, 0xAEF2AC68,
            0x23243DA5, 0x3F649643, 0x5FA495A8, 0x67710DF8, 0x9A6C499E, 0xDCFB0227, 0x46A43433, 0x1832B07A,
            0xC46AFF3C, 0xB9C8FFF0, 0xC9500467, 0x34431BDF, 0xB652432B, 0xE367F12B, 0x427F4C1B, 0x224C006E,
            0x2E7E5A89, 0x96F99AA5, 0x0BEB452A, 0x2FD87C39, 0x74B2E1FB, 0x222EFD24, 0xF357F60C, 0x440FCB1E,
            0x8BBE030F, 0x6704DC29, 0x1144D12F, 0x948B1355, 0x6D8FD7E9, 0x1C11A014, 0xADD1592F, 0xFB3C712E,
            0xFC77642F, 0xF9C4CE8C, 0x31312FB9, 0x08B0DD79, 0x318FA6E7, 0xC040D23D, 0xC0589AA7, 0x0CA5C075,
            0xF874B172, 0x0CF914D5, 0x784D3280, 0x4E8CFEBC, 0xC569F575, 0xCDB2A091, 0x2CC016B4, 0x5C5F4421};

        std::vector<u32> vec_salt;
        if (hash_num <= predefined_salt_num)
        {
            std::copy(predefined_salt, predefined_salt + hash_num, std::back_inserter(vec_salt));
            // integrate the user defined random seed to allow for the generation of unique bloom filter instances.
            for (auto i = 0; i < hash_num; i++)
            {
                vec_salt[i] = vec_salt[i] * vec_salt[(i + 3) % vec_salt.size()] + random_seed;
            }
        }
        else
        {
            std::copy(predefined_salt, predefined_salt + predefined_salt_num, std::back_inserter(vec_salt));
            srand(random_seed);
            while (vec_salt.size() < hash_num)
            {
                u32 current_salt = rand() * rand();
                if (0 == current_salt)
                    continue;
                if (vec_salt.end() == std::find(vec_salt.begin(), vec_salt.end(), current_salt))
                {
                    vec_salt.emplace_back(current_salt);
                }
            }
        }

        return vec_salt;
    }

    // 构造函数实现和其他成员函数的具体实现
    BloomFilter::BloomFilter()
    {
    }
    void BloomFilter::init(size_t max_element_num, size_t statistical_security_parameter)
    {
        // desired_false_positive_probability = 1/2^{statistical_security_parameter/2};
        // hash_num = static_cast<size_t>(-log2(desired_false_positive_probability));
        hash_num = statistical_security_parameter / 2;
        random_seed = static_cast<u32>(0xA5A5A5A55A5A5A5A * 0xA5A5A5A5 + 1);
        vec_salt = GenUniqueSaltVector(hash_num, random_seed);
        // table_size = static_cast<u32>(max_element_num * (-1.44 * log2(desired_false_positive_probability)));
        table_size = static_cast<u32>(max_element_num * (1.44 * statistical_security_parameter / 2));
        // the following operation is very important => make table size = 8*n
        table_size = ((table_size + 0x07) >> 3) << 3; // (table_size+7)/8*8

        bit_table.resize(table_size / 8, static_cast<u8>(0x00)); // naive implementation
        projected_element_num = max_element_num;
        inserted_element_num = 0;
    }
    BloomFilter::BloomFilter(size_t max_element_num, size_t statistical_security_parameter)
    {
        // desired_false_positive_probability = 1/2^{statistical_security_parameter/2};
        // hash_num = static_cast<size_t>(-log2(desired_false_positive_probability));
        hash_num = statistical_security_parameter / 2;
        random_seed = static_cast<u32>(0xA5A5A5A55A5A5A5A * 0xA5A5A5A5 + 1);
        vec_salt = GenUniqueSaltVector(hash_num, random_seed);
        // table_size = static_cast<u32>(max_element_num * (-1.44 * log2(desired_false_positive_probability)));
        table_size = static_cast<u32>(max_element_num * (1.44 * statistical_security_parameter / 2));
        // the following operation is very important => make table size = 8*n
        table_size = ((table_size + 0x07) >> 3) << 3; // (table_size+7)/8*8

        bit_table.resize(table_size / 8, static_cast<u8>(0x00)); // naive implementation
        projected_element_num = max_element_num;
        inserted_element_num = 0;
    }

    BloomFilter::~BloomFilter()
    {
        // 析构函数实现
        // ...
    }

    size_t BloomFilter::ObjectSize()
    {
        /*
         ** hash_num + random_seed + table_size + projected_element_num + inserted_element_num + table_content
         ** one can derive vec_salt from random_seed, so there is no need to save them
         */
        return 3 * sizeof(u32) + 2 * sizeof(size_t) + table_size / 8;
    }

    void BloomFilter::PlainInsert(const void *input, size_t LEN)
    {
        size_t bit_index[hash_num];

#pragma omp parallel for num_threads(6)
        for (auto i = 0; i < hash_num; i++)
        {
            bit_index[i] = FastKeyedHash(vec_salt[i], input, LEN) % table_size;
#pragma omp atomic // atomic operation
            bit_table[bit_index[i] >> 3] |= bit_mask[bit_index[i] & 0x07];
        }
#pragma omp atomic
        inserted_element_num++;
    }

    // template成员函数的具体实现可以直接放在头文件中，不需要在cpp文件中单独实现

    bool BloomFilter::PlainContain(const void *input, size_t LEN) const
    {
        bool CONTAIN = true; // assume input in filter at the beginning
        std::vector<size_t> bit_index(hash_num);
        std::vector<size_t> local_bit_index(hash_num);
#pragma omp parallel for num_threads(6)
        for (auto i = 0; i < hash_num; i++)
        {
            if (CONTAIN == true)
            {
                bit_index[i] = FastKeyedHash(vec_salt[i], input, LEN) % table_size;
                local_bit_index[i] = bit_index[i] & 0x07; // bit_index mod 8
                if ((bit_table[bit_index[i] >> 3] & bit_mask[local_bit_index[i]]) != bit_mask[local_bit_index[i]])
                {
                    CONTAIN = false;
                }
            }
        }
        return CONTAIN;
    }

    template <typename ElementType>
    bool BloomFilter::Contain(const ElementType &element) const
    {
        return PlainContain(&element, sizeof(ElementType));
    }

    bool BloomFilter::Contain(const std::string &str) const
    {
        return PlainContain(str.data(), str.size());
    }

    void BloomFilter::Insert(const std::string &str)
    {
        PlainInsert(str.data(), str.size());
    }

    void BloomFilter::Insert(const std::vector<std::vector<u8>> &str)
    {
#pragma omp parallel for num_threads(6)
        for (auto i = 0; i < str.size(); i++)
        {
            unsigned char buffer[str[i].size()];
            memcpy(buffer, str[i].data(), str[i].size());
            PlainInsert(buffer, str[i].size());
            // delete[] buffer;
        }
    }
    void BloomFilter::Insert(const REccPoint &vec_a)
    {

        u8 *buffer = new u8[vec_a.sizeBytes()];
        vec_a.toBytes(buffer);
        // memcpy(buffer, vec_a.data(), vec_a.sizeBytes());
        PlainInsert(buffer, vec_a.sizeBytes());
    }
    void BloomFilter::Insert(const std::vector<REccPoint> &vec_a)
    {
        for (u64 i = 0; i < vec_a.size(); i++)
        {
            Insert(vec_a[i]);
        }
    }
    template <typename InputIterator>
    void BloomFilter::Insert(const InputIterator begin, const InputIterator end)
    {
        InputIterator itr = begin;
        while (end != itr)
        {
            Insert(*(itr++));
        }
    }
    template <class T, class Allocator, template <class, class> class Container>
    void BloomFilter ::Insert(const Container<T, Allocator> &container)
    {
#pragma omp parallel for num_threads(6)
        for (auto i = 0; i < container.size(); i++)
        {
            Insert(container[i]);
        }
    }
    bool BloomFilter::Contain(const REccPoint &a) const
    {
        u8 *buffer = new u8[a.sizeBytes()];
        a.toBytes(buffer);
        return PlainContain(buffer, a.sizeBytes());
    }
    std::vector<u8> BloomFilter::Contain(const std::vector<REccPoint> &vec_p)
    {
        size_t LEN = vec_p.size();
        std::vector<u8> vec_indication_bit(LEN);
        for (u64 i = 0; i < vec_p.size(); i++)
        {
            u8 *buffer = new u8[vec_p[i].sizeBytes()];
            vec_p[i].toBytes(buffer);
            vec_indication_bit[i] = (int)PlainContain(buffer, vec_p[i].sizeBytes());
        }
        return vec_indication_bit;
    }

    template <class T, class Allocator, template <class, class> class Container>
    std::vector<u8> BloomFilter::Contain(const Container<T, Allocator> &container)
    {
        size_t LEN = container.size();
        std::vector<u8> vec_indication_bit(LEN);
#pragma omp parallel for num_threads(6)
        for (auto i = 0; i < container.size(); i++)
        {
            if (Contain(container[i]) == true)
                vec_indication_bit[i] = 1;
            else
                vec_indication_bit[i] = 0;
        }
        return vec_indication_bit;
    }

    std::vector<u8> BloomFilter::Contain(const std::vector<std::vector<u8>> &vec_A)
    {
        size_t LEN = vec_A.size();
        std::vector<u8> vec_indication_bit(LEN);

#pragma omp parallel for num_threads(6)
        for (auto i = 0; i < vec_A.size(); i++)
        {
            // to buffer
            unsigned char buffer[vec_A[i].size()];
            memcpy(buffer, vec_A[i].data(), vec_A[i].size());
            if (PlainContain(buffer, vec_A[i].size()) == true)
                vec_indication_bit[i] = 1;
            else
                vec_indication_bit[i] = 0;
        }
        return vec_indication_bit;
    }

    // template成员函数的具体实现可以直接放在头文件中，不需要在cpp文件中单独实现

    void BloomFilter::Clear()
    {
        std::fill(bit_table.begin(), bit_table.end(), static_cast<u8>(0x00));
        inserted_element_num = 0;
    }

    // bool BloomFilter::WriteObject(char *buffer)
    // {
    //     // 成员函数实现
    //     // ...
    // }

    // bool BloomFilter::ReadObject(char *buffer)
    // {
    //     // 成员函数实现
    //     // ...
    // }

    void BloomFilter::PrintInfo() const
    {
        PrintLine('-');
        std::cout << "BloomFilter Status:" << std::endl;
        std::cout << "inserted element num = " << inserted_element_num << std::endl;
        std::cout << "hashtable size = " << (bit_table.size() >> 10) << " KB" << std::endl;
        std::cout << "bits per element = " << double(bit_table.size()) * 8 / inserted_element_num << std::endl;
        PrintLine('-');
    }

} // namespace volePSI
