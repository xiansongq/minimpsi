#pragma once
#include "cryptoTools/Crypto/RCurve.h" // cause we need to insert EC Point to filter
#include "murmurhash3.h"
#include "tools.h"
namespace volePSI
{

    class BloomFilter
    {
    public:
        // 构造函数、析构函数和其他成员函数声明
        BloomFilter();

        BloomFilter(size_t max_element_num, size_t statistical_security_parameter);
        void init(size_t max_element_num, size_t statistical_security_parameter);
        ~BloomFilter();

        size_t ObjectSize();

        void PlainInsert(const void *input, size_t LEN);

        template <typename ElementType>
        void Insert(const ElementType &element);

        void Insert(const std::string &str);

        void Insert(const std::vector<std::vector<u8>> &str);

        void Insert(const REccPoint &vec_a);

        void Insert(const std::vector<REccPoint> &vec_a);

        template <typename InputIterator>
        void Insert(const InputIterator begin, const InputIterator end);

        template <class T, class Allocator, template <class, class> class Container>
        void Insert(const Container<T, Allocator> &container);

        bool PlainContain(const void *input, size_t LEN) const;

        template <typename ElementType>
        bool Contain(const ElementType &element) const;

        bool Contain(const std::string &str) const;

        bool Contain(const REccPoint &a) const;

        std::vector<u8> Contain(const std::vector<REccPoint> &vec_p) ;

        template <class T, class Allocator, template <class, class> class Container>
        std::vector<u8> Contain(const Container<T, Allocator> &container);

        std::vector<u8> Contain(const std::vector<std::vector<u8>> &vec_A);

        void Clear();

        bool WriteObject(char *buffer);

        bool ReadObject(char *buffer);

        void PrintInfo() const;

    private:
        // 私有成员变量和其他私有函数声明
        u32 random_seed;
        u32 hash_num;
        std::vector<u32> vec_salt;
        u32 table_size;
        std::vector<u8> bit_table;
        size_t projected_element_num;
        size_t inserted_element_num;
    };
}
