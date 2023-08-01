// MurmurHash3.h
#pragma once

#include "volePSI/Defines.h"
#include "cryptoTools/Crypto/RCurve.h"

namespace volePSI
{
    const u32 fixed_salt32 = 0xAAAA; // used for murmurhash

    void MurmurHash3_x86_32(const void *key, int len, u32 seed, void *out);
    void MurmurHash3_x86_128(const void *key, int len, u32 seed, void *out);
    void MurmurHash3_x64_128(const void *key, int len, u32 seed, void *out);
    u32 MurmurHash3(u32 salt, const unsigned char *input, size_t LEN);
    u32 LiteMurmurHash(u32 salt, const void *input, size_t LEN);
    u32 MurmurHash3(const unsigned char *input, size_t LEN);
}
