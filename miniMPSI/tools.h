#pragma once
// Copyright 2023 xiansongq.

#include <iostream>
#include <random>

#include "cryptoTools/Common/block.h"
#include "sodium.h"
#include "volePSI/Paxos.h"
using namespace osuCrypto;  // NOLINT

/* check threads num and setSize */
u64 checkThreadsNum(u64 numthreads, u64 setSize);

/* output char line */
void PrintLine(char c);

/* 2 block to ristretto225 */
unsigned char *Block_to_Ristretto225(const block &a, const block &b);
