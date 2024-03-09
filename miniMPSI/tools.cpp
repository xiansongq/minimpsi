// Copyright 2023 xiansongq.

#include "../miniMPSI/tools.h"

#include <cassert>

u64 checkThreadsNum(u64 numthreads, u64 setSize) {
  return (numthreads <= setSize) ? numthreads : setSize;
}

void PrintLine(char c) {
  int count = 60;
  std::string line = std::string(count, c);  // NOLINT:
  std::cout << line << std::endl;
}

unsigned char *Block_to_Ristretto225(const block &a, const block &b) {
  auto *point = new unsigned char[crypto_core_ristretto255_BYTES];
  memcpy(point, &a, sizeof(block));
  memcpy(point + sizeof(block), &b, sizeof(block));
  return point;
}
