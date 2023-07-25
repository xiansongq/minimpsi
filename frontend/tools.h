#pragma once
/* 这里包含一些 基础的工具函数 */

#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/RCurve.h"
#include <iostream>
using namespace osuCrypto;
;
/* Eccpoint to block */
block Eccpoint_to_block(REccPoint point);
/* block to Eccpoint */
REccPoint block_to_Eccpoint(block a);