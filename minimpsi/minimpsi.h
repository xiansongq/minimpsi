/**
* multiple party private set intersection for small sets
* @description: minimpsi.h
* @author: XianSong Qian
* @date: 2024/06/08
*/
#pragma once

#include "../dhoprf/Dhoprf.h"
#include "volePSI/Defines.h"

namespace volePSI{

struct minimpsiParams {
  u64 setSize;
  u64 stasecParam;
  u64 nParties;
  bool malicious;
  u64 myIdx;
  u64 numThreads = 1;


  void init(u64 setSize, u64 stasecParam, u64 nParties,
            bool malicious, u64 myIdx, u64 numThreads) {
    this->setSize = setSize;
    this->stasecParam = stasecParam;
    this->nParties = nParties;
    this->malicious = malicious;
    this->myIdx = myIdx;
    this->numThreads = numThreads;
  }
};

class miniMpsiSender : public minimpsiParams, public TimerAdapter {
 public:
  void send(std::vector<PRNG> &mseed, PRNG &prng, std::vector<block> inputs, Socket &chl);

};
class miniMpsiReceiver : public minimpsiParams, public TimerAdapter {
 public:
  void receive(std::vector<PRNG> &mseed, PRNG &prng, std::vector<block> inputs,
               std::vector<block> &outputs, std::vector<block> &sOprfVal, Socket &chl);

};

}