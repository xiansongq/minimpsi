#pragma once
// Copyright 2023 xiansongq.

#include "macoro/task.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

namespace
{
    inline auto eval(macoro::task<>& t0, macoro::task<>& t1)
    {
        auto r = macoro::sync_wait(macoro::when_all_ready(std::move(t0), std::move(t1)));
        std::get<0>(r).result();
        std::get<1>(r).result();
    }

}