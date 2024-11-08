#pragma once

#include "spdlog/spdlog.h"
#include "spdlog/cfg/env.h"   // support for loading levels from the environment variable
#include "spdlog/fmt/ostr.h"  // support for user defined types


class Logger
{
public:
Logger()
{
    spdlog::cfg::load_env_levels();
}
};