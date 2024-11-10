#pragma once

#include "spdlog/spdlog.h"
#include "spdlog/cfg/env.h" // support for loading levels from the environment variable
#include "spdlog/fmt/ostr.h" // support for user defined types

class Logger
{
  public:
  Logger()
  {
    spdlog::cfg::load_env_levels();
  }

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)

#define LOG_INFO(...) \
  spdlog::info(__FILE__ ":" STRINGIZE(__LINE__) ": " __VA_ARGS__)
  
#define LOG_ERROR(...) \
  spdlog::error(__FILE__ ":" STRINGIZE(__LINE__) ": " __VA_ARGS__)
};