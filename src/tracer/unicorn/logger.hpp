//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/
#ifndef TRITON_UC_LOGGER_H
#define TRITON_UC_LOGGER_H

#include <stdio.h>
#include <cstdlib>

namespace tracer {
  namespace unicorn {
    namespace log {
      const char log_prefix[] = "[tracer:%s] ";
      const char log_suffix[] = "\n";
      
      template <typename ... Args>
      void Print(const char *format, const char* log_type, Args const & ... args) {
        fprintf(stderr, log_prefix, log_type);
        fprintf(stderr, format, args ...);
        fprintf(stderr, log_suffix);
      }

      template <typename ... Args>
      void debug(const char* format, Args const & ... args)
      {
        Print(format, "Debug", args ...);
      }

      template <typename ... Args>
      void info(const char* format, Args const & ... args)
      {
        Print(format, "Info", args ...);
      }

      template <typename ... Args>
      void warn(const char* format, Args const & ... args)
      {
        Print(format, "Warn", args ...);
      }

      template <typename ... Args>
      void error(const char* format, Args const & ... args)
      {
        Print(format, "Error", args ...);
        std::exit(1);
      }
    }
  }
}

#endif