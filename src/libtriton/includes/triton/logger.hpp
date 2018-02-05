//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/
#ifndef TRITON_LOGGER_H
#define TRITON_LOGGER_H

#include <stdio.h>
#include <cstdlib>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

namespace triton{
  namespace logger{
    const char log_prefix[] = "[triton:%s] ";
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
      fprintf(stderr, KRED);
      Print(format, "Error", args ...);
      fprintf(stderr, KNRM);
      std::exit(1);
    }
  }
}


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
        fprintf(stderr, KRED);
        Print(format, "Error", args ...);
        fprintf(stderr, KNRM);
        std::exit(1);
      }
    }
  }
}

#endif