//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

/* libTriton */
#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>

#include "utils.hpp"


namespace tracer {
  namespace unicorn {

    triton::__uint getBaseAddress(triton::__uint address) {
      // fprintf(stderr, "[tracer:Warn] tracer::unicorn::getBaseAddress is not implemented\n");
      return UC_getImageBaseAddress(address);
    }


    std::string getImageName(triton::__uint address) {
      // fprintf(stderr, "[tracer:Warn] tracer::unicorn::getImageName is not implemented\n");
      return UC_getImageName(address);
    }


    triton::__uint getInsOffset(triton::__uint address) {
      triton::__uint base = tracer::unicorn::getBaseAddress(address);
      if (base == 0)
        return 0;
      return address - base;
    }


    std::string getRoutineName(triton::__uint address) {
      // RTN rtn;
      // // PIN_LockClient();
      // rtn = RTN_FindByAddress(address);
      // // PIN_UnlockClient();
      // if (RTN_Valid(rtn)) {
      //   return RTN_Name(rtn);
      // }
      fprintf(stderr, "[tracer:Warn] traver::unicorn::getRoutineName is not implemented\n");
      return "";
    }

  };
};

