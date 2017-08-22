//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_UTILS_H
#define TRITON_UTILS_H

#include <string>

#include "unicorn_wrapper.h"

#include <triton/tritonTypes.hpp>



//! The Tracer namespace
namespace tracer {
/*!
 *  \addtogroup tracer
 *  @{
 */

  //! The Unicorn engine namespace
  namespace unicorn {
  /*!
   *  \ingroup tracer
   *  \addtogroup unicorn
   *  @{
   */

    //! Returns the base address from a given address.
    triton::__uint getBaseAddress(triton::__uint address);

    //! Returns the instruction offset from a given address.
    triton::__uint getInsOffset(triton::__uint address);

    //! Returns the image name from a given address.
    std::string getImageName(triton::__uint address);

    //! Returns the routine name from a given address.
    std::string getRoutineName(triton::__uint address);

  /*! @} End of unicorn namespace */
  };
/*! @} End of tracer namespace */
};

#endif /* TRITON_UTILS_H */
