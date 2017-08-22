//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef UNICORN_SNAPSHOT_H
#define UNICORN_SNAPSHOT_H

#include <map>
#include <set>

#include "unicorn_wrapper.h"

/* libTriton */
#include <triton/api.hpp>
#include <triton/ast.hpp>
#include <triton/symbolicEngine.hpp>
#include <triton/taintEngine.hpp>
#include <triton/x8664Cpu.hpp>
#include <triton/x86Cpu.hpp>


//! The Tracer namespace
namespace tracer {
/*!
 *  \addtogroup tracer
 *  @{
 */

  //! The Unicorn namespace
  namespace unicorn {
  /*!
   *  \ingroup tracer
   *  \addtogroup unicorn
   *  @{
   */

    //! \class Snapshot
    //! \brief the snapshot class.
    class Snapshot {

      private:
        //! I/O memory monitoring for snapshot.
        std::map<triton::__uint, char> memory;

        //! Status of the snapshot engine.
        bool locked;

        //! Flag which defines if we must restore the snapshot.
        bool mustBeRestore;

        //! AST node state.
        std::set<triton::ast::AbstractNode*> nodesList;

        //! Variables node state.
        std::map<std::string, triton::ast::AbstractNode*> variablesMap;

        //! Snapshot of the symbolic engine.
        triton::engines::symbolic::SymbolicEngine* snapshotSymEngine;

        //! Snapshot of the taint engine.
        triton::engines::taint::TaintEngine* snapshotTaintEngine;

        //! Snapshot of triton CPU.
        #if defined(__x86_64__) || defined(_M_X64)
        triton::arch::x86::x8664Cpu* cpu;
        #endif
        #if defined(__i386) || defined(_M_IX86)
        triton::arch::x86::x86Cpu* cpu;
        #endif

        //! Snapshot of Unicorn context.
        struct CONTEXT *ucCtx;


      public:
        //! Constructor.
        Snapshot();

        //! Destructor.
        ~Snapshot();

        //! Returns the Pin context.
        uc_context *getCtx(void);

        //! Returns true if the snapshot engine is disabled.
        bool isLocked(void);

        //! Returns true if we must restore the context.
        bool mustBeRestored(void);

        //! Adds a memory modifiction.
        void addModification(triton::__uint address, char byte);

        //! Disables the snapshot engine.
        void disableSnapshot(void);

        //! Resets the snapshot engine.
        void resetEngine(void);

        //! Restores a snapshot.
        void restoreSnapshot(uc_context *ctx);

        //! Sets the restore flag.
        void setRestore(bool flag);

        //! Takes a snapshot.
        void takeSnapshot(uc_context *ctx);
    };

  /*! @} End of unicorn namespace */
  };
/*! @} End of tracer namespace */
};

#endif /* UNICORN_SNAPSHOT_H */

