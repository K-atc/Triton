//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#include <cstring>
#include <stdexcept>

/* libTriton */
#include <triton/cpuSize.hpp>
#include <triton/coreUtils.hpp>
#include <triton/x86Specifications.hpp>
#include <triton/vexSpecifications.hpp>
#include <triton/api.hpp> // to get current architecture

#include "bindings.hpp"
#include "context.hpp"


namespace tracer {
  namespace unicorn {
    namespace context {

      CONTEXT* lastContext    = nullptr;
      bool     mustBeExecuted = false;


      triton::uint512 getCurrentRegisterValue(const triton::arch::Register& reg) {
        triton::uint8 buffer[DQQWORD_SIZE] = {0};
        triton::uint512 value = 0;
        auto currentArch = triton::api.getArchitecture();
        triton::arch::Register syncReg;

        #if defined(__x86_64__) || defined(_M_X64)
        if (currentArch == triton::arch::ARCH_X86_64) {
          switch (reg.getParent().getId()) {
            case triton::arch::x86::ID_REG_RAX:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RAX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_RBX:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RBX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_RCX:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RCX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_RDX:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RDX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_RDI:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RDI,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_RSI:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RSI,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_RBP:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RBP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_RSP:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RSP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_RIP:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RIP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_EFLAGS:  UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EFLAGS, reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_R8:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R8,     reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_R9:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R9,     reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_R10:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R10,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_R11:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R11,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_R12:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R12,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_R13:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R13,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_R14:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R14,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_R15:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R15,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_MM0:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM1:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM2:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM3:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM4:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM5:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM6:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM7:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_XMM0:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM0,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM1:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM1,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM2:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM2,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM3:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM3,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM4:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM4,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM5:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM5,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM6:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM6,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM7:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM7,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM8:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM8,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM9:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM9,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM10:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM10,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM11:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM11,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM12:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM12,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM13:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM13,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM14:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM14,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM15:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM15,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM0:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM0,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM1:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM1,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM2:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM2,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM3:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM3,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM4:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM4,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM5:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM5,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM6:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM6,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM7:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM7,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM8:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM8,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM9:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM9,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM10:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM10,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM11:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM11,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM12:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM12,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM13:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM13,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM14:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM14,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM15:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM15,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_ZMM0:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM1:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM2:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM3:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM4:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM5:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM6:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM7:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM8:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM9:    return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM10:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM11:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM12:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM13:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM14:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM15:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM16:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM17:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM18:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM19:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM20:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM21:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM22:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM23:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM24:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM25:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM26:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM27:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM28:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM29:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM30:   return 0; /* Pin doesn't support AVX-512 */
            case triton::arch::x86::ID_REG_ZMM31:   return 0; /* Pin doesn't support AVX-512 */
            // case triton::arch::x86::ID_REG_MXCSR:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_MXCSR, reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_MXCSR:   return 0; /* Unicorn does not support */
            case triton::arch::x86::ID_REG_CR0:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR1:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR2:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR3:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR4:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR5:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR6:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR7:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR8:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR9:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR10:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR11:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR12:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR13:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR14:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR15:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_CS,       reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_DS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_DS,       reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_ES:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ES,       reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_FS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_FS,           reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_GS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_GS,           reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_SS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_SS,           reinterpret_cast<triton::uint8*>(buffer)); break;
            default:
              if (reg.getId() >= triton::arch::x86::ID_REG_AF && reg.getId() <= triton::arch::x86::ID_REG_ZF)
                UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EFLAGS, reinterpret_cast<triton::uint8*>(buffer)); // XXX: UC_X86_REG_RFLAGS is not implemented
              // else if (reg.getId() >= triton::arch::x86::ID_REG_IE && reg.getId() <= triton::arch::x86::ID_REG_FZ)
              //   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_MXCSR, reinterpret_cast<triton::uint8*>(buffer));
              else
                throw std::runtime_error("tracer::unicorn::context::getCurrentRegisterValue(): Invalid register.");
              break;
          }

          /* Sync with the libTriton */
          // triton::arch::Register syncReg;
          if (reg.getId() >= triton::arch::x86::ID_REG_AF && reg.getId() <= triton::arch::x86::ID_REG_ZF)
            syncReg = TRITON_X86_REG_EFLAGS;
          // else if (reg.getId() >= triton::arch::x86::ID_REG_IE && reg.getId() <= triton::arch::x86::ID_REG_FZ)
          //   syncReg = TRITON_X86_REG_MXCSR;
          else
            syncReg = reg.getParent();
        }
        #endif

        #if defined(__i386) || defined(_M_IX86)
        if (currentArch == triton::arch::ARCH_X86) {
          switch (reg.getParent().getId()) {
            case triton::arch::x86::ID_REG_EAX:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EAX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_EBX:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EBX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_ECX:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ECX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_EDX:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EDX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_EDI:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EDI,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_ESI:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ESI,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_EBP:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EBP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_ESP:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ESP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_EIP:     UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EIP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_EFLAGS:  UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EFLAGS, reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_MM0:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM1:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM2:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM3:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM4:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM5:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM6:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_MM7:     return 0; /* Pin doesn't support MMX */
            case triton::arch::x86::ID_REG_XMM0:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM0,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM1:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM1,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM2:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM2,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM3:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM3,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM4:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM4,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM5:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM5,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM6:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM6,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_XMM7:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM7,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM0:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM0,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM1:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM1,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM2:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM2,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM3:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM3,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM4:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM4,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM5:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM5,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM6:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM6,   reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_YMM7:    UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM7,   reinterpret_cast<triton::uint8*>(buffer)); break;
            // case triton::arch::x86::ID_REG_MXCSR:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_MXCSR,  reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_MXCSR:   return 0; /* Unicorn does not support */
            case triton::arch::x86::ID_REG_CR0:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR1:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR2:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR3:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR4:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR5:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR6:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR7:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR8:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR9:     return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR10:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR11:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR12:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR13:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR14:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CR15:    return 0; /* Don't care about this register in ring3 */
            case triton::arch::x86::ID_REG_CS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_CS,       reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_DS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_DS,       reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_ES:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ES,       reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_FS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_FS,       reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_GS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_GS,       reinterpret_cast<triton::uint8*>(buffer)); break;
            case triton::arch::x86::ID_REG_SS:      UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_SS,       reinterpret_cast<triton::uint8*>(buffer)); break;
            default:
              if (reg.getId() >= triton::arch::x86::ID_REG_AF && reg.getId() <= triton::arch::x86::ID_REG_ZF)
                UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EFLAGS, reinterpret_cast<triton::uint8*>(buffer));
              // else if (reg.getId() >= triton::arch::x86::ID_REG_IE && reg.getId() <= triton::arch::x86::ID_REG_FZ)
              //   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_MXCSR, reinterpret_cast<triton::uint8*>(buffer));
              else
                throw std::runtime_error("tracer::unicorn::context::getCurrentRegisterValue(): Invalid register.");
              break;
          }

          /* Sync with the libTriton */
          if (reg.getId() >= triton::arch::x86::ID_REG_AF && reg.getId() <= triton::arch::x86::ID_REG_ZF)
            syncReg = TRITON_X86_REG_EFLAGS;
          // else if (reg.getId() >= triton::arch::x86::ID_REG_IE && reg.getId() <= triton::arch::x86::ID_REG_FZ)
          //   syncReg = TRITON_X86_REG_MXCSR;
          else
            syncReg = reg.getParent();
        }
        #endif

        if (currentArch == triton::arch::ARCH_VEX_X86_64) {
          tracer::unicorn::log::info("tracer::unicorn::context::getCurrentRegisterValue(): regId = 0x%x, parentId = 0x%x (%d)", reg.getId(), reg.getParent().getId(), reg.getParent().getId());

          // Do not fetch value from unicorn. Fetch from Triton
          if (reg.getParent().getId() >= triton::arch::vex::ID_REG_TMP)
            throw std::runtime_error("tracer::unicorn::context::getCurrentRegisterValue(): Do not pass tmp register.");

          switch (reg.getParent().getId()) { //getID() is offset of Vex register
            case  16:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RAX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  24:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RCX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  32:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RDX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  40:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RBX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  48:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RSP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  56:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RBP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  64:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RSI,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  72:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RDI,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  80:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R8,     reinterpret_cast<triton::uint8*>(buffer)); break;
            case  88:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R9,     reinterpret_cast<triton::uint8*>(buffer)); break;
            case  96:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R10,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 104:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R11,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 112:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R12,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 120:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R13,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 128:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R14,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 136:   UC_GetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R15,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 144:   triton::logger::warn("tracer::unicorn::context::getCurrentRegisterValue(): ommiting cc_op"); return 0; // cc_op; not care
            case 152:   triton::logger::warn("tracer::unicorn::context::getCurrentRegisterValue(): ommiting cc_dep1"); return 0; // cc_dep1: not care
            case 160:   triton::logger::warn("tracer::unicorn::context::getCurrentRegisterValue(): ommiting cc_dep2"); return 0; // cc_dep2: not care
            case 168:   triton::logger::warn("tracer::unicorn::context::getCurrentRegisterValue(): ommiting cc_ndep"); return 0; // cc_ndep: not care
          default:
            throw std::runtime_error("tracer::unicorn::context::getCurrentRegisterValue(): Invalid register.");
          }
          syncReg = reg.getParent();
        }

        value = triton::utils::fromBufferToUint<triton::uint512>(buffer);
        syncReg.setConcreteValue(value);
        triton::api.setConcreteRegisterValue(syncReg);

        /* Returns the good casted value */
        return triton::api.getConcreteRegisterValue(reg, false);
      }


      triton::uint512 getCurrentMemoryValue(const triton::arch::MemoryAccess& mem) {
        return tracer::unicorn::context::getCurrentMemoryValue(mem.getAddress(), mem.getSize());
      }


      triton::uint512 getCurrentMemoryValue(triton::__uint addr) {
        triton::uint512 value = 0;
        if (UC_CheckReadAccess(reinterpret_cast<triton::uint8*>(addr)) == false)
          throw std::runtime_error("tracer::unicorn::context::getCurrentMemoryValue(): Page not readable.");
        value = *(reinterpret_cast<triton::uint8*>(addr));
        return value;
      }


      triton::uint512 getCurrentMemoryValue(triton::__uint addr, triton::uint32 size) {
        triton::uint512 value = 0;

        if (UC_CheckReadAccess(reinterpret_cast<triton::uint8*>(addr)) == false || UC_CheckReadAccess(reinterpret_cast<triton::uint8*>(addr+size-1)) == false)
          throw std::runtime_error("tracer::unicorn::context::getCurrentMemoryValue(): Page not readable.");

        switch(size) {
          case BYTE_SIZE:    value = *(reinterpret_cast<triton::uint8*>(addr));  break;
          case WORD_SIZE:    value = *(reinterpret_cast<triton::uint16*>(addr)); break;
          case DWORD_SIZE:   value = *(reinterpret_cast<triton::uint32*>(addr)); break;
          case QWORD_SIZE:   value = *(reinterpret_cast<triton::uint64*>(addr)); break;
          case DQWORD_SIZE:  value = triton::utils::fromBufferToUint<triton::uint128>(reinterpret_cast<triton::uint8*>(addr)); break;
          case QQWORD_SIZE:  value = triton::utils::fromBufferToUint<triton::uint256>(reinterpret_cast<triton::uint8*>(addr)); break;
          case DQQWORD_SIZE: value = triton::utils::fromBufferToUint<triton::uint512>(reinterpret_cast<triton::uint8*>(addr)); break;
        }

        return value;
      }


      void setCurrentRegisterValue(triton::arch::Register& reg) {
        tracer::unicorn::context::setCurrentRegisterValue(reg, reg.getConcreteValue());
      }


      void setCurrentRegisterValue(triton::arch::Register& reg, triton::uint512 value) {
        std::ostringstream str;
        str << "setCurrentRegisterValue(reg = \'" << reg << "\', value = 0x" << std::hex << value << ")" << std::dec;
        tracer::unicorn::log::info(str.str().c_str());

        triton::uint8 buffer[DQQWORD_SIZE] = {0};

        auto currentArch = triton::api.getArchitecture();

        if (currentArch == triton::arch::ARCH_X86_64) {

          if (reg.getId() != reg.getParent().getId() || triton::api.isFlag(reg))
            throw std::runtime_error("tracer::unicorn::context::setCurrentRegisterValue(): You cannot set a Pin register value on a sub-register or a flag.");

          triton::utils::fromUintToBuffer(value, buffer);

          #if defined(__x86_64__) || defined(_M_X64)
            switch (reg.getId()) {
              case triton::arch::x86::ID_REG_RAX:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RAX,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_RBX:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RBX,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_RCX:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RCX,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_RDX:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RDX,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_RDI:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RDI,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_RSI:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RSI,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_RBP:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RBP,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_RSP:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RSP,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_RIP:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RIP,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_EFLAGS:  UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EFLAGS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_R8:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R8,     reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_R9:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R9,     reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_R10:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R10,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_R11:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R11,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_R12:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R12,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_R13:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R13,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_R14:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R14,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_R15:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R15,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM0:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM0,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM1:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM1,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM2:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM2,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM3:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM3,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM4:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM4,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM5:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM5,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM6:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM6,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM7:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM7,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM8:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM8,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM9:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM9,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM10:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM10,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM11:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM11,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM12:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM12,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM13:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM13,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM14:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM14,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM15:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM15,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM0:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM0,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM1:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM1,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM2:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM2,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM3:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM3,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM4:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM4,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM5:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM5,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM6:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM6,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM7:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM7,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM8:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM8,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM9:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM9,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM10:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM10,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM11:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM11,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM12:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM12,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM13:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM13,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM14:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM14,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM15:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM15,  reinterpret_cast<triton::uint8*>(buffer)); break;
              // case triton::arch::x86::ID_REG_MXCSR:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_MXCSR,  reinterpret_cast<triton::uint8*>(buffer)); break;
              /* Unicorn does not support MXCSR */
              case triton::arch::x86::ID_REG_CS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_CS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_DS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_DS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_ES:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ES, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_FS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_FS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_GS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_GS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_SS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_SS, reinterpret_cast<triton::uint8*>(buffer)); break;
              default:
                throw std::runtime_error("tracer::unicorn::context::setCurrentRegisterValue(): Invalid register.");
            }
          #endif
        }

        if (currentArch == triton::arch::ARCH_X86) {
          if (reg.getId() != reg.getParent().getId() || triton::api.isFlag(reg))
            throw std::runtime_error("tracer::unicorn::context::setCurrentRegisterValue(): You cannot set a Pin register value on a sub-register or a flag.");

          triton::utils::fromUintToBuffer(value, buffer);

          #if defined(__i386) || defined(_M_IX86)
            switch (reg.getId()) {
              case triton::arch::x86::ID_REG_EAX:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EAX,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_EBX:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EBX,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_ECX:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ECX,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_EDX:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EDX,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_EDI:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EDI,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_ESI:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ESI,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_EBP:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EBP,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_ESP:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ESP,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_EIP:     UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EIP,    reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_EFLAGS:  UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_EFLAGS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM0:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM0,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM1:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM1,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM2:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM2,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM3:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM3,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM4:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM4,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM5:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM5,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM6:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM6,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_XMM7:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_XMM7,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM0:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM0,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM1:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM1,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM2:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM2,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM3:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM3,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM4:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM4,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM5:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM5,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM6:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM6,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_YMM7:    UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_YMM7,   reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_MXCSR:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_MXCSR,  reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_CS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_CS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_DS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_DS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_ES:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_ES, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_FS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_FS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_GS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_GS, reinterpret_cast<triton::uint8*>(buffer)); break;
              case triton::arch::x86::ID_REG_SS:      UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_SS, reinterpret_cast<triton::uint8*>(buffer)); break;
              default:
                throw std::runtime_error("tracer::unicorn::context::setCurrentRegisterValue(): Invalid register.");
            }
          #endif
        }

        if (currentArch == triton::arch::ARCH_VEX_X86_64) {
          tracer::unicorn::log::info("tracer::unicorn::context::setCurrentRegisterValue(): regId = 0x%x, parentId = 0x%x (%d)", reg.getId(), reg.getParent().getId(), reg.getParent().getId());

          // Do not fetch value from unicorn. Fetch from Triton
          if (reg.getParent().getId() >= triton::arch::vex::ID_REG_TMP)
            throw std::runtime_error("tracer::unicorn::context::setCurrentRegisterValue(): Do not pass tmp register.");

          triton::utils::fromUintToBuffer(value, buffer);

          switch (reg.getParent().getId()) { // getID() is offset of Vex register
            case  16:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RAX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  24:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RCX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  32:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RDX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  40:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RBX,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  48:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RSP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  56:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RBP,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  64:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RSI,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  72:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_RDI,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case  80:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R8,     reinterpret_cast<triton::uint8*>(buffer)); break;
            case  88:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R9,     reinterpret_cast<triton::uint8*>(buffer)); break;
            case  96:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R10,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 104:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R11,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 112:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R12,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 120:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R13,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 128:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R14,    reinterpret_cast<triton::uint8*>(buffer)); break;
            case 136:   UC_SetContextRegval(tracer::unicorn::context::lastContext, UC_X86_REG_R15,    reinterpret_cast<triton::uint8*>(buffer)); break;
          default:
            throw std::runtime_error("tracer::unicorn::context::getCurrentRegisterValue(): Invalid register.");
          }
        }

        /* Sync with the libTriton */
        triton::arch::Register syncReg(reg);
        syncReg.setConcreteValue(value);
        triton::api.setConcreteRegisterValue(syncReg);

        /* We must concretize the register because the last symbolic value is now false */
        triton::api.concretizeRegister(reg);

        /* Define that the context must be executed as soon as possible */
        tracer::unicorn::context::mustBeExecuted = true;
      }


      void setCurrentMemoryValue(triton::arch::MemoryAccess& mem) {
        tracer::unicorn::context::setCurrentMemoryValue(mem, mem.getConcreteValue());
      }


      void setCurrentMemoryValue(triton::arch::MemoryAccess& mem, triton::uint512 value) {
        triton::__uint addr = mem.getAddress();
        triton::uint32 size = mem.getSize();

        /* Sync with the libTriton */
        mem.setConcreteValue(value);
        triton::api.setConcreteMemoryValue(mem);

        /* We must concretize the memory because the last symbolic value is now false */
        triton::api.concretizeMemory(mem);

        /* Inject memory value */
        for (triton::uint32 i = 0; i < size; i++) {
          if (UC_CheckWriteAccess(reinterpret_cast<triton::uint8*>((addr+i))) == false)
            throw std::runtime_error("tracer::unicorn::context::setCurrentMemoryValue(): Page not writable.");
          tracer::unicorn::log::debug("setCurrentMemoryValue@mem(addr=0x%x, value=0x%x)", addr + i, value);
          UC_WriteCurrentMem(addr + i, &value, 1);
          value >>= 8;
        }
      }


      void setCurrentMemoryValue(triton::__uint addr, triton::uint8 value) {
        if (UC_CheckWriteAccess(reinterpret_cast<triton::uint8*>(addr)) == false)
          throw std::runtime_error("tracer::unicorn::context::setCurrentMemoryValue(): Page not writable.");

        /* Sync with the libTriton */
        triton::api.setConcreteMemoryValue(addr, value);

        /* We must concretize the memory because the last symbolic value is now false */
        triton::api.concretizeMemory(addr);

        /* Inject memory value */
        tracer::unicorn::log::debug("setCurrentMemoryValue@addr(addr=0x%x, value=0x%x)", addr, value);
        UC_WriteCurrentMem(addr, &value, 1);
      }


      void executeContext(void) {
        if (tracer::unicorn::context::mustBeExecuted == true) {
          // PIN_UnlockClient();
          UC_ExecuteAt(tracer::unicorn::context::lastContext);
        }
      }


      void needConcreteRegisterValue(triton::arch::Register& reg) {
        triton::uint512 value = 0;
        auto parentRegid = reg.getParent().getId();

        if (triton::api.getArchitecture() == triton::arch::ARCH_VEX_X86_64) {
            if (parentRegid == triton::arch::vex::ID_REG_INVALID || parentRegid >= triton::arch::vex::ID_REG_TMP) {
              tracer::unicorn::log::info("needConcreteRegisterValue(): immediate return");
              // value = triton::api.getConcreteRegisterValue(reg); // DANGER: causes infinite needConcreteRegisterValue() call
              return; // There's nothing to do. Do immediate return!
            }
        }

        tracer::unicorn::log::info("needConcreteRegisterValue() -> tracer::unicorn::context::getCurrentRegisterValue(reg)");
        std::cout << "\treg = " << reg << std::endl;
        value = tracer::unicorn::context::getCurrentRegisterValue(reg);
        triton::arch::Register tmp(reg.getId(), value);
        triton::api.setConcreteRegisterValue(tmp);
      }


      void synchronizeContext(void) {
        tracer::unicorn::log::debug("synchronizeContext()");
        if (triton::api.isSymbolicEngineEnabled() == false)
          return;

        for (triton::arch::Register* reg : triton::api.getParentRegisters()) {
          if (reg->getId() > triton::arch::x86::ID_REG_EFLAGS)
            continue;

          if (triton::api.getSymbolicRegisterId(*reg) == triton::engines::symbolic::UNSET)
            continue;

          triton::uint512 cv = tracer::unicorn::context::getCurrentRegisterValue(*reg);
          triton::uint512 sv = triton::api.getSymbolicRegisterValue(*reg);

          if (sv != cv) {
            triton::api.concretizeRegister(*reg);
            triton::api.setConcreteRegisterValue(triton::arch::Register(reg->getId(), cv));
          }
        }
      }

    };
  };
};
