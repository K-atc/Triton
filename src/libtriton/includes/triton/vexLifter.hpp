//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_VEXLIFTER_H
#define TRITON_VEXLIFTER_H

#include <triton/tritonTypes.hpp>
#include <string>
#include <vector>
#include <map>

namespace triton {
    namespace intlibs {
        namespace vexlifter {

#define VEX_IST_BASE 0x10000
#define VEX_IEX_BASE 0x100
#define VEX_IOP_BASE 0x1

typedef enum {
    Ist_Invalid = 0,
    Ist_Jump,
    Ist_AbiHint,
    Ist_CAS,
    Ist_Dirty,
    Ist_Exit,
    Ist_IMark,
    Ist_LLSC,
    Ist_LoadG,
    Ist_MBE,
    Ist_NoOp,
    Ist_Put,
    Ist_PutI,
    Ist_Store,
    Ist_StoreG,
    Ist_WrTmp,
} vex_tag_ist;

typedef enum {
    Iex_Invalid = 0,
    Iex_Binder,
    Iex_Binop,
    Iex_CCall,
    Iex_Const,
    Iex_GSPTR,
    Iex_Get,
    Iex_GetI,
    Iex_ITE,
    Iex_Load,
    Iex_Qop,
    Iex_RdTmp,
    Iex_Triop,
    Iex_Unop,
    Iex_VECRET,
} vex_tag_iex;

typedef enum {
    Ity_Invalid = 0,
    Ity_F32,
    Ity_F64,
    Ity_I1,
    Ity_I16,
    Ity_I32,
    Ity_I64,
    Ity_I8,
    Ity_V128,
    Ity_V256,
} vex_ir_ity;

typedef enum {
    Ico_Invalid = 0,
    Ico_F32,
    Ico_F32i,
    Ico_F64,
    Ico_F64i,
    Ico_U1,
    Ico_U16,
    Ico_U32,
    Ico_U64,
    Ico_U8,
    Ico_V128,
    Ico_V256,
} vex_tag_ico;

typedef enum {
    Iop_Invalid = 0,

    Iop_Add,
    Iop_Sub,
    Iop_Mul,
    Iop_MullS,
    Iop_MullU,
    Iop_DivS,
    Iop_DivU,

    Iop_Mod, // Custom operation that does not exist in libVEX

    Iop_Or,
    Iop_And,
    Iop_Xor,

    Iop_Shr,
    Iop_Shl,

    Iop_Not,

    Iop_CmpEQ,
    Iop_CmpNE,
    Iop_CmpSLT,
    Iop_CmpSLE,
    Iop_CmpULT,
    Iop_CmpULE,
    Iop_CmpSGE,
    Iop_CmpUGE,
    Iop_CmpSGT,
    Iop_CmpUGT,

    Iop_Cast,   // ex. Iop_64to1
    Iop_CastU,  // ex. Iop_32Uto64
    Iop_CastS,
    Iop_CastHI,
    Iop_CastHL,
} vex_abst_iop;

typedef enum {
    Ijk_Invalid,
    Ijk_Boring,         /* not interesting; just goto next */
    Ijk_Call,           /* guest is doing a call */
    Ijk_Ret,            /* guest is doing a return */
    Ijk_ClientReq,      /* do guest client req before continuing */
    Ijk_Yield,          /* client is yielding to thread scheduler */
    Ijk_EmWarn,         /* report emulation warning before continuing */
    Ijk_EmFail,         /* emulation critical (FATAL) error; give up */
    Ijk_NoDecode,       /* current instruction cannot be decoded */
    Ijk_MapFail,        /* Vex-provided address translation failed */
    Ijk_InvalICache,    /* Inval icache for range [CMSTART, +CMLEN) */
    Ijk_FlushDCache,    /* Flush dcache for range [CMSTART, +CMLEN) */
    Ijk_NoRedir,        /* Jump to un-redirected guest addr */
    Ijk_SigILL,         /* current instruction synths SIGILL */
    Ijk_SigTRAP,        /* current instruction synths SIGTRAP */
    Ijk_SigSEGV,        /* current instruction synths SIGSEGV */
    Ijk_SigBUS,         /* current instruction synths SIGBUS */
    Ijk_SigFPE_IntDiv,  /* current instruction synths SIGFPE - IntDiv */
    Ijk_SigFPE_IntOvf,  /* current instruction synths SIGFPE - IntOvf */
    /* Unfortunately, various guest-dependent syscall kinds.  They
    all mean: do a syscall before continuing. */
    Ijk_Sys_syscall,    /* amd64/x86 'syscall', ppc 'sc', arm 'svc #0' */
    Ijk_Sys_int32,      /* amd64/x86 'int $0x20' */
    Ijk_Sys_int128,     /* amd64/x86 'int $0x80' */
    Ijk_Sys_int129,     /* amd64/x86 'int $0x81' */
    Ijk_Sys_int130,     /* amd64/x86 'int $0x82' */
    Ijk_Sys_int145,     /* amd64/x86 'int $0x91' */
    Ijk_Sys_int210,     /* amd64/x86 'int $0xD2' */
    Ijk_Sys_sysenter    /* x86 'sysenter'.  guest_EIP becomes
                            invalid at the point this happens. */
} vex_ir_ijk;

typedef enum {
    Iend_Invalid,
    Iend_LE,
    Iend_BE
} vex_ir_endness;

// TODO:
// typedef enum vex_tag_iop
typedef std::string vex_tag_iop;

typedef struct {
    vex_tag_ico tag = Ico_Invalid;
    unsigned int value = 0;
    unsigned int size = 0;
} vex_const;

typedef struct {
    vex_tag_iex tag = Iex_Invalid;
    vex_ir_ity ty = Ity_Invalid;
    int con = 0;
    int tmp = 0;
    int offset = 0;
    int result_size = 0;
} vex_expr;

typedef struct : vex_expr {
    vex_tag_iop op = "Iop_Invalid";
    vex_expr addr;
    vex_expr args[8];
    int nargs = 0;
    vex_ir_endness endness = Iend_Invalid;
} vex_data;


typedef struct {
    vex_tag_ist tag = Ist_Invalid;
    int offset = 0;
    vex_data data;
    std::string full = "";
    int tmp = 0;
    int addr = 0;
    int len = 0;
    vex_ir_ijk jumpkind;
    vex_expr guard;
    int offsIP;
    vex_const dst;
    std::string disasm;
    vex_ir_endness endness = Iend_Invalid;
    vex_expr addr_expr;
} vex_insn;

            typedef std::vector<vex_insn> vex_insns;
            typedef std::map<triton::uint64, vex_insns> vex_insns_group;


            constexpr triton::uint32 vex_itype(vex_tag_ist const &ist) {
                return ist * VEX_IST_BASE;
            }

            constexpr triton::uint32 vex_itype(vex_tag_ist const &ist, vex_tag_iex const &iex) {
                return vex_itype(ist) + iex * VEX_IEX_BASE;
            }

            constexpr triton::uint32 vex_itype(vex_tag_ist const &ist, vex_tag_iex const &iex, vex_abst_iop const &iop) {
                return vex_itype(ist, iex) + iop * VEX_IOP_BASE;
            }

            std::string vex_repr_itype(triton::uint32 type);

            vex_abst_iop vex_iop(vex_tag_iop tag);

            std::string vex_tag_enum_to_str(vex_tag_ist tag);
            std::string vex_tag_enum_to_str(vex_tag_iex tag);
            std::string vex_tag_enum_to_str(vex_ir_ity tag);
            std::string vex_tag_enum_to_str(vex_ir_ijk tag);
            std::string vex_tag_enum_to_str(vex_ir_endness tag);
            std::string vex_tag_enum_to_str(vex_tag_ico tag);
            std::string vex_tag_enum_to_str(vex_abst_iop tag);

            void print_vex_expr(vex_expr expr, char* prefix);
            void print_vex_insn(vex_insn insn);
            void print_vex_insns(vex_insns insns);

            void vex_lift_init(void);
            void vex_lift_finilize(void);
            bool vex_lift(vex_insns_group *insns_group, unsigned char *insns_bytes, triton::uint64 start_addr, triton::uint64 count);

            std::string vex_tag_enum_to_str(vex_tag_iex tag);
        }
    }
}

#endif