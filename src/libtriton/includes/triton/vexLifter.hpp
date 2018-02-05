//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_VEXLIFTER_H
#define TRITON_VEXLIFTER_H

namespace triton { 
    namespace intlibs {
        namespace vexlifter {

typedef enum {
    Ist_Invalid,
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
    Iex_Invalid,
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
    Ity_Invalid,
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
    Ico_Invalid,
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
} vex_ir_ico;


typedef enum {
    Ijk_Invalid=0x1A00,
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

            // TODO:
            // typedef enum vex_tag_iop
            typedef std::string vex_tag_iop;

typedef struct vex_expr {
    vex_tag_iex tag = Iex_Invalid;
    int con = 0;
    int tmp = 0;
    int offset = 0;
    int result_size = 0;
} vex_expr;

typedef struct vex_data {
    vex_tag_iex tag = Iex_Invalid;
    vex_ir_ity ty = Ity_Invalid;
    vex_tag_iop op = "Iop_Invalid";
    int con = 0;
    int tmp = 0;
    int offset = 0;
    vex_expr args[8];
    int nargs = 0;
    int result_size = 0;
} vex_data;

typedef struct vex_insn {
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
    int dst;
    std::string disasm;
} vex_insn;




            typedef std::vector<struct vex_insn> vex_insns;
            typedef std::map<unsigned int, vex_insns> vex_insns_group;

            void print_vex_insns(vex_insns insns);
            bool vex_lift(vex_insns_group *insns_group, unsigned char *insns_bytes, unsigned int start_addr, unsigned int count);

            std::string vex_tag_enum_to_str(vex_tag_iex tag);
        }
    }
}
#endif