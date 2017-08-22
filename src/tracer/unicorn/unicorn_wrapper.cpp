#include "unicorn_wrapper.h"
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

uc_engine* uc;
uc_hook uh_syscall, uh_interrupt;

csh csh_handle;

struct tracer_env tracer_env;

const char* ucPythonScriptFileName;

// orig: samples/shellcode.c
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
    switch(intno){
        case SIGHUP:
            printf("SIGHUP\n");
            break;
        case SIGINT:
            printf("SIGINT\n");
            break;
        case SIGQUIT:
            printf("SIGQUIT\n");
            break;
        case SIGILL:
            printf("SIGILL\n");
            break;
        case SIGABRT:
            printf("SIGABORT\n");
            break;
        case SIGFPE:
            printf("SIGFPE\n");
            break;
        case SIGKILL:
            printf("SIGKILL\n");
            break;
        case SIGSEGV:
            printf("SIGEGV\n");
            break;
        case SIGPIPE:
            printf("SIGALRM\n");
            break;
        case SIGTERM:
            printf("SIGTERM\n");
            break;
        default:
            fprintf(stderr, "in hook_intr: unhandled interrupt occured\n");
    }
}

void UC_InitSymbols(void)
{
    // TODO: load symbols
    fprintf(stderr, "UC_InitSymbols is not implemented\n");
}

bool UC_Init(int argc, char *argv[])
{
    // if (argc <= 1) {
    //     return false; 
    // }
    if (argc > 1) {
        ucPythonScriptFileName = argv[1];
    }

    uc_err err;
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        fprintf(stderr, "Failed on uc_open with error returned: %u\n", err);
        return false;
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh_handle) != CS_ERR_OK)
        fprintf(stderr, "Failed on cs_open\n");
        return -1;
    return true;
}

void UC_AddFiniFunction(VOID (*fun)(INT32, VOID*), VOID *val)
{
    // TODO
}

// XXX: no good
void UC_AddSyscallEntryFunction(void* func, void* var)
{
    // hook interrupts for syscall
    uc_hook_add(uc, &uh_syscall, UC_HOOK_INSN, func, NULL, 1, 0, UC_X86_INS_SYSCALL);
}

// XXX: no good
void UC_AddSyscallExitFunction(void* func, void* var)
{
    // hook interrupts for syscall
    uc_hook_add(uc, &uh_syscall, UC_HOOK_INSN, func, NULL, 1, 0, UC_X86_INS_SYSCALL);
}

void UC_InterceptSignal(int intno, void *func, void* var)
{
    // XXX: arg intno is dummy
    // hook interrupts for syscall
    uc_hook_add(uc, &uh_interrupt, UC_HOOK_INTR, func, NULL, 1, 0);
}


bool UC_CheckReadAccess(void *addr)
{
    // TODO: implement me!!
    return true;
}

bool UC_CheckWriteAccess(void *addr)
{
    // TODO: implement me!!
    return true;
}

void UC_Detach()
{
    fprintf(stderr, "UC_Detach is not implemented");
}

void UC_StartProgram()
{
    // TODO: start, until 
    fprintf(stderr, "[!] param end of uc_emu_start is not correct\n");
    // uc_emu_start(uc, tracer_env.emuStartAddr, 0x1000, 0, 0); // timeout = 0, count = 0
    uc_emu_start(uc, tracer_env.emuStartAddr, 0x1000, 0, 1); // timeout = 0, count = 0
}

void UC_GetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val)
{
    uc_err err;
    struct uc_context *tmp_ctx;
    err = uc_context_alloc(uc, &ctxt);
    if (err) {
        fprintf(stderr, "Failed on uc_context_alloc() with error returned: %u\n", err);
        return;
    }
    uc_context_save(uc, tmp_ctx);
    uc_context_restore(uc, ctxt);
    uc_reg_read(uc, reg, val);
    uc_context_restore(uc, tmp_ctx);
}

void UC_SetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val)
{
    uc_err err;
    struct uc_context *tmp_ctx;
    err = uc_context_alloc(uc, &ctxt);
    if (err) {
        fprintf(stderr, "Failed on uc_context_alloc() with error returned: %u\n", err);
        return;
    }
    uc_context_save(uc, tmp_ctx);
    uc_context_restore(uc, ctxt);
    uc_reg_write(uc, reg, val);
    uc_context_save(uc, ctxt);
    uc_context_restore(uc, tmp_ctx);
}

void UC_ExecuteAt(const CONTEXT *ctxt)
{
    // FIXME:
    fprintf(stderr, "UC_ExecuteAt is not implemented\n");
}

uc_err UC_SaveContext(CONTEXT *ctxtFrom, CONTEXT *ctxtTo)
{
    uc_err err;
    if (ctxtTo == nullptr) {
        err = uc_context_alloc(uc, &ctxtTo);
        if (err) {
            return err;
        }
    }
    memcpy(ctxtTo, ctxtFrom, sizeof(CONTEXT *));
    return UC_ERR_OK;
}

// for prototype only
uc_err UC_LoadBinary(unsigned char *bin, int begin, int size)
{
    uc_err err;
    // map 2MB memory for this emulation
    err = uc_mem_map(uc, begin, 2 * 1024 * 1024, UC_PROT_ALL);
    if (err) {
      fprintf(stderr, "Failed to map memory, quit!\n");
      return err;
    }

    // load binary
    err = uc_mem_write(uc, begin, bin, size);
    if (err) {
      fprintf(stderr, "Failed to write emulation code to memory, quit!\n");
      return err;
    }
}

void UC_SetEmuStartAddr(int start)
{
    tracer_env.emuStartAddr = start;
}

// uc_err UC_AddCodeHook(uc_hook *hh, void (*callback)(uc_engine*, uint64_t, uint32_t, void*), void *user_data, uint64_t begin, uint64_t end)
uc_err UC_AddCodeHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end)
{
    uc_err err;
    err = uc_hook_add(uc, hh, UC_HOOK_CODE, callback, user_data, begin, end);
    return err;
}

uc_err UC_AddInsnHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end, INSN insn)
{
    uc_err err;
    err = uc_hook_add(uc, hh, UC_HOOK_INSN, callback, user_data, begin, end, insn);
    return err;
}

void print_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    cs_insn *insn;
    size_t count;
    struct user_data_for_triton *user_data_for_triton;
    user_data_for_triton = (struct user_data_for_triton *) user_data;

    int r_eip;
    unsigned char tmp[16];

    printf("Tracing instruction at 0x%" PRIx64 " , instruction size = 0x%x\n", address, size);

    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    printf("*** EIP = %x ***: ", r_eip);

    size = MIN(sizeof(tmp), size);
    if (!uc_mem_read(uc, address, tmp, size)) {
        uint32_t i;
        for (i=0; i<size; i++) {
            printf("%x ", tmp[i]);
        }
        printf("\n");

        int index = user_data_for_triton->trace_count;
        memcpy((void *)user_data_for_triton->trace[index].inst, (void *)tmp, size);
        user_data_for_triton->trace[index].addr = r_eip;
        user_data_for_triton->trace[index].size = size;
        user_data_for_triton->trace_count++;

        // // disassemble instruction
        // count = cs_disasm(csh_handle, tmp, size, r_eip, 0, &insn);
        // printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic, insn[0].op_str);
    }
}

ks_err KS_Encode(const char *code, unsigned char **encode, size_t *size)
{
        ks_engine *ks;
        ks_err err;
        size_t count;
        printf("encode = %p\n", encode);

        err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
        if (err != KS_ERR_OK) {
            printf("ERROR: failed on ks_open(), quit\n");
            return err;
        }
    
        if (ks_asm(ks, code, 0, encode, size, &count) != KS_ERR_OK) {
            printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
               count, ks_errno(ks));
        } else {
            printf("[KS_Encode:Debug] %s = ", code);
            for (size_t i = 0; i < *size; i++) {
                printf("%02x ", (*encode)[i]);
            }
            printf("\n");
            printf("Compiled: %lu bytes, statements: %lu\n", *size, count);
        }
    
        // // NOTE: free encode after usage to avoid leaking memory
        // ks_free(encode);
    
        // close Keystone instance when done
        ks_close(ks);
        return KS_ERR_OK;
}