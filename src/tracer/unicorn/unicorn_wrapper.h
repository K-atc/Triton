#ifndef _UNICORN_WRAPPER_H_
#define _UNICORN_WRAPPER_H_

#include <unicorn/unicorn.h>
#include <keystone/keystone.h>

// for prototype only
#define CODE_ADDRESS 0x8000
#define PIN_ThreadId(x) (1)

#define CONTEXT uc_context
#define REG uc_x86_reg

typedef uint8_t  UINT8;
typedef uint32_t  UINT32;
typedef int32_t  INT32;
typedef void  VOID;
typedef UINT32 THREADID;

typedef uc_x86_insn INSN;

struct op {
  unsigned int    addr      = 0;
  unsigned char   inst[16];
  unsigned int    size      = 0;
};
struct user_data_for_triton
{
  struct op trace[16];
  int trace_count = 0;
};

// extern SYSCALL_STANDARD INS_SyscallStd(INS ins);
// typedef VOID (*SYSCALL_ENTRY_CALLBACK)(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);
// typedef VOID (*SYSCALL_EXIT_CALLBACK)(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);

extern const char* ucPythonScriptFileName;

struct tracer_env {
    int entryPoint = CODE_ADDRESS;
    int emuStartAddr = CODE_ADDRESS;
};

// TODO: Mutex
// TODO: IMG

void UC_InitSymbols(void);
bool UC_Init(int argc, char *argv[]);
void UC_AddFiniFunction(VOID (*fun)(INT32, VOID*), VOID *val);
// void UC_AddSyscallEntryFunction(SYSCALL_ENTRY_CALLBACK fun, VOID *val); // TODO
// void UC_AddSyscallExitFunction(SYSCALL_EXIT_CALLBACK fun, VOID *val); // TODO
// void UC_InterceptSignal(int intno, void *func, void* var); // TODO

// BOOL LEVEL_PINCLIENT::PIN_CheckReadAccess   (   VOID *      addr     )      
// Given an address, this API checks whether the memory page which contains this address has a read access protection.
bool UC_CheckReadAccess(void *addr);
bool UC_CheckWriteAccess(void *addr);

// VOID LEVEL_PINCLIENT::PIN_Detach()
// Pin relinquishes control of the application and the original un-instrumented code is executed.
void UC_Detach();

// VOID LEVEL_PINCLIENT::PIN_StartProgram()
// Starts executing the application, when Pin is in JIT mode, which is the default. Note that PIN_Init() must be called before PIN_StartProgram().
// The PIN_StartProgram() function never returns. It also unwinds the tool's stack, so any local (stack based) variables are lost.
void UC_StartProgram();

// VOID LEVEL_PINCLIENT::PIN_GetContextRegval(const CONTEXT *ctxt, REG reg, UINT8 *val)
// Get the value of the requested register from the context. This function is applicable for all context registers (integer, fp etc).
void UC_GetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val);
void UC_SetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val);

// VOID LEVEL_PINCLIENT::PIN_ExecuteAt(const CONTEXT *ctxt)
// A tool can call this API to abandon the current analysis function and resume execution of the calling thread at a new application register state. Note that this API does not return back to the caller's analysis function.
// This API can be called from an analysis function or a replacement routine, but not from a callback.
void UC_ExecuteAt(const CONTEXT *ctxt);

// VOID LEVEL_PINCLIENT::PIN_SaveContext(const CONTEXT *ctxtFrom, CONTEXT *ctxtTo)   
// Copy the CONTEXT structure.
// CONTEXT structures supplied by Pin to the instrumentation callbacks are not "byte-copyable". The tool should use this function to copy the context provided by Pin and must not attempt to move it as raw memory bytes.
uc_err UC_SaveContext(CONTEXT *ctxtFrom, CONTEXT *ctxtTo);

uc_err UC_LoadBinary(unsigned char *bin, int begin, int size);
void UC_SetEmuStartAddr(int start);

// uc_err UC_AddCodeHook(uc_hook *hh, void (*callback)(uc_engine*, uint64_t, uint32_t, void*), void *user_data, uint64_t begin, uint64_t end);
uc_err UC_AddCodeHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end);
uc_err UC_AddInsnHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end, INSN insn);

static void _dump_argv(int argc, char *argv[])
{
    fprintf(stderr, "argc = %d\n", argc);
    for (int i = 0; i < argc; i++) {
        fprintf(stderr, "argv[%d] = %s\n", i, argv[i]);
    }
}
#define DUMP_ARGV() _dump_argv(argc, argv)

// orig: sample/shellcode.c
// callback for tracing instruction
#define MIN(a, b) (a < b? a : b)
void print_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

ks_err KS_Encode(const char *code, unsigned char **encode, size_t *size);

#endif