#ifndef _UNICORN_WRAPPER_H_
#define _UNICORN_WRAPPER_H_

#include <string>
#include <list>

#include <unicorn/unicorn.h>
#include <keystone/keystone.h>

#include "logger.hpp"
using namespace tracer::unicorn;

// for prototype only
#define CODE_ADDRESS 0x80000
#define PIN_ThreadId(x) (1)
#define BIN_FILE_BASE_ADDR 0x100000
#define LOADER_WORKSPACE_ADDR 0x400000

#define CONTEXT uc_context
#define REG uc_x86_reg

typedef uint8_t  UINT8;
typedef uint32_t  UINT32;
typedef int32_t  INT32;
typedef void  VOID;
typedef UINT32 THREADID;
typedef uint64_t ADDR;
typedef uint64_t UINT64;

typedef uc_x86_insn INSN;

struct op {
  ADDR    addr      = 0;
  unsigned char   inst[16];
  ADDR    size      = 0;
};

struct user_data_for_triton
{
  CONTEXT* ctx;
  THREADID threadId = 0; // NOTE: NOT implemented. (multi threading is not supported as of now)
  struct op trace[16];
  int trace_count = 0;
};

/* for loader */
enum uc_file_type {
  UC_FILE_BIN = 0,
  UC_FILE_ELF32,
  UC_FILE_ELF64,
};

struct memory_map {
  std::string name;
  ADDR start;
  ADDR end;
}; 
typedef memory_map IMG;
extern std::list<memory_map> memory_map_list; // need for functions references IMG

enum uc_hook_loader_type {
  UC_HOOK_LOADER_START_LODING = 0,
  UC_HOOK_LOADER_COMPLETE,
  UC_HOOK_LOADER_MAX // indicates number of types
};
#define IMG_Entry(x) (x->start)

/* unicorn include/uc_priv.h */
struct hook {
    int type;            // UC_HOOK_*
    int insn;            // instruction for HOOK_INSN
    int refs;            // reference count to free hook stored in multiple lists
    uint64_t begin, end; // only trigger if PC or memory access is in this address (depends on hook type)
    void *callback;      // a uc_cb_* type
    void *user_data;
};
typedef void (*uc_cb_loader_out_t)(uc_engine *, IMG *);

ADDR UC_getImageBaseAddress(ADDR address);
std::string UC_getImageName(ADDR address);

// extern SYSCALL_STANDARD INS_SyscallStd(INS ins);
// typedef VOID (*SYSCALL_ENTRY_CALLBACK)(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);
// typedef VOID (*SYSCALL_EXIT_CALLBACK)(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);

extern const char* ucPythonScriptFileName;

struct tracer_env {
    int entryPoint = CODE_ADDRESS;
    int emuStartAddr = CODE_ADDRESS;    
    int emuEndAddr = CODE_ADDRESS;    
};

// TODO: Mutex

uc_file_type UC_DetectFileType(const char* file_name);
size_t UC_GetFileSize(const char* file_name);

void UC_InitSymbols(void);
bool UC_Init(int argc, char *argv[]);
void UC_AddFiniFunction(VOID (*fun)(INT32, VOID*), VOID *val);
uc_err UC_AddSyscallEntryFunction(void* func, void* var);
uc_err UC_AddSyscallExitFunction(void* func, void* var);
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
void UC_StopProgram();

uc_err UC_GetCurrentRegVal(REG reg, void *val);
CONTEXT* UC_GetCurrentContext();
// VOID LEVEL_PINCLIENT::PIN_GetContextRegval(const CONTEXT *ctxt, REG reg, UINT8 *val)
// Get the value of the requested register from the context. This function is applicable for all context registers (integer, fp etc).
void UC_GetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val);
void UC_SetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val);

uc_err UC_WriteCurrentMem(ADDR address, void* data, size_t size);

// VOID LEVEL_PINCLIENT::PIN_ExecuteAt(const CONTEXT *ctxt)
// A tool can call this API to abandon the current analysis function and resume execution of the calling thread at a new application register state. Note that this API does not return back to the caller's analysis function.
// This API can be called from an analysis function or a replacement routine, but not from a callback.
void UC_ExecuteAt(CONTEXT *ctxt);

// VOID LEVEL_PINCLIENT::PIN_SaveContext(const CONTEXT *ctxtFrom, CONTEXT *ctxtTo)   
// Copy the CONTEXT structure.
// CONTEXT structures supplied by Pin to the instrumentation callbacks are not "byte-copyable". The tool should use this function to copy the context provided by Pin and must not attempt to move it as raw memory bytes.
uc_err UC_SaveContext(CONTEXT *ctxtFrom, CONTEXT *ctxtTo);

uc_err UC_LoadBinary(unsigned char *bin, int begin, int size);
uc_err UC_LoadBinaryFromBinFile(const char* file_name);
void UC_SetEmuStartAddr(int start);
void UC_SetEmuEndAddr(int address);

// uc_err UC_AddCodeHook(uc_hook *hh, void (*callback)(uc_engine*, uint64_t, uint32_t, void*), void *user_data, uint64_t begin, uint64_t end);
uc_err UC_AddCodeHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end);
uc_err UC_AddInsnHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end, INSN insn);
uc_err UC_AddMemAccessUnmappedHook(uc_hook *hh, void *callback, void *user_data);
uc_err UC_AddLoaderHook(uc_hook *hh, uc_hook_loader_type hook_type, void *callback, void *user_data);

static void _dump_argv(int argc, char *argv[])
{
  log::debug("argc = %d", argc);
  for (int i = 0; i < argc; i++) {
      log::debug("argv[%d] = %s", i, argv[i]);
  }
}
#define DUMP_ARGV() _dump_argv(argc, argv)

static void _non_null_assert(void* v, const char* name)
{
  if (v == nullptr) {
    log::error("variable \'%s\' is null (at line %d in %s)", name, __LINE__, __FILE__);
  }
}
#define NON_NULL_ASSERT(x) _non_null_assert((void *)x, #x)

// orig: sample/shellcode.c
// callback for tracing instruction
#define MIN(a, b) (a < b? a : b)
void print_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

ks_err KS_Encode(const char *code, unsigned char **encode, size_t *size);

#endif