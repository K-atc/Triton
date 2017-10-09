#include "unicorn_wrapper.h"
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

// for file oparation
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <string>
#include <iterator>

#include "logger.hpp"

using namespace tracer::unicorn;

/* for unicorn engine */
uc_engine* uc;
uc_hook uh_syscall, uh_interrupt;

/* for loader */
struct memory_map {
  std::string name;
  ADDR start;
  ADDR end;
}; 
std::list<memory_map> memory_map_list;

/* for capstone engine */
csh csh_handle;

/* for runtime tracer */
struct tracer_env tracer_env;
const char* ucBinFileName;
const char* ucPythonScriptFileName;

static void printBin(unsigned char* bin, size_t size)
{
    for(int i = 0; i < size; i++){
        printf("%02x ", bin[i]);
    }
    puts("\n");
}

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
            log::warn("in hook_intr: unhandled interrupt occured");
    }
}

void register_memory_map(std::string name, unsigned int start, unsigned end)
{
    struct memory_map mm;
    mm.name = name;
    mm.start = start;
    mm.end = end;
    memory_map_list.push_back(mm);
    log::info("%s mapped at 0x%lx - 0x%lx\n", name.c_str(), start, end);
}

ADDR UC_getImageBaseAddress(ADDR address)
{
    for (auto &mm : memory_map_list) {
        if (mm.start <= address && address <= mm.end) {
            // log::info("base address of 0x%lx = 0x%lx", address, mm.start);
            return mm.start;
        }
    }
}

std::string UC_getImageName(ADDR address)
{
    for (auto &mm : memory_map_list) {
        if (mm.start <= address && address <= mm.end) {
            return mm.name;
        }
    }
}

uc_file_type UC_DetectFileType(const char* file_name)
{
    log::warn("UC_DetectFileType is not implemented. returning UC_FILE_BIN");
    return UC_FILE_BIN;
}

// orig: https://techoverflow.net/2013/08/21/how-to-get-filesize-using-stat-in-cc/
size_t UC_GetFileSize(const char* file_name)
{
    struct stat st;
    if(stat(file_name, &st) != 0) {
        return 0;
    }
    return st.st_size; 
}

void UC_InitSymbols(void)
{
    // TODO: load symbols
    log::warn("UC_InitSymbols is not implemented");
}

bool UC_Init(int argc, char *argv[])
{
    if (argc <= 2) {
        return false; 
    }
    if (argc > 2) {
        ucPythonScriptFileName = argv[1];
        ucBinFileName = argv[2];
    }

    uc_err err;
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    
    uc_file_type file_type = UC_DetectFileType(ucBinFileName);
    if (file_type == UC_FILE_BIN) {
        printf("[tracer:Debug] bin file mode\n");
        UC_LoadBinaryFromBinFile(ucBinFileName);
    }

    if (err) {
        log::error("Failed on uc_open with error returned: %u", err);
        // return false;
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh_handle) != CS_ERR_OK) {
        log::error("Failed on cs_open");
        // return false;
    }
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
    log::warn("UC_Detach is not implemented");
}

void UC_StartProgram()
{
    // TODO: start, until 
    log::warn("param end of uc_emu_start is not correct");
    // uc_emu_start(uc, tracer_env.emuStartAddr, 0x1000, 0, 0); // timeout = 0, count = 0
    uc_emu_start(uc, tracer_env.emuStartAddr, 0x10000, 0, 3); // timeout = 0, count = 0
}

void UC_GetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val)
{
    uc_err err;
    struct uc_context *tmp_ctx;
    err = uc_context_alloc(uc, &ctxt);
    if (err) {
        log::error("[tracer:error] Failed on uc_context_alloc() with error returned: %u", err);
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
        log::error("Failed on uc_context_alloc() with error returned: %u", err);
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
    log::warn("UC_ExecuteAt is not implemented");
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

    // allocate memory 
    unsigned int alignment = 2 * 1024 * 1024;
    unsigned int map_size = size;
    if (map_size % alignment) { // check 4 KB alignment
        map_size += alignment - (size % alignment);
        log::info("param size is not 2 MB aligned. New size is 0x%x", map_size);
    }
    log::debug("uc_mem_map(uc=%p, begin=0x%x, size=0x%x, UC_PROT_ALL)", uc, begin, bin, map_size);
    err = uc_mem_map(uc, begin, map_size, UC_PROT_ALL);
    if (err) {
      log::error("Failed to map memory, quit!");
      return err; // never returns?
    }
    register_memory_map("main_bin", begin, begin + map_size - 1);

    // load binary
    log::debug("uc_mem_write(uc=%p, begin=0x%x, bin=%p, size=0x%x)", uc, begin, bin, size);
    err = uc_mem_write(uc, begin, bin, size);
    if (err) {
      log::error("Failed to write emulation code to memory, quit!");
      return err; // never returns?
    }
}

// @return read byte size
static size_t readFileAll(const char* file_name, unsigned char* read_to, size_t size)
{
    if (read_to == nullptr) {
        log::error("in readfileAll, param read_to is nullptr. exit");
        return 0;
    }
    std::ifstream ifs(file_name);
    if (ifs.fail()) {
        log::error("Fialed to read %s. exit", file_name);
        return 0;
    }
    std::string read_to_str((std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
    memset(read_to, 0, size);
    memcpy(read_to, read_to_str.c_str(), size);
    return strlen((char *) read_to);
}

uc_err UC_LoadBinaryFromBinFile(const char* file_name)
{
    size_t file_size = UC_GetFileSize(ucBinFileName);
    unsigned char* bin;
    bin = (unsigned char*) malloc(file_size);
    readFileAll(file_name, bin, file_size);
    log::debug("loaded binary:");
    printBin(bin, file_size);
    UC_LoadBinary(bin, BIN_FILE_BASE_ADDR, file_size);
    UC_SetEmuStartAddr(BIN_FILE_BASE_ADDR);
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

