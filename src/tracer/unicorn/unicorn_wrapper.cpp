#include <string.h>
#include <signal.h>
#include <assert.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

// for file oparation
#include <fcntl.h>
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <string>
#include <iterator>

#include "context.hpp"
#include <triton/logger.hpp>

using namespace tracer::unicorn;

#include "unicorn_wrapper.h"
#include "unicorn_elf_loader.hpp"

/* for unicorn engine */
uc_engine* uc;
uc_hook uh_trap;
uc_hook uh_syscall, uh_interrupt, uh_syscall_entry, uh_syscall_exit;
uc_hook trace2, trace3, uc_hook_syscall; // at UC_LoadElf

/* for loader */
std::list<memory_map> memory_map_list;
std::list<struct hook> uc_hook_loader[UC_HOOK_LOADER_MAX];

/* for capstone engine */
csh csh_handle;

/* for runtime tracer */
struct tracer_env tracer_env;
const char* ucBinFileName;
const char* ucPythonScriptFileName;


void _interrupt(uc_engine *uc, uint32_t intno, void *user_data)
{
    log::info("==> syscall intno=%d", intno);
    if (intno == 6) {
        uc_emu_stop(uc);
    }
}

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

void register_memory_map(std::string name, unsigned long int start, unsigned end)
{
    struct memory_map mm;
    mm.name = name;
    mm.start = start;
    mm.end = end;
    memory_map_list.push_back(mm);
    log::info("'%s' mapped at 0x%lx - 0x%lx", name.c_str(), start, end);
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
    FILE *fp;
    fp = fopen(file_name, "r");
    if (fp == 0) {
        log::error("file not exists");
    }
    uint8_t magic[4];
    fread(magic, 4, 1, fp);
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        return UC_FILE_ELF64;
    }
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

    // Open Unicorn Engine
    uc_err err;
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        log::error("Failed on uc_open with error: %u", err);
    }

    // Load file
    bool load_ok = false;
    uc_file_type file_type = UC_DetectFileType(ucBinFileName);
    if (file_type == UC_FILE_BIN) {
        log::debug("bin file mode");
        load_ok = UC_LoadBinaryFromBinFile(ucBinFileName); // not supports argv
    }
    else if (file_type == UC_FILE_ELF32 || file_type == UC_FILE_ELF64) {
        log::debug("elf file mode");
        load_ok = UC_LoadElf(argc - 2, &argv[2]); // drop argv[0], argv[1] in main()
    }
    if (!load_ok) {
        log::error("UC_Init: Load failed");
    }

    // Open Capstone Engine
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh_handle) != CS_ERR_OK) {
        log::error("Failed on cs_open");
    }

    return true;
}

void UC_AddFiniFunction(VOID (*fun)(INT32, VOID*), VOID *val)
{
    // TODO
}

uc_err UC_AddSyscallEntryFunction(void* func, void* var)
{
    NON_NULL_ASSERT(func);
    // hook interrupts for syscall
    uc_err err;
    // err = uc_hook_add(uc, &uh_syscall_entry, UC_HOOK_INTR, func, var, 1, 0);
    err = uc_hook_add(uc, &uh_syscall_entry, UC_HOOK_INSN, func, var, 1, 0, UC_X86_INS_SYSCALL);
    log::debug("UC_AddSyscallEntryFunction(func=%p, var=%p) => err=%d", func, var, err);
    return err;
}

uc_err UC_AddSyscallExitFunction(void* func, void* var)
{
    // XXX* not corrext implements
    NON_NULL_ASSERT(func);
    uc_err err;
    err = uc_hook_add(uc, &uh_syscall_exit, UC_HOOK_INSN, func, var, 1, 0, UC_X86_INS_SYSCALL);
    return err;
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
    NON_NULL_ASSERT(tracer::unicorn::context::lastContext);
    UC_ERR_CHECK(uc_context_restore(uc, tracer::unicorn::context::lastContext)); // sync state from Triton to unicorn
    int count = 0;
    log::debug("UC_StartProgram(): uc_emu_start(uc=%p, begin=0x%x, until=0x%x, timeout=%u, count=%u)", 
        uc, tracer_env.emuStartAddr, tracer_env.emuEndAddr, 0, count);
#if 0
    uint64_t rax, rsi, rsp;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    printf(">>> RAX = 0x%lx\n", rax);
    printf(">>> RSI = 0x%lx\n", rsi);
    printf(">>> RSP = 0x%lx\n", rsp);
    if (rsp == 0) log::error("this context is blank");
#endif
    UC_ERR_CHECK(uc_emu_start(uc, tracer_env.emuStartAddr, tracer_env.emuEndAddr, 0, count)); // timeout = 0, count = 0
}

void UC_StopProgram()
{
    log::debug("UC_StopProgram() called");
    UC_ERR_CHECK(uc_emu_stop(uc));
}

CONTEXT* UC_GetCurrentContext(uc_engine *uc)
{
    uc_context *ctxt = nullptr;
    UC_ERR_CHECK(uc_context_alloc(uc, &ctxt));
    UC_ERR_CHECK(uc_context_save(uc, ctxt));
    return ctxt;
}

CONTEXT* UC_GetCurrentContext()
{
    NON_NULL_ASSERT(uc);
    uc_context *ctxt = nullptr;
    UC_ERR_CHECK(uc_context_alloc(uc, &ctxt));
    UC_ERR_CHECK(uc_context_save(uc, ctxt));
    return ctxt;
}

uc_err UC_GetCurrentRegVal(REG reg, void *val)
{
    NON_NULL_ASSERT(val);
    return UC_ERR_CHECK(uc_reg_read(uc, reg, val));
}

void UC_GetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val)
{
    NON_NULL_ASSERT(ctxt);
    NON_NULL_ASSERT(&reg);
    uc_err err;
    struct uc_context *tmp_ctxt;
    err = uc_context_alloc(uc, &tmp_ctxt);
    if (err) {
        log::error("Failed on uc_context_alloc() with error returned: %u", err);
    }
    NON_NULL_ASSERT(tmp_ctxt);
    uc_context_save(uc, tmp_ctxt);
    uc_context_restore(uc, ctxt);
    uc_reg_read(uc, reg, val);
    log::debug("UC_GetContextRegval() = 0x%x :uint32", *((unsigned int *)val));
    uc_context_restore(uc, tmp_ctxt);
}

void UC_SetContextRegval(CONTEXT *ctxt, REG reg, UINT8 *val)
{
    NON_NULL_ASSERT(ctxt);
    NON_NULL_ASSERT(&reg);
    uc_err err;
    struct uc_context *tmp_ctxt;
    err = uc_context_alloc(uc, &tmp_ctxt);
    if (err) {
        log::error("Failed on uc_context_alloc() with error returned: %u", err);
        return;
    }
    NON_NULL_ASSERT(tmp_ctxt);
    uc_context_save(uc, tmp_ctxt);
    uc_context_restore(uc, ctxt);
    uc_reg_write(uc, reg, val);
    uc_context_save(uc, ctxt);
    uc_context_restore(uc, tmp_ctxt);
}

uc_err UC_ReadCurrentMem(ADDR address, void* data, size_t size)
{
    return uc_mem_read(uc, address, data, size);
}

uc_err UC_WriteCurrentMem(ADDR address, void* data, size_t size)
{
    return uc_mem_write(uc, address, data, size);
}

void UC_ExecuteAt(CONTEXT *ctxt)
{
    NON_NULL_ASSERT(ctxt);
    uc_context_restore(uc, ctxt);
    ADDR pc;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    uc_emu_start(uc, pc, 0, 0, 1); // 1 step execution
}

uc_err UC_SaveContext(CONTEXT *ctxtFrom, CONTEXT *ctxtTo)
{
    uc_err err = UC_ERR_OK;
    if (ctxtTo == nullptr) {
        err = uc_context_alloc(uc, &ctxtTo);
        if (err) {
            return err;
        }
    }
    memcpy(ctxtTo, ctxtFrom, sizeof(CONTEXT *));
    return err;
}

// for prototype only
uc_err UC_LoadBinary(unsigned char *bin, int begin, int size)
{
    uc_err err = UC_ERR_OK;

    // allocate memory 
    unsigned int alignment = 2 * 1024 * 1024;
    unsigned int map_size = size;
    if (map_size % alignment) { // check 4 KB alignment
        map_size += alignment - (size % alignment);
        log::info("param size is not 2 MB aligned. New size is 0x%x", map_size);
    }
    log::debug("uc_mem_map(uc=%p, begin=0x%x, size=0x%x, UC_PROT_ALL)", uc, begin, map_size);
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

    // allocate stack
    ADDR stack_size = 0x100000;
    ADDR stack_addr = 0x800000 - stack_size;
    log::debug("uc_mem_map(uc=%p, begin=0x%x, size=0x%x, UC_PROT_ALL)", uc, stack_addr, stack_size);
    err = uc_mem_map(uc, stack_addr, stack_size, UC_PROT_ALL);
    if (err) {
      log::error("Failed to map memory, quit!");
      return err; // never returns?
    }
    register_memory_map("main_stack", stack_addr, stack_addr + stack_size - 1);

    // allocate workspace
    ADDR workspace_size = 0x10000;
    ADDR workspace_addr = LOADER_WORKSPACE_ADDR;
    log::debug("uc_mem_map(uc=%p, begin=0x%x, size=0x%x, UC_PROT_ALL)", uc, workspace_addr, workspace_size);
    err = uc_mem_map(uc, workspace_addr, workspace_size, UC_PROT_ALL);
    if (err) {
      log::error("Failed to map memory, quit!");
      return err; // never returns?
    }
    register_memory_map("main_workspace", workspace_addr, workspace_addr + workspace_size - 1);    

    // fire callbacks
    IMG* img = &*(memory_map_list.end());
    for (auto &hh : uc_hook_loader[UC_HOOK_LOADER_COMPLETE]) {
        log::debug("%s\n", img->name);
        ((uc_cb_loader_out_t) hh.callback)(uc, img);
    }
    return err;
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

bool UC_LoadBinaryFromBinFile(const char* file_name)
{
    size_t file_size = UC_GetFileSize(ucBinFileName);
    unsigned char* bin;
    bin = (unsigned char*) malloc(file_size);
    readFileAll(file_name, bin, file_size);
    // log::debug("loaded binary:");
    // printBin(bin, file_size);
    UC_LoadBinary(bin, BIN_FILE_BASE_ADDR, file_size);
    UC_SetEmuStartAddr(BIN_FILE_BASE_ADDR);
    UC_SetEmuEndAddr(BIN_FILE_BASE_ADDR + file_size);
    return true;
}

uc_context* test(uc_engine* uc)
{
  uc_context *ctxt = nullptr;
  UC_ERR_CHECK(uc_context_alloc(uc, &ctxt));
  UC_ERR_CHECK(uc_context_save(uc, ctxt));
  return ctxt;
}

bool UC_LoadElf(int argc, char* argv[])
{
    using namespace triton::tracer::unicorn::loader::elf;

    err_t err;

    if (argc < 1) {
        log::error("Failed on UC_LoadElf() argc must not less than 1");
        return false;
    }

    char *ELF_FILE = argv[0];
    log::debug("ELF_FILE = %s", ELF_FILE);
    header header;
    sections sections;
    segments segments;
    err = parse_elf(ELF_FILE, &header, &sections, &segments);
    if (err) {
        if (err == ERR_EXIST) perror("file not exists.");
        if (err == ERR_FORMAT) fprintf(stdout, "this is not elf.\n");
        log::error("parse_elf failed");
    }

    print_header(&header);
    print_sections(&sections);
    print_segments(&segments);

    UC_ERR_CHECK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc)); // FIXME: Multi-arch support

    log::debug("call elf_loader(uc=%p, ...)", uc);
    elf_loader(ELF_FILE, uc, &header, &segments);

    // prepare stack
    uc_mem_map(uc, 0x7fffffff0000, 0x10000, UC_PROT_ALL);
    register_memory_map("stack", 0x7fffffff0000, 0x10000);
    uint64_t rsp = 0x7ffffffff000; // FIXME: really
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    uint64_t emu_argc = argc;
    std::vector<uint64_t> argv_ptr;
    log::info("=== [prepare stack] ===");
    log::info("emu_argc = %d",  emu_argc);
    // -- argv[1]
    if (argc >= 2)
        argv_ptr.push_back(push_argv(uc, (uint8_t *) argv[1], strlen(argv[1])));
    // -- argv[0]
    if (argc >= 1)
        argv_ptr.push_back(push_argv(uc, (uint8_t *) argv[0], strlen(argv[0])));
    // -- address of argvs
    if (emu_argc == 1) {
        push_stack(uc, 0);
    }
    for (int i = 0; i < emu_argc; i++) {
        push_stack(uc, argv_ptr[i]);
    }
    // -- argc
    push_stack(uc, emu_argc);
    // synchronize rbp with rsp
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uc_reg_write(uc, UC_X86_REG_RBP, &rsp);

    // #ifndef NDEBUG
    //     // print executed codes (debug purpose)
    //     uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code64, NULL, 1, 0);
    // #endif
    // intercept invalid memory events
    uc_hook_add(uc, &trace3, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, (void *)hook_mem_invalid, NULL, 1, 0);
    // prepare hooks for syscall
    uc_hook_add(uc, &uc_hook_syscall, UC_HOOK_INSN, (void *)hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);

    // Set entry-point
    UC_SetEmuStartAddr(header.entry_point);
    UC_SetEmuEndAddr(0); // Endless emulation

    return true;
}

void UC_SetEmuStartAddr(int address)
{
    log::info("UC_SetEmuStartAddr(address=0x%x)", address);
    tracer_env.emuStartAddr = address;
}

void UC_SetEmuEndAddr(int address)
{
    tracer_env.emuEndAddr = address;
}

// uc_err UC_AddCodeHook(uc_hook *hh, void (*callback)(uc_engine*, uint64_t, uint32_t, void*), void *user_data, uint64_t begin, uint64_t end)
uc_err UC_AddCodeHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end)
{
    uc_err err;
    err = uc_hook_add(uc, hh, UC_HOOK_CODE, callback, user_data, begin, end);
    return err;
}

uc_err UC_AddBlockHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end)
{
    uc_err err;
    err = uc_hook_add(uc, hh, UC_HOOK_BLOCK, callback, user_data, begin, end);
    return err;
}

uc_err UC_AddInsnHook(uc_hook *hh, void *callback, void *user_data, uint64_t begin, uint64_t end, INSN insn)
{
    uc_err err;
    err = uc_hook_add(uc, hh, UC_HOOK_INSN, callback, user_data, begin, end, insn);
    return err;
}

uc_err UC_AddMemAccessUnmappedHook(uc_hook *hh, void *callback, void *user_data)
{
    uc_err err;
    err = uc_hook_add(uc, hh, UC_HOOK_MEM_UNMAPPED, callback, user_data, 1, 0);
    return err;
}

uc_err UC_AddLoaderHook(uc_hook *hh, uc_hook_loader_type hook_type, void *callback, void *user_data)
{
    uc_err err = UC_ERR_OK;
    struct hook hook;
    hook.type = hook_type;
    hook.refs = 0;
    hook.callback = callback;
    hook.user_data = user_data;
    uc_hook_loader[hook_type].push_back(hook);
    *hh = (uc_hook) hook.type;
    return err;
}

void print_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    cs_insn *insn;
    int r_rip;
    int count;
    unsigned char insn_bytes[16];
    uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
    size = MIN(sizeof(insn_bytes), size);
    if (!uc_mem_read(uc, address, insn_bytes, size)) {
        // disassemble instruction
        count = cs_disasm(csh_handle, insn_bytes, size, r_rip, 0, &insn);
        log::debug("[UC] 0x%llx:\t%s\t\t%s", insn[0].address, insn[0].mnemonic, insn[0].op_str);
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

