#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>

#include <string>
#include <vector>
#include <map>
#include <list>
#include <set>

#include <unicorn/unicorn.h> // emulator
#include <capstone/capstone.h> // disassembler

#include "unicorn_elf_loader.hpp"
#include "unicorn_wrapper.h"
#include <triton/logger.hpp>
using namespace tracer::unicorn;

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

namespace triton {
namespace tracer {
namespace unicorn {
namespace loader {
namespace elf {


err_t parse_elf(char *file_name, header *header, sections *sections, segments *segments)
{
    // open elf file
    int fd = open(file_name, O_RDONLY);
    if (fd == 0) {
        return ERR_EXIST;
    }

    // map file to memory
    struct stat sb;
    fstat(fd, &sb);
    void *head = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

    // check the file's magic number
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)head; // parse this file as 32-bit elf
    if (!IS_ELF(ehdr)) {
        return ERR_FORMAT;
    }

    if (ehdr->e_ident[EI_CLASS] == ELFCLASS64) { // this is 64-bit elf
        Elf64_Ehdr *e64hdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr *shstr;
        Elf64_Phdr *phdr;

        // re-parse elf header
        e64hdr = (Elf64_Ehdr *) ehdr;

        // parse header
        header->entry_point = e64hdr->e_entry;

        // parse sections
        shstr = (Elf64_Shdr *)(head + e64hdr->e_shoff + e64hdr->e_shentsize * e64hdr->e_shstrndx);
        for (int i = 0; i < e64hdr->e_shnum; i++) {
            shdr = (Elf64_Shdr *)(head + e64hdr->e_shoff + e64hdr->e_shentsize * i);
            std::string section_name = std::string((char*) head + shstr->sh_offset + shdr->sh_name);
            struct section s = {(long unsigned int) shdr->sh_addr, (long unsigned int) shdr->sh_offset, (long unsigned int) shdr->sh_size};
            (*sections)[section_name] = s;
        }

        // parse segments
        for (int i = 0; i < e64hdr->e_phnum; i++) {
            phdr = (Elf64_Phdr *)(head + e64hdr->e_phoff + e64hdr->e_phentsize * i);
            struct segment s = {(long unsigned int) phdr->p_vaddr, (long unsigned int) phdr->p_offset, (long unsigned int) phdr->p_filesz, (Elf32_Word) phdr->p_type};
            (*segments)[i] = s;
        }
    }
    else { // Unsupported
        // TODO: 32-bit elf support
        fprintf(stderr, "Unsupported elf class\n");
    }

    munmap(head, sb.st_size);
    close(fd);
    return ERR_OK;
}

void print_header(header *header)
{
    printf("entry point: 0x%x\n", header->entry_point);
}

void print_sections(sections *sections)
{
    puts("=== [sections] ===");
    for(auto itr = sections->begin(); itr != sections->end(); ++itr) {
        printf("%s (addr=0x%x, offset=0x%x, size=0x%x)\n",
            itr->first.c_str(), itr->second.addr, itr->second.offset, itr->second.size
            );
    }
}

void print_segments(segments *segments)
{
    puts("=== [segments] ===");
    for(auto itr = segments->begin(); itr != segments->end(); ++itr) {
        printf("%d (addr=0x%x, offset=0x%x, size=0x%x, type=%d)\n",
            itr->first, itr->second.addr, itr->second.offset, itr->second.size, itr->second.type
            );
    }
}

void print_memory_map(memory_map *memory_map)
{
    puts("=== [memory map] ===");
    for (auto x: *memory_map) {
        printf("region: 0x%lx - 0x%lx\n", x.begin, x.end);
    }
}

void calc_memory_map(memory_map *memory_map, segments *segments)
{
    auto page_size = 4 * 1024;
    std::set<unsigned long int> page_bits; // page: 4KB
    for (auto itr = segments->begin(); itr != segments->end(); ++itr) {
        auto begin = itr->second.addr;
        auto end = begin + itr->second.size;
        for (long int i = begin / page_size; i <= end /page_size; i++) {
            page_bits.insert(i);
        }
    }
    for(auto x : page_bits) {
        struct range r = {x * page_size, (x + 1) * page_size};
        memory_map->push_back(r);
    }
}

// callback for tracing instruction in real time
void hook_code64(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%lx, instruction size = 0x%x\n", address, size);

    // disassemble
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
        uint8_t code[32];
        memset(code, 0, sizeof(code));
        uc_err err = uc_mem_read(uc, address, &code, size);
        cs_insn *insn;
        size_t count = 0;
        count = cs_disasm(handle, (uint8_t *) &code, sizeof(code)-1, address, 0, &insn);
        if (count > 0) {
            printf("\t0x%lx:\t%s\t\t%s\n",
                insn[0].address, insn[0].mnemonic, insn[0].op_str);
            #if 0
                uint64_t rax, rsi, rsp;
                uint32_t dword_ptr_ref = 0;
                uc_reg_read(uc, UC_X86_REG_RAX, &rax);
                uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
                uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
                printf(">>> RAX is 0x%lx\n", rax);
                uc_mem_read(uc, rax, &dword_ptr_ref, sizeof(dword_ptr_ref));
                printf(">>> dword ptr [rax] = %lx\n", dword_ptr_ref);
                printf(">>> RSI is 0x%lx\n", rsi);
                printf(">>> RSP is 0x%lx\n", rsp);
            #endif
            cs_free(insn, count);
        }
        cs_close(&handle);
    }
}

// callback for tracing memory access (READ or WRITE)
bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_READ_UNMAPPED:
                 printf(">>> Missing memory is being READ at 0x%lx, data size = %u, data value = 0x%lx\n",
                         address, size, value);
                 return true;
        case UC_MEM_WRITE_UNMAPPED:
                 printf(">>> Missing memory is being WRITE at 0x%lx, data size = %u, data value = 0x%lx\n",
                         address, size, value);
                 return true;
    }
}

// callback for SYSCALL instruction (X86).
void hook_syscall(uc_engine *uc, void *user_data)
{
    uint64_t rax, rdi, rsi, rdx;
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    if (rax == 1) {
        // rdi: unsigned int fd
        // rsi: const char *buf
        // rdx: size_t count
        uc_mem_read(uc, rsi, buf, rdx);
        printf(ANSI_COLOR_YELLOW">>> syscall write"ANSI_COLOR_RESET"(fd=%d, *buf='%s', count=%d)\n", rdi, buf, rdx);
    }
    else if (rax == 60) { // sys_exit
        printf(">>> enumation stoped because of sys_exit(error_code=%d)\n", rdi);
        uc_emu_stop(uc);
    }
}

err_t load_file(void *head, uc_engine *uc, segments *segments)
{
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;

    ehdr = (Elf64_Ehdr *) head;

    for(auto itr = segments->begin(); itr != segments->end(); ++itr) {
        auto type = itr->second.type; // NOTE: to avoid 'error: jump to case label'
        switch (type) {
            case PT_LOAD:
                // load to memory
                uc_mem_write(uc, itr->second.addr, (char *)head + itr->second.offset, itr->second.size);
                break;
            default:
                // Do nothing
                break;
        }
    }
    return ERR_OK;
}

err_t elf_loader(char *file_name, uc_engine *uc, header *header, segments *segments)
{
    log::debug("elf_loader(file_name='%s', uc=%p, header=%p, segments=%p)", file_name, uc, header, segments);

    // open elf file
    int fd = open(file_name, O_RDONLY);
    if (fd == 0) {
        return ERR_EXIST;
    }

    // map file to memory
    struct stat sb;
    fstat(fd, &sb);
    void *head = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

    // prepare emulator memory
    memory_map memory_map;
    calc_memory_map(&memory_map, segments);
    print_memory_map(&memory_map);
    uc_err uerr;
    for (auto x : memory_map) {
        auto size = x.end - x.begin;
        log::debug("uc_mem_map(uc, begin=0x%x, size=0x%x, UC_PROT_ALL)", x.begin, size);
        uerr = uc_mem_map(uc, x.begin, size, UC_PROT_ALL);
        if (uerr != UC_ERR_OK) {
            log::error("elf_loader: uc_mem_map(uc, begin=0x%x, size=0x%x, UC_PROT_ALL) faild", x.begin, size);
        }
        register_memory_map("text", x.begin, x.end);
    }
    // map stack region
    uc_mem_map(uc, 0x800000 - 0x10000, 0x10000, UC_PROT_ALL);

    // load file to emulator
    err_t err;
    err = load_file(head, uc, segments);
    if (err) {
        return err;
    }

    return ERR_OK;
}

void push_stack(uc_engine *uc, uint64_t data) {
    int64_t rsp;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    rsp -= sizeof(uint64_t); // slide rbp
    uc_mem_write(uc, rsp, &data, sizeof(uint64_t));
    printf("push_stack: rsp = 0x%lx, data = 0x%lx\n", rsp, data);
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
}

// @return address of this argv
uint64_t push_argv(uc_engine *uc, uint8_t* orig_buf, uint64_t len) {
    assert(len > 0);
    int malloc_len = len + (sizeof(uint64_t) - (len % sizeof(uint64_t)));
    uint8_t* buf = (uint8_t*) malloc(malloc_len);
    memset(buf, 0, malloc_len);
    memcpy(buf, orig_buf, len);
    for (int offset = (len / sizeof(uint64_t)) * sizeof(uint64_t); offset >= 0; offset -= sizeof(uint64_t)) {
        uint64_t *data = (uint64_t *) (&(buf[offset]));
        push_stack(uc, *data);
    }
    int64_t rsp;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    return rsp;
}

}
}
}
}
}