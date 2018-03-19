#ifndef _UNICORN_ELF_LOADER_H_
#define _UNICORN_ELF_LOADER_H_

#include <elf.h>
#include <unicorn/unicorn.h>

namespace triton {
namespace tracer {
namespace unicorn {
namespace loader {
namespace elf {

typedef enum {
    ERR_OK = 0,
    ERR_EXIST,
    ERR_FORMAT,
} err_t;

struct header {
    long unsigned int entry_point = 0;
};
struct section {
    long unsigned int addr;
    long unsigned int offset;
    long unsigned int size;
};
typedef std::map<std::string, struct section> sections;
struct segment {
    long unsigned int addr;
    long unsigned int offset;
    long unsigned int size;
    Elf32_Word type;
};
typedef std::map<int, struct segment> segments;
struct range {
    long unsigned int begin;
    long unsigned int end;
};
typedef std::list<struct range> memory_map;

#define IS_ELF(h) (h->e_ident[0] == 0x7f && h->e_ident[1] == 'E' && h->e_ident[2] == 'L' && h->e_ident[3] == 'F')


err_t parse_elf(char *file_name, header *header, sections *sections, segments *segments);
void print_header(header *header);
void print_sections(sections *sections);
void print_segments(segments *segments);
void print_memory_map(memory_map *memory_map);
err_t elf_loader(char *file_name, uc_engine *uc, header *header, segments *segments);
void push_stack(uc_engine *uc, uint64_t data);
uint64_t push_argv(uc_engine *uc, uint8_t* orig_buf, uint64_t len);

// hooks
void hook_code64(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data);
void hook_syscall(uc_engine *uc, void *user_data);

}
}
}
}
}

#endif