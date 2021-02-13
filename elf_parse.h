#pragma once

#include "heap.h"
#include <elf.h>
#include <stdbool.h>

/*
 * Struct for more conveniently accessing important stuff in the ELF data
 */
struct ELF64_Data {
    uint8_t *raw_data;              /* Raw ELF data */
    uint64_t raw_data_len;          /* Length of raw ELF data */
    Elf64_Ehdr hdr;                 /* ELF64 Header */
    Elf64_Shdr *sh_table;           /* Section Header array */
    uint64_t sh_num_entries;        /* Number of Section Headers */
    char *sh_name_data;             /* Section Header name array. Points to raw_data + offset */

    /* Sections */
    Elf64_Shdr *sh_rela_plt;        /* Section Header for .rela.plt */
    Elf64_Rela *rela_plt_entries;   /* .rela.plt table entries */
    uint64_t rela_plt_num_entries;

    Elf64_Shdr *sh_dynsym;          /* Section Header for .rela.plt */
    Elf64_Sym *dynsym_entries;      /* .dynsym symbol table entries */
    uint64_t dynsym_num_entries;    /* number of .dynsym symbols */

    Elf64_Shdr *sh_dynstr;
    char *dynstr_data;

    Elf64_Shdr *sh_plt;
    uint8_t *plt_data;

    Elf64_Shdr *sh_symtab;
    Elf64_Sym *symtab_entries;
    uint64_t symtab_num_entries;

    Elf64_Shdr *sh_strtab;
    char *strtab_data;
};

bool parse_elf64(const uint8_t *_elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data);
bool get_PLT_addresses(struct ELF64_Data *elf64, struct Heap_Func_Addrs *addrs);
void ELF64_Data_destroy(struct ELF64_Data *e);
