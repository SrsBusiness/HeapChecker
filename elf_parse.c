#include "elf_parse.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

void
ELF64_Data_destroy(struct ELF64_Data *e)
{
    free(e->raw_data);
    e->raw_data = NULL;
    free(e->sh_table);
    e->sh_table = NULL;
    free(e->rela_plt_entries);
    e->rela_plt_entries = NULL;
    free(e->dynsym_entries);
    e->dynsym_entries = NULL;
    free(e->symtab_entries);
    e->symtab_entries = NULL;
}

static inline bool
verify_elf_header(Elf64_Ehdr *hdr)
{
    /* bytes [0, 4) */
    if (memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0) {
        error("ELF Magic bytes do not match\n");
        return false;
    }
    
    /* byte 4 */
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        error("Only 64-bit ELF supported\n");
        return false;
    }

    /* byte 5 */
    if (hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        error("Only little endian systems supported\n");
        return false;
    }

    /* byte 6 */
    if (hdr->e_ident[EI_VERSION] != EV_CURRENT) {
        error("ELF version %u not supported, must be version %u\n", hdr->e_ident[EI_VERSION], EV_CURRENT);
    }

    /* byte 7 */
    if (hdr->e_ident[EI_OSABI] != ELFOSABI_SYSV) {
        error("Only System V ABI supported\n");
    }

    /* bytes [8, 16) are padding */

    /*
     * TODO: Support ET_DYN. On some systems gcc is configured to output PI
     * code, which changes the binary type to ET_DYN
     */
    if (hdr->e_type != ET_EXEC) {
        if (hdr->e_type == ET_DYN) {
            error("Position Independent binaries not supported yet. Please try re-compiling with -no-pie\n");
        } else {
            error("ELF is not executable\n");
        }
        return false;
    }
    
    /* TODO: support more ISA like ARM */
    if (hdr->e_machine != EM_X86_64) {
        error("Only x86_64 supported\n");
        return false;
    }

    if (hdr->e_version != EV_CURRENT) {
        error("ELF version %u not supported, must be version %u\n", hdr->e_ident[EI_VERSION], EV_CURRENT);
        return false;
    }

    if (hdr->e_ehsize != sizeof(*hdr)) {
        error("ELF header size mismatch: %u instead of %u\n", hdr->e_ehsize, sizeof(*hdr));
        return false;
    }


    return true;
}


static inline bool
parse_elf64_section_header_table(uint8_t *elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data)
{
    /* Read Section Header Table */
    uint64_t sh_off = parsed_data->hdr.e_shoff;
    uint16_t sh_entsize = parsed_data->hdr.e_shentsize;
    if (sh_entsize != sizeof(Elf64_Shdr)) {
        error("Section Header size mismatch: %u instead of %u\n", sh_entsize, sizeof(Elf64_Shdr));
        return false;
    }
    parsed_data->sh_num_entries = parsed_data->hdr.e_shnum;
    uint64_t sh_table_size = parsed_data->sh_num_entries * sizeof(Elf64_Shdr);
    parsed_data->sh_table = malloc(sh_table_size);
    memcpy(parsed_data->sh_table, &elf_raw_data[sh_off], sh_table_size);

    debug("Found %u Section Headers\n", parsed_data->sh_num_entries);

    /* Read Section Header Name Table */
    uint16_t sh_strndx = parsed_data->hdr.e_shstrndx;
    Elf64_Shdr *sh_name_table = &parsed_data->sh_table[sh_strndx];
    if (sh_name_table->sh_type != SHT_STRTAB) {
        error("Section Header Name Table type mismatch: %u instead of %u\n", sh_name_table->sh_type, SHT_STRTAB);
        return false;
    }
    parsed_data->sh_name_data = &elf_raw_data[sh_name_table->sh_offset];
    const char *sh_name_table_name = &parsed_data->sh_name_data[sh_name_table->sh_name];
    debug("Found Section Header Name Table named %s\n", sh_name_table_name);
    return true;
}

static inline bool
parse_elf64_symtab(uint8_t *elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data)
{
    /* Find the SHT_RELA Section with the name .symtab */
    Elf64_Shdr *sh_symtab = NULL;
    for (uint64_t i = 0; i < parsed_data->sh_num_entries; i++) {
        Elf64_Shdr *sh = &parsed_data->sh_table[i];
        if (sh->sh_type == SHT_SYMTAB) {
            const char *sh_name = &parsed_data->sh_name_data[sh->sh_name];
            if (strncmp(sh_name, ".symtab", sizeof(".symtab")) == 0) {
                debug("Found SHT_SYMTAB section named %s\n", sh_name);
                sh_symtab = parsed_data->sh_symtab = sh; 
                break;
            }
        }
    }
    
    uint64_t symtab_num_entries = parsed_data->symtab_num_entries = sh_symtab->sh_size / sh_symtab->sh_entsize;
    if (symtab_num_entries * sh_symtab->sh_entsize != sh_symtab->sh_size) {
        error(".symtab table size not a multiple of that of its entries\n");
        return false;
    }
    Elf64_Sym *symtab_entries = parsed_data->symtab_entries = malloc(sh_symtab->sh_size);
    memcpy(symtab_entries, &elf_raw_data[sh_symtab->sh_offset], sh_symtab->sh_size);


    

    return true;
}

static inline bool
parse_elf64_strtab(uint8_t *elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data)
{
    /* Find SHT_STRTAB section named .strtab */
    Elf64_Shdr *sh_symtab = parsed_data->sh_symtab;
    if (sh_symtab->sh_link == 0) {
        error("Section .symtab contains no link to .strtab\n");
        return false;
    }

    Elf64_Shdr *sh_strtab = parsed_data->sh_strtab = &parsed_data->sh_table[sh_symtab->sh_link];
    if (sh_strtab->sh_type != SHT_STRTAB) {
        error("Section .strtab is not of type SHT_STRTAB");
        return false;
    }
    const char *strtab_name = &parsed_data->sh_name_data[sh_strtab->sh_name];
    if (strncmp(strtab_name, ".strtab", sizeof(".strtab"))) {
        error("Section .strtab named %s instead of .strtab\n", strtab_name);
        return false;
    }
    debug("Found SHT_STRTAB section named %s\n", strtab_name);
    parsed_data->strtab_data = &elf_raw_data[sh_strtab->sh_offset];
    return true;
}

static inline bool
parse_elf64_plt(uint8_t *elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data)
{
    /* Find the SHT_RELA Section with the name .rela.plt */
    Elf64_Shdr *sh_plt = NULL;
    for (uint64_t i = 0; i < parsed_data->sh_num_entries; i++) {
        Elf64_Shdr *sh = &parsed_data->sh_table[i];
        if (sh->sh_type == SHT_PROGBITS) {
            const char *sh_name = &parsed_data->sh_name_data[sh->sh_name];
            if (strncmp(sh_name, ".plt", sizeof(".plt")) == 0) {
                debug("Found SHT_PROGBITS section named %s\n", sh_name);
                sh_plt = parsed_data->sh_plt = sh; 
                break;
            }
        }
    }

    if (sh_plt == NULL) {
        error("Section .plt not found\n");
    }

    parsed_data->plt_data = &elf_raw_data[sh_plt->sh_offset];
     
    return true;
}

static inline bool
parse_elf64_rela_plt(uint8_t *elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data)
{
    /* Find the SHT_RELA Section with the name .rela.plt */
    Elf64_Shdr *sh_rela_plt = NULL;
    for (uint64_t i = 0; i < parsed_data->sh_num_entries; i++) {
        Elf64_Shdr *sh = &parsed_data->sh_table[i];
        if (sh->sh_type == SHT_RELA) {
            const char *sh_name = &parsed_data->sh_name_data[sh->sh_name];
            if (strncmp(sh_name, ".rela.plt", sizeof(".rela.plt")) == 0) {
                debug("Found SHT_RELA section named %s\n", sh_name);
                sh_rela_plt = parsed_data->sh_rela_plt = sh; 
                break;
            }
        }
    }
    if (sh_rela_plt == NULL) {
        error("Section .rela.plt not found\n");
    }
    
    uint8_t *rela_plt_data = &parsed_data->raw_data[sh_rela_plt->sh_offset];
    if (sh_rela_plt->sh_entsize != sizeof(Elf64_Rela)) {
        error(".rela.plt entries size mismatch: %u instead of %u\n", sh_rela_plt->sh_entsize, sizeof(Elf64_Rela));
        return false;
    }
    uint64_t rela_plt_num_entries = parsed_data->rela_plt_num_entries = sh_rela_plt->sh_size / sh_rela_plt->sh_entsize;
    if (rela_plt_num_entries * sh_rela_plt->sh_entsize != sh_rela_plt->sh_size) {
        error(".rela.plt table size not a multiple of that of its entries\n");
    }
    Elf64_Rela *rela_plt_entries = parsed_data->rela_plt_entries = malloc(sh_rela_plt->sh_size);
    memcpy(rela_plt_entries, rela_plt_data, sh_rela_plt->sh_size);
    return true;
}

static inline bool
parse_elf64_dynsym(uint8_t *elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data)
{
    /* Find the SHT_DYNSYM Section named .dynsym to which .rela.plt links */
    Elf64_Shdr *sh_rela_plt = parsed_data->sh_rela_plt;
    if (sh_rela_plt->sh_link == 0) {
        error("Section .rela.plt contains no link to Section .dynsym\n");
        return false;
    }
    Elf64_Shdr *sh_dynsym = parsed_data->sh_dynsym = &parsed_data->sh_table[sh_rela_plt->sh_link];
    if (sh_dynsym->sh_type != SHT_DYNSYM) {
        error("Section .dynsym is not of type SHT_DYNSYM\n");
        return false;
    }
    const char *dynsym_name = &parsed_data->sh_name_data[sh_dynsym->sh_name];
    if (strncmp(dynsym_name, ".dynsym", sizeof(".dynsym")) != 0) {
        error("Section .dynsym named %s instead of .dynsym\n", dynsym_name);
        return false;
    }
    debug("Found SHT_DYNSYM Section named %s\n", dynsym_name);
    uint8_t *dynsym_data = &parsed_data->raw_data[sh_dynsym->sh_offset];
    if (sh_dynsym->sh_entsize != sizeof(Elf64_Sym)) {
        error(".dynsym entries size mismatch: %u instead of %u\n", sh_dynsym->sh_entsize, sizeof(Elf64_Sym));
    }
    uint64_t dynsym_num_entries = parsed_data->dynsym_num_entries = sh_dynsym->sh_size / sh_dynsym->sh_entsize;
    if (dynsym_num_entries * sh_dynsym->sh_entsize != sh_dynsym->sh_size) {
        error(".dynsym table size not a multiple of that of its entries\n");
    }
    Elf64_Sym *dynsym_entries = parsed_data->dynsym_entries = malloc(sh_dynsym->sh_size);
    memcpy(dynsym_entries, dynsym_data, sh_dynsym->sh_size);
    return true;
}

static inline bool
parse_elf64_dynstr(uint8_t *elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data)
{
    Elf64_Shdr *sh_dynsym = parsed_data->sh_dynsym;
    if (sh_dynsym->sh_link == 0) {
        error("Section .rela.plt contains no link to Section .dynstr\n");
        return false;
    }
    Elf64_Shdr *sh_dynstr = parsed_data->sh_dynstr = &parsed_data->sh_table[sh_dynsym->sh_link];
    if (sh_dynstr->sh_type != SHT_STRTAB) {
        error("Section .dynstr is not of type SHT_STRTAB\n");
        return false;
    }
    const char *dynstr_name = &parsed_data->sh_name_data[sh_dynstr->sh_name];
    if (strncmp(dynstr_name, ".dynstr", sizeof(".dynstr")) != 0) {
        error("Section .dynstr named %s instead of .dynstr\n");
        return false;
    }
    debug("Found SHT_STRTAB Section named %s\n", dynstr_name);
    parsed_data->dynstr_data = &parsed_data->raw_data[sh_dynstr->sh_offset];
    return true;
}


/*
 * Parse elf_raw_data and populate parsed_data
 * TODO: break up into separate helper functions for each ELF section
 */
bool
parse_elf64(const uint8_t *_elf_raw_data, uint64_t len, struct ELF64_Data *parsed_data)
{
    /* Make and use a copy of elf_raw_data */
    parsed_data->raw_data = malloc(len);
    memcpy(parsed_data->raw_data, _elf_raw_data, len);
    parsed_data->raw_data_len = len;
    
    uint8_t *elf_raw_data = parsed_data->raw_data;

    /* Read header */
    if (len < sizeof(parsed_data->hdr)) {
        error("Length of ELF data shorter than ELF header length\n");
        return false;
    }
    memcpy(&parsed_data->hdr, elf_raw_data, sizeof(parsed_data->hdr));
    if (!verify_elf_header(&parsed_data->hdr)) {
        return false;
    }

    /* Read Section Header Table and Section Header Name Table */
    if (!parse_elf64_section_header_table(elf_raw_data, len, parsed_data)) {
        return false;
    }

    /* Find the SHT_PROGBITS Section with the name .plt */
    if (!parse_elf64_plt(elf_raw_data, len, parsed_data)) {
        return false;
    }

    /* Find the SHT_RELA Section with the name .rela.plt */
    if (!parse_elf64_rela_plt(elf_raw_data, len, parsed_data)) {
        return false;
    }

    /* Find the SHT_DYNSYM Section named .dynsym to which .rela.plt links */
    if (!parse_elf64_dynsym(elf_raw_data, len, parsed_data)) {
        return false;
    }
    
    /* Find the SHT_STRTAB Section named .dynstr to which .dynsym links */
    if (!parse_elf64_dynstr(elf_raw_data, len, parsed_data)) {
        return false;
    }

    return true;
}

bool
get_GOT_offsets(struct ELF64_Data *elf64)
{
    for (uint64_t i = 0; i < elf64->rela_plt_num_entries; i++) {
        Elf64_Rela *rela = &elf64->rela_plt_entries[i];
        uint64_t GOT_offset = rela->r_offset; 
        uint64_t dynsym_index = ELF64_R_SYM(rela->r_info);
        Elf64_Sym *sym = &elf64->dynsym_entries[dynsym_index];
        const char *sym_name = &elf64->dynstr_data[sym->st_name];
        
        bool found = false;
        if (found = (strncmp(sym_name, "calloc", sizeof("calloc"))) == 0) {
            
        } else if (found = (strncmp(sym_name, "malloc", sizeof("malloc"))) == 0) {
        } else if (found = (strncmp(sym_name, "realloc", sizeof("realloc"))) == 0) {
        } else if (found = (strncmp(sym_name, "free", sizeof("free"))) == 0) {
        }
        if (found) {
            debug("Found symbol %s\n", sym_name);
            debug("Symbol index: %llu\n", dynsym_index);
            debug("GOT offset: 0x%x, addend: 0x%x\n", GOT_offset);
            debug("Sym value: 0x%x\n", sym->st_value);
            debug("Relocation type: %u\n", ELF32_R_TYPE(rela->r_info));
        }

    }
    return true;
}

bool
get_PLT_addresses(struct ELF64_Data *elf64, struct Heap_Func_Addrs *addrs)
{
    debug("PLT size: %u\n", elf64->sh_plt->sh_size);
    debug("PLT entry size: %u\n", elf64->sh_plt->sh_entsize);
    uint64_t PLT_base_address = elf64->sh_plt->sh_addr;
    uint64_t PLT_entsize = elf64->sh_plt->sh_entsize;
    for (uint64_t i = 0; i < elf64->rela_plt_num_entries; i++) {
        Elf64_Rela *rela = &elf64->rela_plt_entries[i];
        uint64_t dynsym_index = ELF64_R_SYM(rela->r_info);
        Elf64_Sym *sym = &elf64->dynsym_entries[dynsym_index];
        const char *sym_name = &elf64->dynstr_data[sym->st_name];
        uint64_t PLT_sym_address = PLT_base_address + (i + 1) * PLT_entsize;
        if (strncmp(sym_name, "calloc", sizeof("calloc")) == 0) {
            debug("calloc: 0x%x\n", PLT_base_address + (i + 1) * PLT_entsize);
            addrs->addrs[HEAP_CALLOC] = PLT_sym_address;
        } else if (strncmp(sym_name, "malloc", sizeof("malloc")) == 0) {
            debug("malloc: 0x%x\n", PLT_base_address + (i + 1) * PLT_entsize);
            addrs->addrs[HEAP_MALLOC] = PLT_sym_address;
        } else if (strncmp(sym_name, "realloc", sizeof("realloc")) == 0) {
            debug("realloc: 0x%x\n", PLT_base_address + (i + 1) * PLT_entsize);
            addrs->addrs[HEAP_REALLOC] = PLT_sym_address;
        } else if (strncmp(sym_name, "free", sizeof("free")) == 0) {
            debug("free: 0x%x\n", PLT_base_address + (i + 1) * PLT_entsize);
            addrs->addrs[HEAP_FREE] = PLT_sym_address;
        }
    }
    return true;
}


