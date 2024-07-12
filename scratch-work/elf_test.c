#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdint.h>
#endif
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <capstone.h>
#include <stdbool.h>
#include "riscv.h"
#include <sys/syscall.h>

#define DG_DYNARR_IMPLEMENTATION // this define is only needed in *one* .c/.cpp file!
#include "DG_dynarr.h"
DA_TYPEDEF(uint64_t, ulong_list)

/*
 * get_object_path - attempt to find the path of the object in the
 * filesystem.
 *
 * This is usually supplied by dl_iterate_phdr in the dl_phdr_info struct,
 * but sometimes that does not contain it.
 */

#define MEM_SIZE (0x10)

struct object_info {
  char *addr;
  const char *path;
};
struct object_info libc_location = {NULL, NULL};
int callback(struct dl_phdr_info *info, size_t size, void *data) {
  if (strstr(info->dlpi_name, "libc.") != NULL) libc_location = (struct object_info) {(char *) info->dlpi_addr, info->dlpi_name};
  return 0;
}

bool is_nop(cs_insn ins) {
  return strcmp(ins.mnemonic, "nop") == 0;
  // cs_riscv_op op1, op2, op3;
  // if (ins.detail->riscv.op_count >= 1) op3 = *(ins.detail->riscv.operands + (uint8_t) 0);
  // if (ins.detail->riscv.op_count >= 2) op3 = *(ins.detail->riscv.operands + (uint8_t) 1);
  // if (ins.detail->riscv.op_count >= 3) op3 = *(ins.detail->riscv.operands + (uint8_t) 2);
  // switch (ins.id) {
  //   case RISCV_INS_ADD:
  //     if (ins.detail->riscv.op_count == 3) {
  //       // uncompressed
  //       if (op1.type == RISCV_OP_REG && op2.type == RISCV_OP_REG && op3.type == RISCV_OP_IMM && op1.reg == RISCV_REG_ZERO && op2.reg == RISCV_REG_ZERO && op3.imm == 0) {
  //         return true;
  //       }
  //     } else if (ins.detail->riscv.op_count == 2) {
  //       // compressed
  //       if (op1.type == RISCV_OP_REG && op2.type == RISCV_OP_IMM && op1.reg == RISCV_REG_ZERO && op2.imm == 0) {
  //         return true;
  //       }
  //     }
  //     return false;
  //   case RISCV_INS_ADDI:
  //     if (ins.detail->riscv.op_count == 3) {
  //       // uncompressed
  //       if (op1.type == RISCV_OP_REG && op2.type == RISCV_OP_REG && op3.type == RISCV_OP_IMM && op1.reg == RISCV_REG_ZERO && op2.reg == RISCV_REG_ZERO && op3.imm == 0) {
  //         return true;
  //       }
  //     } else if (ins.detail->riscv.op_count == 2) {
  //       // compressed
  //       if (op1.type == RISCV_OP_REG && op2.type == RISCV_OP_IMM && op1.reg == RISCV_REG_ZERO && op2.imm == 0) {
  //         return true;
  //       }
  //     }
  //     return false;
  //   case RISCV_INS_ADDIW:
  //     if (ins.detail->riscv.op_count == 3) {
  //       // uncompressed
  //       if (op1.type == RISCV_OP_REG && op2.type == RISCV_OP_REG && op3.type == RISCV_OP_IMM && op1.reg == RISCV_REG_ZERO && op2.reg == RISCV_REG_ZERO && op3.imm == 0) {
  //         return true;
  //       }
  //     } else if (ins.detail->riscv.op_count == 2) {
  //       // compressed
  //       if (op1.type == RISCV_OP_REG && op2.type == RISCV_OP_IMM && op1.reg == RISCV_REG_ZERO && op2.imm == 0) {
  //         return true;
  //       }
  //     }
  //     return false;
  //   case RISCV_INS_ADDW:
  //     if (ins.detail->riscv.op_count == 3) {
  //       // uncompressed
  //       if (op1.type == RISCV_OP_REG && op2.type == RISCV_OP_REG && op3.type == RISCV_OP_IMM && op1.reg == RISCV_REG_ZERO && op2.reg == RISCV_REG_ZERO && op3.imm == 0) {
  //         return true;
  //       }
  //     } else if (ins.detail->riscv.op_count == 2) {
  //       // compressed
  //       if (op1.type == RISCV_OP_REG && op2.type == RISCV_OP_IMM && op1.reg == RISCV_REG_ZERO && op2.imm == 0) {
  //         return true;
  //       }
  //     }
  //     return false;
  //   default:
  //     return false;
  // }
  // return false;
}

const uint8_t data[32] = {
  0x41, 0x11, 0x06, 0xe0, 0x17, 0x05, 0x00, 0x00,
  0x13, 0x05, 0x05, 0x00, 0xaa, 0x85, 0x05, 0x45,
  0x41, 0x46, 0x93, 0x08, 0x00, 0x04, 0x73, 0x00,
  0x00, 0x00, 0x82, 0x60, 0x41, 0x01, 0x02, 0x90
};
const uint8_t data2[12] = {
    0x13, 0x05, 0x50, 0x04, 0x93, 0x08, 0xd0, 0x05,
    0x73, 0x00, 0x00, 0x00
};
const uint8_t data3[56] = {
    0x41, 0x11, 0x37, 0x65, 0x61, 0x00, 0x1b, 0x05,
    0x05, 0x20, 0x2a, 0xe0, 0x8a, 0x85, 0x13, 0x05,
    0x80, 0xc1, 0x13, 0x06, 0x10, 0x04, 0x93, 0x06,
    0x40, 0x1a, 0x93, 0x08, 0x80, 0x03, 0x73, 0x00,
    0x00, 0x00, 0x93, 0x08, 0xb0, 0x03, 0x73, 0x00,
    0x00, 0x00, 0x41, 0x01, 0x13, 0x05, 0x50, 0x04,
    0x93, 0x08, 0xd0, 0x05, 0x73, 0x00, 0x00, 0x00
};

static inline unsigned char *round_down_address(unsigned char *address) {
	return (unsigned char *)(((uintptr_t)address) & ~(4096 - 1));
}

void printBits(size_t const size, void const * const ptr) {
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;
    
    for (i = size-1; i >= 0; i--) {
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}

uint32_t create_instruction(uint32_t imm) {
  uint32_t base = (imm & 0xFFFFF); // 0xFFFFF is the first 20 digits
  uint32_t bit20 = (base >> 19); // Extract bit 20
  uint32_t bits19_12 = (base >> 11); // Extract bits 19:12
  uint32_t bits_11 = (base >> 10) & 0x1; // Extract bit 11
  uint32_t bits10_1 = (base & 0x3FF); // Extract bits 10:1
  // printBits(4, &bit20);
  // printBits(4, &bits19_12);
  // printBits(4, &bits_11);
  // printBits(4, &bits10_1);
  uint32_t instruction = (bit20 << 31) | (bits10_1 << 21) | (bits_11 << 20) | (bits19_12 << 12) | 0x6F;
  return instruction;
}

long syscall_no_intercept(long syscall_number, ...);

int check_memory_permissions(void *addr, char perm) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    unsigned long start, end;
    char perms[5], line[256];
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if ((unsigned long)addr >= start && (unsigned long)addr < end) {
                found = 1;
                break;
            }
        }
    }

    fclose(fp);

    if (found && strchr(perms, perm)) {
        return 1; // Permission exists
    }

    return 0; // Permission does not exist or address not found
}

int main() {
  dl_iterate_phdr(callback, NULL);
  printf("libc: %p\n", (void *) libc_location.addr);
  printf("libc path: %s\n", libc_location.path);

  int fd = open(libc_location.path, O_RDONLY);
  long file_size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  void *file_mem = mmap(NULL, file_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
  close(fd);
  fd = -1;

  void *hook_mem = mmap(NULL, 56, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
  printf("File mem: %p\n", file_mem);
  printf("Hook mem: %p\n", hook_mem);
  memcpy(hook_mem, data3, 56);
  mprotect(hook_mem, 56, PROT_READ | PROT_EXEC);
  // ((void (*)()) hook_mem)();

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) file_mem;
  Elf64_Shdr shdrs[ehdr->e_shnum];
  memcpy(shdrs, (file_mem + ehdr->e_shoff), sizeof(Elf64_Shdr) * ehdr->e_shnum);
  char *sec_str_tbl = file_mem + shdrs[ehdr->e_shstrndx].sh_offset;
  Elf64_Shdr *text = NULL;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    printf("Section %d: %s\n", i, sec_str_tbl + shdrs[i].sh_name);
    if (strcmp(sec_str_tbl + shdrs[i].sh_name, ".text") == 0) {
      text = &shdrs[i];
    }
  }
  printf(".text: %p\n", (void *) text);
  
  csh handle;
  cs_insn *insn;
  // if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return EXIT_FAILURE;
  if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCVC, &handle) != CS_ERR_OK) return EXIT_FAILURE;
  if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != 0) return EXIT_FAILURE;
  if (cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON) != 0) return EXIT_FAILURE;
  size_t count = cs_disasm(handle, ((uint8_t *)libc_location.addr) + text->sh_addr, text->sh_size, 0, 0, &insn);
  printf("Offset: %lx\n.text size: %lx\n", text->sh_offset, text->sh_size);
  // size_t count = cs_disasm(handle, ((uint8_t *) file_mem) + text->sh_offset, text->sh_size, 0, 0, &insn);
  if (count > 0) {
    unsigned long slide_len = 0;
    ulong_list ecall_list = {0};
    for (size_t j = 0; j < count; j++) {
      // printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
      if (is_nop(insn[j])) slide_len++;
      else {
        if (slide_len > 0) printf("NOP slide end: %ld\n", slide_len);
        slide_len = 0;
      }
      if (insn[j].id == RISCV_INS_ECALL) {
        da_push(ecall_list, insn[j].address);
        printf("ECALL: %lx\n", insn[j].address + (uint64_t) libc_location.addr);
      }
    }
    printf("Number of ECALLs: %ld\n", count);
    cs_close(&handle);
    munmap(file_mem, file_size);
    uint8_t *start = round_down_address((unsigned char *) libc_location.addr);
    uint8_t *end = (uint8_t *) ((uint64_t) start + (uint64_t) text->sh_size + ((uint64_t) libc_location.addr - (uint64_t) start));
    int err = mprotect(start, text->sh_size + ((uint8_t*)libc_location.addr - start), PROT_READ | PROT_WRITE | PROT_EXEC);
    if (err != 0) {
      printf("Error: %d\n", err);
      exit(EXIT_FAILURE);
    }
    // syscall_no_intercept(SYS_mprotect, start, text->sh_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    printf("Start %lx %lx\n", (uint64_t) start, (uint64_t) end);
    while (da_count(ecall_list) > 0) {
      // syscall_no_intercept(SYS_write, STDOUT_FILENO, "ECALL\n", 6);
      uint64_t addr = da_pop(ecall_list) + (uint64_t) libc_location.addr;
      printf("ecall: %lx\n", addr);
      if (addr < (uint64_t) start || addr > (uint64_t) start + text->sh_size) {
        printf("Ecall not in region\n");
      }
      uint32_t new_ins = create_instruction((uint64_t)(hook_mem - addr) & 0xFFFFF);
      // syscall_no_intercept(SYS_mprotect, round_down_address((unsigned char *)addr), 4, PROT_READ | PROT_WRITE | PROT_EXEC);
      // if (!check_memory_permissions((void *) addr, 'w')) {
      //   printf("No write permission on %lx\n", addr);
      //   exit(EXIT_FAILURE);
      // } else {
      //   printf("Good permissions\n");
      // }
      memcpy((void *) addr, &new_ins, 4);
      // syscall_no_intercept(SYS_mprotect, round_down_address((unsigned char *)addr), 4, PROT_READ | PROT_EXEC);
    }
    
    printf("End\n");
    syscall(SYS_exit, 43);
    syscall_no_intercept(SYS_write, "WROTE\n", 6);
    // syscall_no_intercept(SYS_mprotect, start, text->sh_size, PROT_READ | PROT_EXEC);
  } else syscall_no_intercept(SYS_write, STDOUT_FILENO, "ERROR: Failed to disassemble given code!\n", 39);
  // Cleanup
  // syscall_no_intercept(SYS_munmap, hook_mem, 32);
  return EXIT_SUCCESS;
  /*
   * Iterate over code looking for syscalls and nop regions
   * Create code to jump to (need an assembler?)
   * 
   */
}
