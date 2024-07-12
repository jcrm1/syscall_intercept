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
#include <sys/syscall.h>

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
  return strcmp(ins.mnemonic, "c.nop") == 0;
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

  printf("File mem: %p\n", file_mem);

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
  if (count > 0) {
    unsigned long slide_len = 0;
    for (size_t j = 0; j < count; j++) {
      if (is_nop(insn[j])) slide_len++;
      else {
        if (slide_len > 0) printf("NOP slide end: %ld\n", slide_len);
        slide_len = 0;
      }
      printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
    }
  } else printf("ERROR: Failed to disassemble given code!\n");
  cs_close(&handle);
  return EXIT_SUCCESS;
}
