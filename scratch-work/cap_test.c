#include <capstone.h>
// #define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
const uint8_t data[4] = {
    0x93, 0x08, 0x80, 0x03
};
int main() {
  csh handle;
  cs_insn *insn;
  size_t count;
  if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCVC, &handle) != CS_ERR_OK) return EXIT_FAILURE;
	count = cs_disasm(handle, data, 4, 0, 1, &insn);
  if (count > 0) {
    for (size_t j = 0; j < count; j++) {
      printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
    }
  } else printf("ERROR: Failed to disassemble given code!\n");
  cs_close(&handle);
  return EXIT_SUCCESS;
}
