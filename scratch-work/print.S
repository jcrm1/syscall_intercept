.section .text
print_msg:
  # addi sp, sp, -16
  # sd ra, 0(sp)
  # la a0, msg
  # mv a1, a0
  # li a0, 1
  # li a2, 16
  # li a7, 64
  # ecall
  # ld ra, 0(sp)
  # addi sp, sp, 16
  # write something to create a file
  addi sp, sp, -16
  li a0, 0x616200 # "ab\0"
  sd a0, 0(sp) 
  mv a1, sp
  li a0, -1000
  li a2, 65
  li a3, 0644
  li a7, 56 # openat
  ecall
  li a7, 57 # close # need to recompile and get bytes from scratch from xelfviewer
  ecall
  addi sp, sp, 16
  li a0, 69
  li a7, 93 # exit
  ecall
# .section .rodata
# msg: .string "Assembly rocks!\n"
