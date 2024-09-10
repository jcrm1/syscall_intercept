## Requirements
- [x] Iterate over instructions
- [x] Determine which instructions are ecalls
- [x] Determine which instructions are nops
	- [ ] and replace them with jalr trampoline where appropriate
- [ ] Replace instructions in place
- [ ] Save instructions for later use
- [ ] Examine instructions preceding ecalls
- [ ] If we need to jump more than 2^12 bytes, then check:
1. [x] Is the preceding instruction affected by the pc? i.e. auipc. If no, relocate
2. [ ] Otherwise, jump to a trampoline series
- [ ] Calculate 32 bit offset and split into upper 20 and lower 12 bits
- [ ] Assembly template that will:
3. [ ] Save registers to the stack.
4. [ ] Jump to the user intercept code and allow it to return.
5. [ ] Restore registers from the stack.
6. [ ] Set the return value, if desired by the user intercept code.
7. [ ] Execute the relocated instruction if present. Otherwise, default to a nop
- [ ] instruction.
8. [ ] Return to the original ecall location.
- [ ] Ability to copy and modify assembly template
- [ ] Ability to create a series of copies of said template in memory

## pc-relative instructions:
```
auipc
jal
jalr
beq
bne
blt
bge
bltu
bgeu
c.jr
c.jalr
```
## sp-dependent instructions:
```
c.addi4spn
c.addi16sp
c.fldsp
c.lwsp
c.flwsp
c.ldsp
c.fsdsp
c.swsp
c.fswsp
c.sdsp
```
