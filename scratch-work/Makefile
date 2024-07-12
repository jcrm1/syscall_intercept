CC=gcc
RISCV_CC=riscv64-unknown-linux-gnu-gcc
CFLAGS=-I. -I/usr/include/capstone
DEPS = 
SHOBJ = 
EXE = cap_test cap_file_test

all: clean $(SHOBJ) $(EXE)

%.so: $(DEPS)
	$(CC) $*.c -fpic -g -shared -o $@

%: %.c $(DEPS)
	$(CC) -o $@ $< $(CFLAGS) -lcapstone -g

elf_test: elf_test.c $(DEPS)
	$(RISCV_CC) -o $@ $< tutil.S $(CFLAGS) -lcapstone -g

clean:
	rm -f $(SHOBJ) $(EXE)
