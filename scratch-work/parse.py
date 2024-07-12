with open("fixed_cap_riscv_libc", "r") as file:
  lines = [line.strip().rstrip() for line in file.readlines()]
largest = 0
largestidx = -1
for idx, line in enumerate(lines):
  if line.startswith("NOP slide end: "):
    num = int(line[14:])
    if num > largest:
      largest = num
      largestidx = idx
print(largest)
print(largestidx)

count = 0
for line in lines:
  if "ecall" in line:
    count += 1
print(count)
