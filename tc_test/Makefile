# Compiler and flags
CC = clang
CFLAGS = -g -O2 -target bpf -I/usr/include/bpf

# Files
EBPF_SRC = tc_test.c
EBPF_OBJ = tc_test.o
PYTHON_SCRIPT = tc_test.py

# Default target
all: $(EBPF_OBJ) run

# Compile the eBPF program
$(EBPF_OBJ): $(EBPF_SRC)
	$(CC) $(CFLAGS) -c $(EBPF_SRC) -o $(EBPF_OBJ)

# Run the Python script
run:
	python3 $(PYTHON_SCRIPT)

# Clean up generated files
clean:
	rm -f $(EBPF_OBJ)
