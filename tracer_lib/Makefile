# TBMI Sandbox - ELF Tracer Library Makefile
#
# Компиляция shared libraries для LD_PRELOAD трейсинга
#
# Использование:
#   make all    - собрать обе архитектуры (требует multilib)
#   make x64    - собрать только x86_64
#   make x86    - собрать только i386
#   make clean  - удалить скомпилированные файлы

CC = gcc
CFLAGS = -shared -fPIC -Wall -Wextra -O2
LDFLAGS = -ldl

# Source files
SRC = tracer.c

# Output files
LIB_X64 = libtracer_x64.so
LIB_X86 = libtracer_x86.so

.PHONY: all x64 x86 clean help

# Default: build only x64 (most common)
all: x64

# Build x86_64 version
x64: $(LIB_X64)

$(LIB_X64): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built $(LIB_X64) for x86_64"

# Build i386 version (requires gcc-multilib)
x86: $(LIB_X86)

$(LIB_X86): $(SRC)
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built $(LIB_X86) for i386"

# Build both architectures
both: x64 x86

# Clean compiled files
clean:
	rm -f $(LIB_X64) $(LIB_X86)
	@echo "Cleaned tracer libraries"

# Help
help:
	@echo "TBMI Sandbox - ELF Tracer Library"
	@echo ""
	@echo "Targets:"
	@echo "  all   - Build x64 library (default)"
	@echo "  x64   - Build x86_64 library"
	@echo "  x86   - Build i386 library (requires gcc-multilib)"
	@echo "  both  - Build both architectures"
	@echo "  clean - Remove compiled libraries"
	@echo ""
	@echo "Requirements:"
	@echo "  - gcc"
	@echo "  - For x86: gcc-multilib (apt install gcc-multilib)"

