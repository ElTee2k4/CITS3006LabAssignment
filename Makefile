# Makefile for compiling C files with custom output filename

# Default output filename
OUTPUT = server

# Compiler and flags
CC = gcc
CFLAGS = -fno-stack-protector -z execstack -no-pie -m32 -Wno-error=implicit-function-declaration

# Target to build the executable
all: $(OUTPUT)

$(OUTPUT): $(OUTPUT).c
	$(CC) $(OUTPUT).c -o $(OUTPUT) $(CFLAGS)

# Clean up build files
clean:
	rm -f $(OUTPUT)

.PHONY: all clean
