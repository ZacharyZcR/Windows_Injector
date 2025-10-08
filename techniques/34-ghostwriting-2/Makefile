# Ghostwriting-2 Makefile
# Requires 32-bit MinGW compiler (i686-w64-mingw32-gcc)

CC32 = i686-w64-mingw32-gcc
CFLAGS = -Wall
TARGET = build/ghost.exe

all: $(TARGET)

$(TARGET): ghost.c helpers.h shellcode.h
	@mkdir -p build
	$(CC32) $(CFLAGS) ghost.c -o $(TARGET)
	@echo "Build complete: $(TARGET)"

clean:
	rm -rf build

test: $(TARGET)
	@echo "Usage: $(TARGET) [thread_id]"
	@echo "First, find a target thread ID using Process Explorer or similar tools"

.PHONY: all clean test
