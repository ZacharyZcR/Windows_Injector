cmake_minimum_required(VERSION 3.10)
project(Ghostwriting2 C)

set(CMAKE_C_STANDARD 11)

# This technique requires 32-bit (x86) architecture
# Current project uses x64 by default, so we keep the original source as reference
# Compile with: i686-w64-mingw32-gcc ghost.c -o build/ghost.exe

message(WARNING "Ghostwriting-2 requires 32-bit compilation. Use the provided Makefile or compile manually with i686-w64-mingw32-gcc")
