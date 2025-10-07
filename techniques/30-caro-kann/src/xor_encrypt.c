#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XOR_KEY 0x04030201

void XorEncrypt(unsigned char* data, size_t size) {
    unsigned int* data32 = (unsigned int*)data;
    unsigned int key = XOR_KEY;

    // XOR 4 bytes at a time
    size_t fullBlocks = size / 4;
    for (size_t i = 0; i < fullBlocks; i++) {
        data32[i] ^= key;
    }

    // XOR remaining bytes
    for (size_t i = fullBlocks * 4; i < size; i++) {
        data[i] ^= (unsigned char)(key & 0xFF);
    }
}

int main(int argc, char* argv[]) {
    printf("[+] XOR Encryptor for Caro-Kann\n");
    printf("[+] XOR Key: 0x%08X\n\n", XOR_KEY);

    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        printf("\n");
        printf("Example:\n");
        printf("  %s calc_shellcode.bin calc_encrypted.bin\n", argv[0]);
        return 1;
    }

    const char* inputFile = argv[1];
    const char* outputFile = argv[2];

    // Read input file
    FILE* fin = fopen(inputFile, "rb");
    if (fin == NULL) {
        printf("[-] Failed to open input file: %s\n", inputFile);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    size_t size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    unsigned char* data = (unsigned char*)malloc(size);
    if (data == NULL) {
        printf("[-] Failed to allocate memory\n");
        fclose(fin);
        return 1;
    }

    size_t bytesRead = fread(data, 1, size, fin);
    if (bytesRead != size) {
        printf("[-] Failed to read file\n");
        free(data);
        fclose(fin);
        return 1;
    }
    fclose(fin);

    printf("[+] Loaded input file: %zu bytes\n", size);

    // Encrypt data
    XorEncrypt(data, size);
    printf("[+] Encrypted data using XOR key: 0x%08X\n", XOR_KEY);

    // Write output file
    FILE* fout = fopen(outputFile, "wb");
    if (fout == NULL) {
        printf("[-] Failed to open output file: %s\n", outputFile);
        free(data);
        return 1;
    }

    size_t bytesWritten = fwrite(data, 1, size, fout);
    if (bytesWritten != size) {
        printf("[-] Failed to write file\n");
        free(data);
        fclose(fout);
        return 1;
    }
    fclose(fout);

    printf("[+] Wrote encrypted file: %zu bytes\n", bytesWritten);
    printf("[+] Output: %s\n", outputFile);
    printf("\n[+] Encryption successful!\n");

    free(data);
    return 0;
}
