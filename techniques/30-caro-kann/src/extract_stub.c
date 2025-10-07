#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This program extracts the .text section from decrypt_stub.exe to create decrypt_stub.bin

int main(int argc, char* argv[]) {
    printf("[+] Decrypt Stub Extractor\n\n");

    if (argc != 3) {
        printf("Usage: %s <decrypt_stub.exe> <output.bin>\n", argv[0]);
        printf("\n");
        printf("Example:\n");
        printf("  %s decrypt_stub.exe decrypt_stub.bin\n", argv[0]);
        printf("\n");
        printf("This tool extracts the .text section from the compiled\n");
        printf("decrypt stub to create position-independent shellcode.\n");
        return 1;
    }

    const char* inputFile = argv[1];
    const char* outputFile = argv[2];

    FILE* fin = fopen(inputFile, "rb");
    if (fin == NULL) {
        printf("[-] Failed to open input file: %s\n", inputFile);
        return 1;
    }

    // Read entire file
    fseek(fin, 0, SEEK_END);
    size_t fileSize = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    unsigned char* fileData = (unsigned char*)malloc(fileSize);
    if (fileData == NULL) {
        printf("[-] Failed to allocate memory\n");
        fclose(fin);
        return 1;
    }

    fread(fileData, 1, fileSize, fin);
    fclose(fin);

    printf("[+] Loaded PE file: %zu bytes\n", fileSize);

    // Parse PE header
    if (fileData[0] != 'M' || fileData[1] != 'Z') {
        printf("[-] Invalid PE file (missing MZ signature)\n");
        free(fileData);
        return 1;
    }

    unsigned int peOffset = *(unsigned int*)(&fileData[0x3C]);
    if (peOffset >= fileSize || fileData[peOffset] != 'P' || fileData[peOffset + 1] != 'E') {
        printf("[-] Invalid PE file (missing PE signature)\n");
        free(fileData);
        return 1;
    }

    printf("[+] PE signature found at offset: 0x%X\n", peOffset);

    // Get number of sections
    unsigned short numberOfSections = *(unsigned short*)(&fileData[peOffset + 6]);
    printf("[+] Number of sections: %d\n", numberOfSections);

    // Optional header size
    unsigned short sizeOfOptionalHeader = *(unsigned short*)(&fileData[peOffset + 20]);
    unsigned int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;

    printf("[+] Section table offset: 0x%X\n", sectionTableOffset);

    // Find .text section
    for (int i = 0; i < numberOfSections; i++) {
        unsigned int sectionOffset = sectionTableOffset + (i * 40);

        char sectionName[9] = {0};
        memcpy(sectionName, &fileData[sectionOffset], 8);

        if (strcmp(sectionName, ".text") == 0) {
            unsigned int virtualSize = *(unsigned int*)(&fileData[sectionOffset + 8]);
            unsigned int rawSize = *(unsigned int*)(&fileData[sectionOffset + 16]);
            unsigned int rawOffset = *(unsigned int*)(&fileData[sectionOffset + 20]);

            printf("[+] Found .text section:\n");
            printf("    Virtual Size: 0x%X\n", virtualSize);
            printf("    Raw Size: 0x%X\n", rawSize);
            printf("    Raw Offset: 0x%X\n", rawOffset);

            // Extract .text section
            FILE* fout = fopen(outputFile, "wb");
            if (fout == NULL) {
                printf("[-] Failed to open output file: %s\n", outputFile);
                free(fileData);
                return 1;
            }

            fwrite(&fileData[rawOffset], 1, rawSize, fout);
            fclose(fout);

            printf("[+] Extracted .text section to: %s\n", outputFile);
            printf("[+] Size: %d bytes\n", rawSize);

            free(fileData);
            return 0;
        }
    }

    printf("[-] .text section not found\n");
    free(fileData);
    return 1;
}
