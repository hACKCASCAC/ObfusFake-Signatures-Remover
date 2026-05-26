#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

// Fake sections list
const char *fake_sections[] = {
    ".enigma1", ".enigma2", ".vmp0", ".vmp1", ".vmp2", "UPX0", ".winlice",
    ".petite", ".rlp", ".dsstext", "logicoma", "adr", "have", "30cm", 
    "PETETRIS", ".alien", ".pwdprot", ".tw", ".vlizer", ".aspack", 
    ".adata", "__wibu00", "__wibu01"
};

// Byte patterns
const unsigned char pat_enigma[] = {0x45, 0x6e, 0x69, 0x67, 0x6d, 0x61, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x76, 0x01};
const unsigned char pat_denuvo[] = {0x64, 0x65, 0x6E, 0x75, 0x76, 0x6F, 0x5F, 0x61, 0x74, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const unsigned char pat_nuitka[] = {0x4e, 0x55, 0x49, 0x54, 0x4b, 0x41, 0x5f, 0x4f, 0x4e, 0x45, 0x46, 0x49, 0x4c, 0x45, 0x5f, 0x50, 0x41, 0x52, 0x45, 0x4e, 0x54};
const unsigned char pat_screen2exe[] = {0x56, 0x69, 0x64, 0x65, 0x6f, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x53, 0x43, 0x52, 0x45, 0x45, 0x4e, 0x32, 0x45, 0x58, 0x45, 0x2f, 0x53, 0x43, 0x52, 0x45, 0x45, 0x4e, 0x32, 0x53, 0x57, 0x46};

typedef struct {
    const unsigned char *pattern;
    size_t length;
    const char *name;
} Pattern;

Pattern fake_patterns[] = {
    { pat_enigma, sizeof(pat_enigma), "ENIGMA" },
    { pat_denuvo, sizeof(pat_denuvo), "DENUVO" },
    { pat_nuitka, sizeof(pat_nuitka), "NUITKA" },
    { pat_screen2exe, sizeof(pat_screen2exe), "SCREEN2EXE" }
};

// Fake strings
const char *fake_strings[] = {
    "skeydrv.dll", "HASPDOSDRV", "MARXDEV1.SYS", "MxLPT_Sem",
    "nethasp.ini", "sense4.dll", "SNTNLUSB", "RNBOspro",
    "SSIVDDP.DLL", "WIBUKEY", "\\\\.\\WIZZKEYRL", "\\\\.\\NVKEY"
};

void printHeader() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 11); // CYAN
    printf("   ____  __    ____           ______      __            _____ _                   __                      \n");
    printf("  / __ \\/ /_  / __/_  _______/ ____/___ _/ /_____      / ___/(_)___ _____  ____ _/ /___  __________  _____\n");
    printf(" / / / / __ \\/ /_/ / / / ___/ /_  / __ `/ //_/ _ \\     \\__ \\/ / __ `/ __ \\/ __ `/ __/ / / / ___/ _ \\/ ___/\n");
    printf("/ /_/ / /_/ / __/ /_/ (__  ) __/ / /_/ / ,< /  __/    ___/ / / /_/ / / / / /_/ / /_/ /_/ / /  /  __(__  ) \n");
    printf("\\____/_.___/_/  \\__,_/____/_/    \\__,_/_/|_|\\___/____/____/_/\\__, /_/ /_/\\__,_/\\__/\\__,_/_/   \\___/____/  \n");
    printf("                                               /_____/      /____/                                        \n\n");
    SetConsoleTextAttribute(hConsole, 7); // Reset to default (white/gray)
}

void process_file(const char *filename) {
    FILE *f = fopen(filename, "rb"); 
    if (!f) {
        printf("[-] Failed to open file: %s\n", filename);
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fclose(f);
        return;
    }

    unsigned char *data = (unsigned char *)malloc(size);
    if (!data) {
        printf("[-] Memory allocation error\n");
        fclose(f);
        return;
    }
    
    if (fread(data, 1, size, f) != size) {
        printf("[-] File read error\n");
        free(data);
        fclose(f);
        return;
    }
    fclose(f);

    int matchCount = 0;
    printf("[+] Scanning file: %s (%ld bytes)\n\n", filename, size);

    // 1. Clear fake section names
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)data;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && dos->e_lfanew < size - sizeof(IMAGE_NT_HEADERS)) {
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(data + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
            int num_sections = nt->FileHeader.NumberOfSections;
            
            if ((unsigned char*)(sections + num_sections) <= data + size) {
                for (int i = 0; i < num_sections; i++) {
                    char sec_name[9] = {0};
                    memcpy(sec_name, sections[i].Name, 8);
                    
                    int is_fake = 0;
                    for (int j = 0; j < sizeof(fake_sections) / sizeof(fake_sections[0]); j++) {
                        if (strcmp(sec_name, fake_sections[j]) == 0) {
                            is_fake = 1;
                            break;
                        }
                    }
                    if (is_fake) {
                        printf("[+] Found fake section: %-8s -> renamed to .data\n", sec_name);
                        memset(sections[i].Name, 0, 8); // Имя секции становится полностью пустым
                        matchCount++;
                    }
                }
            }
        }
    }

    // 2. Clear fake patterns and strings
    for (long i = 0; i < size; i++) {
        // Byte patterns
        for (int p = 0; p < sizeof(fake_patterns)/sizeof(fake_patterns[0]); p++) {
            if (i + fake_patterns[p].length <= size) {
                if (memcmp(data + i, fake_patterns[p].pattern, fake_patterns[p].length) == 0) {
                    printf("[+] Found fake pattern %s at offset 0x%08lX\n", fake_patterns[p].name, i);
                    memset(data + i, 0, fake_patterns[p].length);
                    matchCount++;
                }
            }
        }
        
        // Strings
        for (int s = 0; s < sizeof(fake_strings)/sizeof(fake_strings[0]); s++) {
            size_t len = strlen(fake_strings[s]);
            if (i + len <= size) {
                if (memcmp(data + i, fake_strings[s], len) == 0) {
                    printf("[+] Found fake string '%s' at offset 0x%08lX\n", fake_strings[s], i);
                    memset(data + i, 0, len);
                    matchCount++;
                }
            }
        }
    }

    printf("\n[+] Removed %d fake signatures in total.\n", matchCount);

    // 3. Build output filename
    char out_filename[MAX_PATH];
    strncpy(out_filename, filename, MAX_PATH - 15);
    out_filename[MAX_PATH - 15] = '\0';
    
    char *ext = strrchr(out_filename, '.');
    if (ext && stricmp(ext, ".exe") == 0) {
        strcpy(ext, ".unp.exe");
    } else {
        strcat(out_filename, ".unp.exe");
    }

    // Save to new file
    FILE *out = fopen(out_filename, "wb");
    if (!out) {
        printf("[-] Failed to create output file: %s\n", out_filename);
        free(data);
        return;
    }

    fwrite(data, 1, size, out);
    fclose(out);
    free(data);
    
    printf("[*] Done! Result saved as: %s\n", out_filename);
}

int main(int argc, char *argv[]) {
    // Set UTF-8 encoding just in case
    SetConsoleOutputCP(CP_UTF8);

    printHeader();

    if (argc < 2) {
        printf("Usage: %s <path_to_exe>\n", argv[0]);
        return 1;
    }
    
    process_file(argv[1]);
    
    return 0;
}