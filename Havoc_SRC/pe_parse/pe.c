#include <Windows.h>
#include <stdio.h>

/*for these analytical printf's is temporary until we create the Havoc GUI and put these analytics on specific section.*/

// reading file into memory 
BOOL read_file_into_memory(
    LPCSTR file_path,
    BYTE **Buffer,
    DWORD *FileSize
) {
    // INVALID_HANDLE_VALUE : means “no valid file was opened yet.”
    HANDLE hFile       = INVALID_HANDLE_VALUE;
    DWORD  dwBytesRead = 0;
    PBYTE  pBuffer     = NULL;
    DWORD  dwFileSize  = 0;

    hFile = CreateFileA(
        file_path,
        GENERIC_READ, // request read-only access
        FILE_SHARE_READ, // allow other processes to read the file while we have it open
        NULL,
        OPEN_EXISTING, // open the file only if it exists
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file : %lu\n", GetLastError());
        return FALSE;
    }

    dwFileSize = GetFileSize(hFile, NULL);
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
    //HEAP_ZERO_MEMORY : fills the allocated memory with zeros

    if(pBuffer == NULL) {
        printf("Error to allocate memory : %lu\n" , GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    if(!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL)) {
        printf("Error reading file : %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pBuffer);
        CloseHandle(hFile);
        return FALSE;
    }

    *Buffer = pBuffer;
    *FileSize = dwFileSize;

    CloseHandle(hFile);
    return TRUE;
}

BOOL parse_dos_file(
    PBYTE Buffer
) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature. Not a PE file.\n");
        return FALSE;
    }
    
    printf("[+] DOS Header:\n");
    printf("    e_magic:    0x%X (MZ)\n", pDosHeader->e_magic);
    printf("    e_lfanew:   0x%X (Offset to NT Headers)\n", pDosHeader->e_lfanew);

    return TRUE;
}

BOOL parse_nt_headers(
    PBYTE Buffer
) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(Buffer + pDosHeader->e_lfanew);

    if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature. Not a PE file.\n");
        return FALSE;
    }

    printf("[+] NT Headers:\n");
    printf("    Signature:  0x%X (PE00)\n", pNtHeaders->Signature);
    
     printf("[+] File Header:\n");
    printf("    Machine:              0x%X\n", pNtHeaders->FileHeader.Machine);
    printf("    NumberOfSections:     %d\n", pNtHeaders->FileHeader.NumberOfSections);
    printf("    TimeDateStamp:        0x%X\n", pNtHeaders->FileHeader.TimeDateStamp);
    printf("    Characteristics:      0x%X\n", pNtHeaders->FileHeader.Characteristics);

    printf("[+] Optional Header:\n");
    printf("    Magic:                0x%X (%s)\n", 
        pNtHeaders->OptionalHeader.Magic,
        pNtHeaders->OptionalHeader.Magic == 0x20B ? "64-bit" : "32-bit"
    );
    printf("    AddressOfEntryPoint:  0x%X\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("    ImageBase:            0x%llX\n", pNtHeaders->OptionalHeader.ImageBase);
    printf("    SizeOfImage:          0x%X\n", pNtHeaders->OptionalHeader.SizeOfImage);

    return TRUE;
}

VOID parse_sections(
    PBYTE Buffer
) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(Buffer + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for(int i=0 ; i < pNtHeaders->FileHeader.NumberOfSections ; i++) {
        printf("[+] Section %d:\n", i + 1);
        printf("    Name:                 %.8s\n", pSectionHeader[i].Name);
        printf("    VirtualAddress:       0x%X\n", pSectionHeader[i].VirtualAddress);
        printf("    SizeOfRawData:        0x%X\n", pSectionHeader[i].SizeOfRawData);
        printf("    PointerToRawData:     0x%X\n", pSectionHeader[i].PointerToRawData);
        printf("    Characteristics:      0x%X\n", pSectionHeader[i].Characteristics);
    }
}

// for testing
int main(int argc, char *argv[]) {
    
    PBYTE Buffer = NULL;
    DWORD FileSize = 0;

    if(argc != 2) {
        printf("Usage: %s <path_to_pe_file>\n", argv[0]);
        return 1;
    }


    if(!read_file_into_memory(argv[1], &Buffer, &FileSize)) {
        return 1;
    }

    if(!parse_dos_file(Buffer)) {
        goto Cleanup;
    }

    if(!parse_nt_headers(Buffer)) {
        goto Cleanup;
    }

    parse_sections(Buffer);

Cleanup:
    if(Buffer) {
        HeapFree(GetProcessHeap(), 0, Buffer);
    }
    return 0;
}