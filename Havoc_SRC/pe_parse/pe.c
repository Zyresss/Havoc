#include <Windows.h>
#include <stdio.h>

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
        printf("Error opening file : %Lu\n", GetLastError());
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