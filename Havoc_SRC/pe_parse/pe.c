#include <Windows.h>
#include <stdio.h>
#include <stddef.h>

static BOOL range_is_valid(DWORD file_size, DWORD offset, size_t length)
{
    return offset <= file_size && length <= (size_t)(file_size - offset);
}

static BOOL is_power_of_two(DWORD value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

static BOOL are_pe_alignments_valid(const IMAGE_OPTIONAL_HEADER64 *optional_header)
{
    DWORD section_alignment;
    DWORD file_alignment;

    if (optional_header == NULL) {
        return FALSE;
    }

    section_alignment = optional_header->SectionAlignment;
    file_alignment = optional_header->FileAlignment;

    if (section_alignment == 0 || file_alignment == 0 || section_alignment < file_alignment) {
        return FALSE;
    }

    /* For ordinary images, FileAlignment should be a power of two from 512 to 64 KB. */
    if (section_alignment >= 0x1000) {
        return file_alignment >= 0x200 && file_alignment <= 0x10000 &&
            is_power_of_two(file_alignment);
    }

    /* Low-alignment images require file and section alignment to match. */
    return file_alignment == section_alignment;
}

/*for these analytical printf's is temporary until we create the Havoc GUI and put these analytics on specific section.*/

// reading file into memory
BOOL read_file_into_memory(
    LPCSTR file_path,
    BYTE **Buffer,
    DWORD *FileSize)
{
    // INVALID_HANDLE_VALUE : means “no valid file was opened yet.”
    LARGE_INTEGER file_size;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwBytesRead = 0;
    PBYTE pBuffer = NULL;
    DWORD dwFileSize = 0;

    if (Buffer == NULL || FileSize == NULL || file_path == NULL)
    {
        return FALSE;
    }

    *Buffer = NULL;
    *FileSize = 0;

    hFile = CreateFileA(
        file_path,
        GENERIC_READ,    // request read-only access
        FILE_SHARE_READ, // allow other processes to read the file while we have it open
        NULL,
        OPEN_EXISTING, // open the file only if it exists
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error opening file : %lu\n", GetLastError());
        return FALSE;
    }

    if (!GetFileSizeEx(hFile, &file_size))
    {
        printf("Error getting file size : %lu\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    if (file_size.QuadPart <= 0 || file_size.QuadPart > MAXDWORD)
    {
        printf("File is empty or too large for this parser.\n");
        CloseHandle(hFile);
        return FALSE;
    }
    dwFileSize = (DWORD)file_size.QuadPart;
    pBuffer = (PBYTE)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        (SIZE_T)dwFileSize);
    // HEAP_ZERO_MEMORY : fills the allocated memory with zeros

    if (pBuffer == NULL)
    {
        printf("Error to allocate memory : %lu\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL))
    {
        printf("Error reading file : %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pBuffer);
        CloseHandle(hFile);
        return FALSE;
    }

    if (dwBytesRead != dwFileSize)
    {
        printf("Incomplete file read.\n");
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
    PBYTE Buffer,
    DWORD FileSize)
{

    if (Buffer == NULL || FileSize < sizeof(IMAGE_DOS_HEADER))
    {
        printf("File is too small for a DOS header.\n");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Invalid DOS signature. Not a PE file.\n");
        return FALSE;
    }

    printf("[+] DOS Header:\n");
    printf("    e_magic:    0x%X (MZ)\n", pDosHeader->e_magic);
    printf("    e_lfanew:   0x%X (Offset to NT Headers)\n", pDosHeader->e_lfanew);

    return TRUE;
}

BOOL parse_nt_headers(
    PBYTE Buffer,
    DWORD FileSize)
{

    if (Buffer == NULL || FileSize < sizeof(IMAGE_DOS_HEADER))
    {
        printf("File is too small for a DOS header.\n");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pDosHeader->e_lfanew < 0 ||
        !range_is_valid(FileSize, (DWORD)pDosHeader->e_lfanew,
                        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)))
    {
        printf("Invalid or out-of-range NT-header offset.\n");
        return FALSE;
    }
    // we put the headers64 to ensure that we are parsing a 64 bit PE file, if it is not the case we will return an error.
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(Buffer + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid NT signature. Not a PE file.\n");
        return FALSE;
    }

    if (pNtHeaders->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        !range_is_valid(FileSize, (DWORD)pDosHeader->e_lfanew,
                        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                            pNtHeaders->FileHeader.SizeOfOptionalHeader))
    {
        printf("Optional header is incomplete or extends past the file.\n");
        return FALSE;
    }

    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("Unsupported machine type; expected AMD64.\n");
        return FALSE;
    }

    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("Unsupported optional header magic; expected PE32+.\n");
        return FALSE;
    }

    if(
        pNtHeaders->OptionalHeader.SizeOfImage == 0 ||
        pNtHeaders->OptionalHeader.SizeOfHeaders == 0 ||
        pNtHeaders->OptionalHeader.SizeOfHeaders > FileSize ||
        pNtHeaders->OptionalHeader.SizeOfHeaders > pNtHeaders->OptionalHeader.SizeOfImage
    ) {
        printf("invalid image or header size.\n");
        return FALSE;
    }

    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint != 0 &&
        pNtHeaders->OptionalHeader.AddressOfEntryPoint >= pNtHeaders->OptionalHeader.SizeOfImage) {
        printf("Entry point is outside the image.\n");
        return FALSE;
    }

    if (!are_pe_alignments_valid(&pNtHeaders->OptionalHeader)) {
        printf("Invalid SectionAlignment or FileAlignment values.\n");
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
           pNtHeaders->OptionalHeader.Magic == 0x20B ? "64-bit" : "32-bit");
    printf("    AddressOfEntryPoint:  0x%X\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("    ImageBase:            0x%llX\n", pNtHeaders->OptionalHeader.ImageBase);
    printf("    SizeOfImage:          0x%X\n", pNtHeaders->OptionalHeader.SizeOfImage);

    return TRUE;
}

BOOL parse_sections(
    PBYTE Buffer,
    DWORD FileSize)
{

    if (Buffer == NULL || FileSize < sizeof(IMAGE_DOS_HEADER))
    {
        printf("File is too small for a DOS header.\n");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)Buffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pDosHeader->e_lfanew < 0 ||
        !range_is_valid(FileSize, (DWORD)pDosHeader->e_lfanew,
                        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)))
    {
        printf("Invalid or out-of-range NT-header offset.\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(Buffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE ||
        pNtHeaders->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        !range_is_valid(FileSize, (DWORD)pDosHeader->e_lfanew,
                        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                            pNtHeaders->FileHeader.SizeOfOptionalHeader))
    {
        printf("Invalid or incomplete NT headers.\n");
        return FALSE;
    }

    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        pNtHeaders->OptionalHeader.SizeOfHeaders == 0 ||
        pNtHeaders->OptionalHeader.SizeOfHeaders > FileSize ||
        pNtHeaders->OptionalHeader.SizeOfImage == 0 ||
        !are_pe_alignments_valid(&pNtHeaders->OptionalHeader)) {
        printf("Invalid or unsupported x64 image metadata.\n");
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    size_t section_table_offset = (size_t)((BYTE *)pSectionHeader - Buffer);
    size_t section_count = pNtHeaders->FileHeader.NumberOfSections;
    if (section_table_offset > FileSize ||
        section_count > ((size_t)FileSize - section_table_offset) / sizeof(IMAGE_SECTION_HEADER))
    {
        printf("Section table extends past the end of the file.\n");
        return FALSE;
    }

    if(section_table_offset > pNtHeaders->OptionalHeader.SizeOfHeaders || 
        section_count > ((size_t)pNtHeaders->OptionalHeader.SizeOfHeaders - section_table_offset) / sizeof(IMAGE_SECTION_HEADER)
    ) {
        printf("Section table is located outside the headers.\n");
        return FALSE;
    }

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {

        DWORD section_span = pSectionHeader[i].Misc.VirtualSize;

        if(pSectionHeader[i].SizeOfRawData > section_span) {
            section_span = pSectionHeader[i].SizeOfRawData;
        }

        ULONGLONG section_end = (ULONGLONG)pSectionHeader[i].VirtualAddress + section_span;

        if(section_end > pNtHeaders->OptionalHeader.SizeOfImage) {
            printf("Section %d extends past the end of the image.\n", i + 1);
            return FALSE;
        }

        if (pSectionHeader[i].VirtualAddress % pNtHeaders->OptionalHeader.SectionAlignment != 0) {
            printf("Section %d virtual address is not section-aligned.\n", i + 1);
            return FALSE;
        }
        // Check raw data alignment and range
        if (pSectionHeader[i].SizeOfRawData != 0) {
            if (!range_is_valid(FileSize,
                                pSectionHeader[i].PointerToRawData,
                                pSectionHeader[i].SizeOfRawData)) {
                printf("Section %d extends past the end of the file.\n", i + 1);
                return FALSE;
            }
            if (pSectionHeader[i].PointerToRawData < pNtHeaders->OptionalHeader.SizeOfHeaders ||
                pSectionHeader[i].PointerToRawData % pNtHeaders->OptionalHeader.FileAlignment != 0 ||
                pSectionHeader[i].SizeOfRawData % pNtHeaders->OptionalHeader.FileAlignment != 0) {
                printf("Section %d raw range is not validly aligned or overlaps headers.\n", i + 1);
                return FALSE;
            }
        }

        printf("[+] Section %d:\n", i + 1);
        printf("    Name:                 %.8s\n", pSectionHeader[i].Name);
        printf("    VirtualAddress:       0x%X\n", pSectionHeader[i].VirtualAddress);
        printf("    SizeOfRawData:        0x%X\n", pSectionHeader[i].SizeOfRawData);
        printf("    PointerToRawData:     0x%X\n", pSectionHeader[i].PointerToRawData);
        printf("    Characteristics:      0x%X\n", pSectionHeader[i].Characteristics);
    }
    
    // Overlap check for sections with each other
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        ULONGLONG i_virtual_start = pSectionHeader[i].VirtualAddress;
        ULONGLONG i_virtual_size = pSectionHeader[i].Misc.VirtualSize > pSectionHeader[i].SizeOfRawData
            ? pSectionHeader[i].Misc.VirtualSize : pSectionHeader[i].SizeOfRawData;
        ULONGLONG i_raw_start = pSectionHeader[i].PointerToRawData;
        ULONGLONG i_raw_size = pSectionHeader[i].SizeOfRawData;

        for (int j = i + 1; j < pNtHeaders->FileHeader.NumberOfSections; ++j) {
            ULONGLONG j_virtual_start = pSectionHeader[j].VirtualAddress;
            ULONGLONG j_virtual_size = pSectionHeader[j].Misc.VirtualSize > pSectionHeader[j].SizeOfRawData
                ? pSectionHeader[j].Misc.VirtualSize : pSectionHeader[j].SizeOfRawData;
            ULONGLONG j_raw_start = pSectionHeader[j].PointerToRawData;
            ULONGLONG j_raw_size = pSectionHeader[j].SizeOfRawData;

            BOOL virtual_overlap = i_virtual_size != 0 && j_virtual_size != 0 &&
                i_virtual_start < j_virtual_start + j_virtual_size &&
                j_virtual_start < i_virtual_start + i_virtual_size;
            BOOL raw_overlap = i_raw_size != 0 && j_raw_size != 0 &&
                i_raw_start < j_raw_start + j_raw_size &&
                j_raw_start < i_raw_start + i_raw_size;

            if (virtual_overlap || raw_overlap) {
                printf("Sections %d and %d overlap.\n", i + 1, j + 1);
                return FALSE;
            }
        }
    }

    return TRUE;
}

// for testing
int main(int argc, char *argv[])
{

    PBYTE Buffer = NULL;
    DWORD FileSize = 0;
    int exit_code = 1;

    if (argc != 2)
    {
        printf("Usage: %s <path_to_pe_file>\n", argv[0]);
        return 1;
    }

    if (!read_file_into_memory(argv[1], &Buffer, &FileSize))
    {
        return 1;
    }

    if (!parse_dos_file(Buffer, FileSize))
    {
        goto Cleanup;
    }

    if (!parse_nt_headers(Buffer, FileSize))
    {
        goto Cleanup;
    }

    if (!parse_sections(Buffer, FileSize))
    {
        goto Cleanup;
    }
    exit_code = 0;

Cleanup:
    if (Buffer)
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
    }
    return exit_code;
}
