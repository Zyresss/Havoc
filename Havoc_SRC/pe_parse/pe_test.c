#include "pe.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void pe64_set_error(pe64 *pe, const char *message)
{
    if (pe == NULL) {
        return;
    }

    strncpy(pe->error, message, sizeof(pe->error) - 1);
    pe->error[sizeof(pe->error) - 1] = '\0';
}

static int pe64_add_size(size_t left, size_t right, size_t *result)
{
    if (right > SIZE_MAX - left) {
        return 0;
    }

    *result = left + right;
    return 1;
}

static int pe64_range_is_valid(size_t offset, size_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static void pe64_release_allocations(pe64 *pe)
{
    free(pe->buffer);
    free(pe->buffer_not_relocated);
    free(pe->path);
    pe->buffer = NULL;
    pe->buffer_not_relocated = NULL;
    pe->path = NULL;
    pe->buffer_size = 0;
    pe->raw_size = 0;
}

static PIMAGE_SECTION_HEADER pe64_first_section(pe64 *pe)
{
    PIMAGE_NT_HEADERS64 nt = pe64_get_nt(pe);
    size_t optional_offset;

    if (nt == NULL || !pe64_add_size((size_t)((uint8_t *)&nt->OptionalHeader - pe->buffer),
                                     nt->FileHeader.SizeOfOptionalHeader,
                                     &optional_offset) ||
        !pe64_range_is_valid(optional_offset,
                              (size_t)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
                              pe->buffer_size)) {
        return NULL;
    }

    return (PIMAGE_SECTION_HEADER)(pe->buffer + optional_offset);
}

static int pe64_name_equals(const IMAGE_SECTION_HEADER *section, const char *name)
{
    size_t name_length;
    size_t i;

    if (section == NULL || name == NULL) {
        return 0;
    }

    name_length = strlen(name);
    if (name_length > IMAGE_SIZEOF_SHORT_NAME) {
        return 0;
    }

    for (i = 0; i < IMAGE_SIZEOF_SHORT_NAME; ++i) {
        unsigned char left = section->Name[i];
        unsigned char right = i < name_length ? (unsigned char)name[i] : 0;

        if (tolower(left) != tolower(right)) {
            return 0;
        }
    }

    return 1;
}

uint32_t pe64_align(uint32_t address, uint32_t alignment)
{
    uint64_t aligned;

    if (alignment == 0) {
        return 0;
    }

    aligned = ((uint64_t)address + alignment - 1u) / alignment * alignment;
    return aligned > UINT32_MAX ? 0 : (uint32_t)aligned;
}

int pe64_open(pe64 *pe, const char *binary_path)
{
    FILE *stream;
    long input_length;
    size_t bytes_read;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_SECTION_HEADER sections;
    size_t section_table_offset;
    size_t i;

    if (pe == NULL || binary_path == NULL || binary_path[0] == '\0') {
        return 0;
    }

    memset(pe, 0, sizeof(*pe));
    stream = fopen(binary_path, "rb");
    if (stream == NULL) {
        pe64_set_error(pe, "could not open input binary");
        return 0;
    }

    if (fseek(stream, 0, SEEK_END) != 0 || (input_length = ftell(stream)) < 0 ||
        fseek(stream, 0, SEEK_SET) != 0 || input_length == 0) {
        fclose(stream);
        pe64_set_error(pe, "could not determine input binary size");
        return 0;
    }

    pe->raw_size = (size_t)input_length;
    pe->buffer_not_relocated = (uint8_t *)malloc(pe->raw_size);
    if (pe->buffer_not_relocated == NULL) {
        fclose(stream);
        pe64_set_error(pe, "out of memory while reading input binary");
        return 0;
    }

    bytes_read = fread(pe->buffer_not_relocated, 1, pe->raw_size, stream);
    fclose(stream);
    if (bytes_read != pe->raw_size) {
        pe64_set_error(pe, "could not read input binary");
        pe64_release_allocations(pe);
        return 0;
    }

    if (!pe64_range_is_valid(0, sizeof(IMAGE_DOS_HEADER), pe->raw_size)) {
        pe64_set_error(pe, "input binary is too small for a DOS header");
        pe64_release_allocations(pe);
        return 0;
    }

    dos = (PIMAGE_DOS_HEADER)pe->buffer_not_relocated;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        !pe64_range_is_valid((size_t)dos->e_lfanew, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), pe->raw_size)) {
        pe64_set_error(pe, "input binary is not a valid PE file");
        pe64_release_allocations(pe);
        return 0;
    }

    nt = (PIMAGE_NT_HEADERS64)(pe->buffer_not_relocated + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        !pe64_range_is_valid((size_t)dos->e_lfanew,
                              sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader,
                              pe->raw_size) ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.SizeOfImage == 0 || nt->OptionalHeader.SizeOfHeaders == 0 ||
        nt->OptionalHeader.SizeOfHeaders > pe->raw_size ||
        nt->OptionalHeader.SizeOfHeaders > nt->OptionalHeader.SizeOfImage) {
        pe64_set_error(pe, "input binary is not a supported AMD64 PE file");
        pe64_release_allocations(pe);
        return 0;
    }

    section_table_offset = (size_t)((uint8_t *)IMAGE_FIRST_SECTION(nt) - pe->buffer_not_relocated);
    if (!pe64_range_is_valid(section_table_offset,
                              (size_t)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
                              pe->raw_size)) {
        pe64_set_error(pe, "input binary has an invalid section table");
        pe64_release_allocations(pe);
        return 0;
    }

    pe->buffer_size = nt->OptionalHeader.SizeOfImage;
    pe->buffer = (uint8_t *)calloc(1, pe->buffer_size);
    if (pe->buffer == NULL) {
        pe64_set_error(pe, "out of memory while mapping input binary");
        pe64_release_allocations(pe);
        return 0;
    }

    memcpy(pe->buffer, pe->buffer_not_relocated, nt->OptionalHeader.SizeOfHeaders);
    sections = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        size_t raw_size = sections[i].SizeOfRawData;
        size_t raw_offset = sections[i].PointerToRawData;
        size_t virtual_offset = sections[i].VirtualAddress;

        if (!pe64_range_is_valid(raw_offset, raw_size, pe->raw_size) ||
            !pe64_range_is_valid(virtual_offset, raw_size, pe->buffer_size)) {
            pe64_set_error(pe, "input binary contains an invalid section range");
            pe64_release_allocations(pe);
            return 0;
        }

        if (raw_size != 0) {
            memcpy(pe->buffer + virtual_offset, pe->buffer_not_relocated + raw_offset, raw_size);
        }
    }

    pe->path = (char *)malloc(strlen(binary_path) + 1);
    if (pe->path == NULL) {
        pe64_set_error(pe, "out of memory while storing input path");
        pe64_release_allocations(pe);
        return 0;
    }
    strcpy(pe->path, binary_path);
    pe->error[0] = '\0';
    return 1;
}

void pe64_destroy(pe64 *pe)
{
    if (pe == NULL) {
        return;
    }

    pe64_release_allocations(pe);
    memset(pe, 0, sizeof(*pe));
}

const char *pe64_error(const pe64 *pe)
{
    return pe == NULL ? "invalid PE handle" : pe->error;
}

uint8_t *pe64_get_buffer(pe64 *pe)
{
    return pe == NULL ? NULL : pe->buffer;
}

const uint8_t *pe64_get_buffer_not_relocated(const pe64 *pe)
{
    return pe == NULL ? NULL : pe->buffer_not_relocated;
}

PIMAGE_NT_HEADERS64 pe64_get_nt(pe64 *pe)
{
    PIMAGE_DOS_HEADER dos;

    if (pe == NULL || pe->buffer == NULL || pe->buffer_size < sizeof(IMAGE_DOS_HEADER)) {
        return NULL;
    }

    dos = (PIMAGE_DOS_HEADER)pe->buffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        !pe64_range_is_valid((size_t)dos->e_lfanew,
                              sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64),
                              pe->buffer_size)) {
        return NULL;
    }

    return (PIMAGE_NT_HEADERS64)(pe->buffer + dos->e_lfanew);
}

PIMAGE_SECTION_HEADER pe64_get_section(pe64 *pe, const char *section_name)
{
    PIMAGE_NT_HEADERS64 nt = pe64_get_nt(pe);
    PIMAGE_SECTION_HEADER sections = pe64_first_section(pe);
    size_t i;

    if (nt == NULL || sections == NULL) {
        return NULL;
    }

    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (pe64_name_equals(&sections[i], section_name)) {
            return &sections[i];
        }
    }

    return NULL;
}

PIMAGE_SECTION_HEADER pe64_create_section(
    pe64 *pe, const char *name, uint32_t size, uint32_t characteristics)
{
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_SECTION_HEADER sections;
    size_t name_length;
    size_t i;
    uint32_t virtual_end = 0;
    uint32_t raw_end = 0;
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t virtual_address;
    uint32_t raw_address;
    uint32_t image_size;
    uint8_t *resized;

    if (pe == NULL || name == NULL || (name_length = strlen(name)) > IMAGE_SIZEOF_SHORT_NAME) {
        pe64_set_error(pe, "section name must be at most eight characters");
        return NULL;
    }

    nt = pe64_get_nt(pe);
    sections = pe64_first_section(pe);
    if (nt == NULL || sections == NULL || nt->FileHeader.NumberOfSections == 0 ||
        nt->OptionalHeader.SectionAlignment == 0 || nt->OptionalHeader.FileAlignment == 0) {
        pe64_set_error(pe, "PE image cannot accept a new section");
        return NULL;
    }

    if (!pe64_range_is_valid((size_t)((uint8_t *)&sections[nt->FileHeader.NumberOfSections] - pe->buffer),
                              sizeof(IMAGE_SECTION_HEADER), nt->OptionalHeader.SizeOfHeaders)) {
        pe64_set_error(pe, "PE headers have no room for another section");
        return NULL;
    }

    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t mapped_size = sections[i].Misc.VirtualSize > sections[i].SizeOfRawData
            ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        uint32_t current_virtual_end = sections[i].VirtualAddress + mapped_size;
        uint32_t current_raw_end = sections[i].PointerToRawData + sections[i].SizeOfRawData;

        if (current_virtual_end < sections[i].VirtualAddress || current_raw_end < sections[i].PointerToRawData) {
            pe64_set_error(pe, "PE image has overflowing section bounds");
            return NULL;
        }
        if (current_virtual_end > virtual_end) virtual_end = current_virtual_end;
        if (current_raw_end > raw_end) raw_end = current_raw_end;
    }

    virtual_size = size;
    raw_size = pe64_align(size, nt->OptionalHeader.FileAlignment);
    virtual_address = pe64_align(virtual_end, nt->OptionalHeader.SectionAlignment);
    raw_address = pe64_align(raw_end, nt->OptionalHeader.FileAlignment);
    image_size = pe64_align(virtual_address + virtual_size, nt->OptionalHeader.SectionAlignment);
    if (raw_size == 0 || virtual_address == 0 || image_size == 0 || image_size < virtual_address) {
        pe64_set_error(pe, "new section size overflows PE limits");
        return NULL;
    }

    resized = (uint8_t *)realloc(pe->buffer, image_size);
    if (resized == NULL) {
        pe64_set_error(pe, "out of memory while extending PE image");
        return NULL;
    }
    memset(resized + pe->buffer_size, 0, image_size - pe->buffer_size);
    pe->buffer = resized;
    pe->buffer_size = image_size;

    nt = pe64_get_nt(pe);
    sections = pe64_first_section(pe);
    memset(&sections[nt->FileHeader.NumberOfSections], 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(sections[nt->FileHeader.NumberOfSections].Name, name, name_length);
    sections[nt->FileHeader.NumberOfSections].Misc.VirtualSize = virtual_size;
    sections[nt->FileHeader.NumberOfSections].VirtualAddress = virtual_address;
    sections[nt->FileHeader.NumberOfSections].SizeOfRawData = raw_size;
    sections[nt->FileHeader.NumberOfSections].PointerToRawData = raw_address;
    sections[nt->FileHeader.NumberOfSections].Characteristics = characteristics;
    nt->FileHeader.NumberOfSections += 1;
    nt->OptionalHeader.SizeOfImage = image_size;

    pe->error[0] = '\0';
    return &sections[nt->FileHeader.NumberOfSections - 1];
}

int pe64_save_to_disk(
    pe64 *pe,
    const char *output_path,
    PIMAGE_SECTION_HEADER new_section,
    uint32_t total_size)
{
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_SECTION_HEADER sections;
    size_t output_size;
    size_t i;
    uint8_t *output;
    FILE *stream;

    if (pe == NULL || output_path == NULL || output_path[0] == '\0') {
        return 0;
    }
    nt = pe64_get_nt(pe);
    sections = pe64_first_section(pe);
    if (nt == NULL || sections == NULL) {
        pe64_set_error(pe, "invalid mapped PE image");
        return 0;
    }

    if (new_section != NULL) {
        int found = 0;
        for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (new_section == &sections[i]) {
                uint32_t raw_size = pe64_align(total_size, nt->OptionalHeader.FileAlignment);
                uint32_t image_size = pe64_align(new_section->VirtualAddress + total_size,
                                                  nt->OptionalHeader.SectionAlignment);
                if (raw_size == 0 || image_size == 0 ||
                    !pe64_range_is_valid(new_section->VirtualAddress, total_size, pe->buffer_size)) {
                    pe64_set_error(pe, "final section size exceeds mapped image");
                    return 0;
                }
                new_section->Misc.VirtualSize = total_size;
                new_section->SizeOfRawData = raw_size;
                nt->OptionalHeader.SizeOfImage = image_size;
                found = 1;
                break;
            }
        }
        if (!found) {
            pe64_set_error(pe, "new section does not belong to this PE image");
            return 0;
        }
    }

    output_size = nt->OptionalHeader.SizeOfHeaders;
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        size_t section_end;
        if (!pe64_add_size(sections[i].PointerToRawData, sections[i].SizeOfRawData, &section_end)) {
            pe64_set_error(pe, "section raw range overflows output size");
            return 0;
        }
        if (section_end > output_size) output_size = section_end;
    }

    output = (uint8_t *)calloc(1, output_size);
    if (output == NULL) {
        pe64_set_error(pe, "out of memory while building output binary");
        return 0;
    }
    memcpy(output, pe->buffer, nt->OptionalHeader.SizeOfHeaders);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        size_t bytes_to_copy = sections[i].SizeOfRawData;
        if (sections[i].VirtualAddress >= pe->buffer_size) {
            free(output);
            pe64_set_error(pe, "section virtual address exceeds mapped image");
            return 0;
        }
        if (bytes_to_copy > pe->buffer_size - sections[i].VirtualAddress) {
            bytes_to_copy = pe->buffer_size - sections[i].VirtualAddress;
        }
        memcpy(output + sections[i].PointerToRawData,
               pe->buffer + sections[i].VirtualAddress,
               bytes_to_copy);
    }

    stream = fopen(output_path, "wb");
    if (stream == NULL || fwrite(output, 1, output_size, stream) != output_size) {
        if (stream != NULL) fclose(stream);
        free(output);
        pe64_set_error(pe, "could not write output binary");
        return 0;
    }
    fclose(stream);
    free(output);
    pe->error[0] = '\0';
    return 1;
}

const char *pe64_get_path(const pe64 *pe)
{
    return pe == NULL ? NULL : pe->path;
}
