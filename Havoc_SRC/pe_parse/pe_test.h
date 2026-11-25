#pragma once

#include <stdint.h>
#include <stddef.h>
#include <Windows.h>

/*
 * A PE32+ (AMD64) image.  `buffer` is laid out by RVA, while
 * `buffer_not_relocated` retains the original on-disk bytes.
 */
typedef struct pe64 {
    uint8_t *buffer;
    size_t buffer_size;
    uint8_t *buffer_not_relocated;
    size_t raw_size;
    char *path;
    char error[160];
} pe64;

/* Opens and maps an AMD64 PE into RVA-addressable memory. Returns non-zero on success. */
int pe64_open(pe64 *pe, const char *binary_path);
void pe64_destroy(pe64 *pe);

/* Returns the last error reported by an operation, or an empty string. */
const char *pe64_error(const pe64 *pe);

uint32_t pe64_align(uint32_t address, uint32_t alignment);

uint8_t *pe64_get_buffer(pe64 *pe);
const uint8_t *pe64_get_buffer_not_relocated(const pe64 *pe);
PIMAGE_NT_HEADERS64 pe64_get_nt(pe64 *pe);
PIMAGE_SECTION_HEADER pe64_get_section(pe64 *pe, const char *section_name);

/*
 * Adds a final section. `size` is the number of bytes the caller intends to
 * place in the section. There must be unused room in the existing PE headers
 * for another IMAGE_SECTION_HEADER.
 */
PIMAGE_SECTION_HEADER pe64_create_section(
    pe64 *pe, const char *name, uint32_t size, uint32_t characteristics);

/*
 * Writes a valid on-disk PE. `new_section` may be NULL when no newly-created
 * section needs final sizing. When supplied, `total_size` is its final size.
 * Returns non-zero on success.
 */
int pe64_save_to_disk(
    pe64 *pe,
    const char *output_path,
    PIMAGE_SECTION_HEADER new_section,
    uint32_t total_size);

const char *pe64_get_path(const pe64 *pe);
