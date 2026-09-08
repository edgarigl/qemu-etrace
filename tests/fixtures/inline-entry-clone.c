/* Adapted from Xen common/libelf/libelf-tools.c for inline-entry coverage. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct elf_binary {
    const void *image_base;
    uint64_t size;
    uint64_t unused1[5];
    const void *dest_base;
    uint64_t dest_size;
    uint64_t unused2[6];
    const void *xdest_base;
    uint64_t xdest_size;
    uint64_t unused3[2];
    const char *broken;
};

void elf_mark_broken(struct elf_binary *elf, const char *msg)
{
    if (elf->broken == NULL)
        elf->broken = msg;
}

static bool elf_ptrval_in_range(uint64_t ptrval, uint64_t size,
                                const void *region, uint64_t regionsize)
{
    uint64_t regionp = (uint64_t)region;

    if (region == NULL || ptrval < regionp || ptrval > regionp + regionsize
        || size > regionsize - (ptrval - regionp))
        return false;
    return true;
}

__attribute__((noinline, noclone))
bool elf_access_ok(struct elf_binary *elf, uint64_t ptrval, size_t size)
{
    if (elf_ptrval_in_range(ptrval, size, elf->image_base, elf->size))
        return true;
    if (elf_ptrval_in_range(ptrval, size, elf->dest_base, elf->dest_size))
        return true;
    if (elf_ptrval_in_range(ptrval, size, elf->xdest_base, elf->xdest_size))
        return true;
    elf_mark_broken(elf, "out of range access");
    return false;
}

int main(void)
{
    struct elf_binary elf = { 0 };

    return elf_access_ok(&elf, 0x1008, 8) || elf.broken == NULL;
}
