/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <lib/common.h>
#include <lib/debug.h>
#include <lib/storage.h>
#include <lib/string.h>

/* Layout checked against this LK's bio_open/read/write and list traversal. */
static struct part_context context;
static void *bio_open(const char *name) {
    return ((void *(*)(const char *))ARCH_FN(CONFIG_BIO_OPEN_ADDRESS))(name);
}
static void bio_close(void *dev) {
    ((void (*)(void *))ARCH_FN(CONFIG_BIO_CLOSE_ADDRESS))(dev);
}
static uint64_t device_size(void *dev) {
    return *(uint64_t *)((uintptr_t)dev + 0x20);
}
const struct part_info *storage_part_find(const char *name) {
    for (int i = 0; i < context.count; ++i)
        if (!strcmp(context.parts[i].name, name)) return &context.parts[i];
    return NULL;
}
int storage_part_count(void) { return context.count; }
const struct part_info *storage_part_get(int index) {
    return index >= 0 && index < context.count ? &context.parts[index] : NULL;
}
static ssize_t transfer(const struct part_info *part, void *data, uint64_t offset,
                        size_t size, bool write) {
    if (!part || !data || !size) return -1;
    void *dev = bio_open(part->name);
    if (!dev) return -1;
    uint64_t total = device_size(dev);
    ssize_t result = -1;
    if (offset <= total && size <= total - offset && offset <= INT64_MAX) {
        uintptr_t fn = write ? CONFIG_BIO_WRITE_ADDRESS : CONFIG_BIO_READ_ADDRESS;
        result = ((ssize_t (*)(void *, void *, uint64_t, size_t))fn)(dev, data, offset, size);
    }
    bio_close(dev);
    return result;
}
ssize_t storage_part_read(const struct part_info *part, void *dst, uint64_t off, size_t n) {
    return transfer(part, dst, off, n, false);
}
ssize_t storage_part_write(const struct part_info *part, void *src, uint64_t off, size_t n) {
    return transfer(part, src, off, n, true);
}
void storage_init(void) {
    context.count = 0;
    uintptr_t head = CONFIG_BIO_DEVICE_LIST_ADDRESS;
    uintptr_t node = *(uintptr_t *)(head + 8);
    /* Native BIO names are devices/partition aliases; offsets are device-relative. */
    for (unsigned visited = 0; node && node != head && visited < 512; ++visited) {
        const char *name = *(const char **)(node + 0x40);
        uint64_t size = *(uint64_t *)(node + 0x20);
        if (name && size && strnlen(name, PART_NAME_MAX + 1) <= PART_NAME_MAX &&
            !storage_part_find(name) && context.count < PARTS_MAX) {
            struct part_info *part = &context.parts[context.count++];
            strcpy(part->name, name);
            part->start_block = 0;
            part->size_blocks = size / 512;
        }
        node = *(uintptr_t *)(node + 8);
    }
    printf("kaeru: %d native BIO devices/partitions\n", context.count);
}
