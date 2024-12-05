#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>
#include <bitmap.h>

extern struct bitmap *swap_bitmap;

void swap_init (void);
void swap_in (size_t, void*);
size_t swap_out (void*);
void swap_free (size_t);

#endif
