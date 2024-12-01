#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>

struct bitmap *SwapTable_Bitmap;

void init_SwapTable(void);
void swap_in(size_t idx, void *paddr);
size_t swap_out(void *paddr);

#endif