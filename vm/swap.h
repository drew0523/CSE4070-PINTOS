#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>
#include <bitmap.h>
#include "vm/page.h"

extern struct bitmap *swap_bitmap;

void swap_table_init (void);
void swap_in (size_t, void*);               //ON_SWAP   SWAP_SLOT(DISK)->FRAME
bool load_file (void*, struct pt_entry*);   //ON_FILE   BINARY_FILE(DISK)->FRAME 
size_t swap_out (void*);
void swap_free (size_t);

#endif
