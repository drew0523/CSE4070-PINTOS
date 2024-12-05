#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

struct lock swap_lock;
struct block *swap_block;
struct bitmap *swap_bitmap;

void swap_init(void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  swap_bitmap = bitmap_create (PGSIZE);
  lock_init (&swap_lock);
}

void swap_in(size_t index, void *kaddr)
{
    lock_acquire(&swap_lock);

    if (index == 0) {
        return;         
    }
    index--;
    for (unsigned i = 0; i < 8; i++) {
        block_read(swap_block, (index * 8) + i, kaddr + (512 * i));
    }
    bitmap_flip(swap_bitmap, index);
    
    lock_release(&swap_lock);
}

size_t swap_out (void *kaddr)
{
  lock_acquire (&swap_lock);

  size_t swap_idx = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
  if (swap_idx == BITMAP_ERROR){
    lock_release (&swap_lock);
    return BITMAP_ERROR;
  }

  swap_block = block_get_role (BLOCK_SWAP);  
  size_t counter = 0;
  while (counter < 8){
    block_write (swap_block, swap_idx * 8 + counter, kaddr + counter * BLOCK_SECTOR_SIZE);
    counter++;
  }
  swap_idx++;

  lock_release (&swap_lock);
  return swap_idx;
}

void 
swap_free (size_t index)
{
  lock_acquire (&swap_lock);
  bitmap_set (swap_bitmap, index, false);
  lock_release (&swap_lock);
}
