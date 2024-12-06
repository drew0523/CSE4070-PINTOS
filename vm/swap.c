#include <stdlib.h>
#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

struct lock swap_lock;
struct block *swap_slot;
struct bitmap *swap_bitmap;

//swap table bitmap으로 관리: system-wide(init.c)
void swap_table_init(void)
{
  swap_slot = block_get_role (BLOCK_SWAP);
  swap_bitmap = bitmap_create (PGSIZE);
  lock_init (&swap_lock);
}

//swap slot에서 physical memory로 가져옴
void swap_in(size_t index, void *kaddr)
{
    lock_acquire(&swap_lock);

    if (index == 0) {
        lock_release(&swap_lock);
        return;         
    }
    index--;
    for (unsigned i = 0; i < 8; i++) {
        block_read(swap_slot, (index * 8) + i, kaddr + (512 * i));  //swap block
    }
    bitmap_flip(swap_bitmap, index);
    
    lock_release(&swap_lock);
}

//BINAY FILE에서 physical memory로 가져옴
bool load_file(void *kaddr, struct pt_entry *pte) {
    if (!kaddr || !pte || !pte->file) {
        return false;
    }
    size_t bytes_read = file_read_at(pte->file, kaddr, pte->read_bytes, pte->offset); //binary file
    if (bytes_read != pte->read_bytes) {
        return false;
    }
    if (pte->zero_bytes > 0) {
        memset((uint8_t *)kaddr + pte->read_bytes, 0, pte->zero_bytes);
    }

    return true;
}

size_t swap_out (void *kaddr)
{
  lock_acquire (&swap_lock);

  size_t swap_idx = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
  if (swap_idx == BITMAP_ERROR){
    lock_release (&swap_lock);
    return BITMAP_ERROR;
  }

  swap_slot = block_get_role (BLOCK_SWAP);  
  for (size_t i = 0; i < 8; i++) {
        block_write(swap_slot, swap_idx * 8 + i, kaddr + i * BLOCK_SECTOR_SIZE);  //swap block에 저장
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