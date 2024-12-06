#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "threads/palloc.h"

#define ON_FILE 1
#define ON_SWAP 2

struct pt_entry 
{
  void *vaddr;             
  int type;                 
  bool writable;            
  bool is_loaded;        

  struct hash_elem elem;   //page_table's hash_elem

  size_t slot_idx;         //swap space idx

  struct file *file;       //ON_FILE
  size_t offset;           //file offset
  size_t read_bytes;            
  size_t zero_bytes;         
}; 

void supt_init (struct hash*);
struct pt_entry* supt_entry_alloc(void);
void supt_entry_init(struct pt_entry*, void*, int, bool, bool, struct file*, size_t, size_t, size_t);
bool supt_insert (struct hash*, struct pt_entry*);
struct pt_entry* supt_find(struct hash*, void*);
void supt_destroy (struct hash*);

#endif
