#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

typedef enum { BINARY, MAPPED, SWAPPED } pt_type;

struct pt_entry 
{
  void *vaddr;                  /* VPN(Virtual Page Number). */
  pt_type type;                 /* Type of page indicated by this PTE. */
  bool writable;                /* Is it OK to write to this page? */
  bool is_loaded;               /* Is this page loaded onto physical memory? */

  struct hash_elem elem;        /* Hash element for each page table. */

  struct list_elem mm_elem;     /* Iterator for the mmap list. */

  size_t swap_slot;             /* Index of the slot for swapping this. */

  struct file *file;            /* Pointer to the mapped file. */
  size_t offset;                /* Current file position of the file. */
  size_t read_bytes;            /* Number of bytes written on page. */
  size_t zero_bytes;            /* Number of rest of bytes of that page. */
};

static unsigned pt_hash_func (const struct hash_elem*, void*);
static bool pt_hash_less (const struct hash_elem*, const struct hash_elem*, void*);
void pt_init (struct hash*);
struct pt_entry* pt_alloc_entry(void);
void pt_init_entry(struct pt_entry*, void*, pt_type, bool, bool, struct file*, size_t, size_t, size_t);
struct pt_entry* pt_create_entry(void*, pt_type, bool, bool, struct file*, size_t, size_t, size_t);
bool pt_insert_entry (struct hash*, struct pt_entry*);
struct pt_entry* pt_find(struct hash*, void*);
static void pt_destroy_func (struct hash_elem *, void*);
void pt_destroy (struct hash*);

#endif
