#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/thread.h"

struct frame 
{ 
  void *kaddr;                  /* Physical Address of this frame. */
  struct thread *thread;        /* The thread who uses this frame. */
  struct pt_entry *pte;         /* Pointer to the mapped PTE for this. */
  struct list_elem frame_elem;  /* Iterator for the page replacement. */
};

extern struct list frame_list;
extern struct list_elem *frame_clock;

void ft_init (void);
struct frame *alloc_page (enum palloc_flags);
void free_page (void*);
static struct list_elem* ft_clocking (void);
static struct frame* ft_get_unaccessed_frame (void);
static void ft_evict_frame (void);
bool load_file_to_page (void*, struct pt_entry*);

#endif
