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

static void ft_insert_frame (struct frame *frame);
static void ft_delete_frame (struct frame *frame);
static struct frame *ft_find_frame (void *kaddr);
static struct list_elem *ft_clocking (void);
static struct frame *ft_get_unaccessed_frame (void);
static void ft_evict_frame (void);

#endif
