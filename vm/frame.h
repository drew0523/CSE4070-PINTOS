#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/page.h"

struct frame
{ 
  void *kaddr;                  //물리 주소
  struct thread *thread;        //해당 프레임 사용 중인 thread
  struct pt_entry *pte;         //해당 frame과 mapping된 pte
  struct list_elem frame_elem;
};

extern struct list frame_list;
extern struct list_elem *frame_clock;

void frame_pool_init (void);
struct frame *alloc_frame (enum palloc_flags);
void free_frame (void*);
static struct list_elem* clock_next_frame(void);
static struct frame* Second_Chance_Algorithm (void);
static void evict_frame (void);

#endif
