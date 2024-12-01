#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include "vm/page.h"
#include <list.h>

struct frame 
{ 
  void *paddr;
  struct thread *thread;
  struct PTE *pte;
  struct list_elem elem;
};

struct list FramePool; // Frame Pool: system wide 변수
struct list_elem *LRU_elem; //second chance algoritm element

void init_FramePool(void);   //Frame Pool 초기화 (system wide: sync 고려)
struct frame *allocate_frame (enum palloc_flags flags); //물리 frame을 할당
void deallocate_frame (void *paddr);    //물리 frame 반환
bool load_file (void *paddr, struct PTE *pte);  //disk-->frame

#endif