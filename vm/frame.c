#include <stdlib.h>
#include "vm/frame.h"
#include "vm/swap.h"
#include "lib/string.h"
#include "threads/malloc.h"

struct list frame_list;
struct list_elem *frame_clock;
struct lock frame_lock;

//frame pool 생성: system-wide(init.c)
void frame_pool_init (void)
{
  list_init (&frame_list);
  lock_init (&frame_lock);
  frame_clock = NULL;
}

//frame 할당: 없으면 LRU로 evict후 재alloc
struct frame *alloc_frame (enum palloc_flags flags)
{
  lock_acquire(&frame_lock);

  void* frame_page = palloc_get_page(flags);
  if(frame_page==NULL){   //더 이상 frame x: 따라서 LRU evict
    evict_frame ();  
    frame_page = palloc_get_page (flags);
  }

  struct frame *frame = (struct frame *)malloc(sizeof(struct frame)); // page == frame //
  frame->thread = thread_current ();
  frame->kaddr = frame_page;
  list_push_back (&frame_list, &(frame->frame_elem));
  
  lock_release (&frame_lock);

  return frame;
}

void free_frame(void *kaddr) {
  lock_acquire(&frame_lock);

  struct frame *frame = NULL;
  struct list_elem *e;
  
  //frame pool에서 frame search
  for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e)) {
    struct frame *entry = list_entry(e, struct frame, frame_elem);
    if (entry->kaddr == kaddr) {
      frame = entry;
      break;
    }
  }

  if (frame) {
    palloc_free_page(kaddr);
    free(frame);
  }

  lock_release(&frame_lock);
}

//second-chance algoritm helper 함수
static struct list_elem* clock_next_frame(void)
{
  if (list_empty(&frame_list))
    exit(-1);
  
  if (frame_clock == NULL || frame_clock == list_end(&frame_list)) {
    frame_clock = list_begin(&frame_list);
  }
  else{
    frame_clock = list_next(frame_clock);
    if (frame_clock == list_end (&frame_list)) frame_clock = clock_next_frame();
  }
  
  return frame_clock;
}

//approximate LRU
static struct frame* Second_Chance_Algorithm(void)
{
  int n = list_size(&frame_list);
  if (n == 0) exit(-1);

  int iterations = 0;
  while (iterations <= 2 * n) { //아무리 돌아도 최대 2바퀴
    struct list_elem *tmp_frame=clock_next_frame();
    struct frame *entry = list_entry(tmp_frame, struct frame, frame_elem);
    if (pagedir_is_accessed(entry->thread->pagedir, entry->pte->vaddr)) { //1이면 0으로 set하고 다음으로 넘어감
      pagedir_set_accessed(entry->thread->pagedir, entry->pte->vaddr, false);
      iterations++;
      continue;
    }
    return entry; //0이면 반환
  }
  return NULL;
}

//더 이상 frame없는 경우 evict하기 위해
static void evict_frame (void)
{
  struct frame *frame = Second_Chance_Algorithm();
  if (frame == NULL) exit(-1);

  pagedir_clear_page (frame->thread->pagedir, frame->pte->vaddr); //해당 vaddr와 매핑된 물리 프레임 해제 present bit=0
  
  frame->pte->slot_idx = swap_out (frame->kaddr);
  frame->pte->type = ON_SWAP;
  frame->pte->is_loaded = false;
  /////////////////////////////////////////
  ///////////////구현 미흡/////////////////
  ////////////////////////////////////////

  palloc_free_page (frame->kaddr);  //해당 물리 프레임 반환
  
  //frame table에서 제거
  struct list_elem *entry = &(frame->frame_elem);
  if (frame_clock==entry) //frame clock이 제거되는 frame이면 옮기기
    frame_clock = list_next(frame_clock);
  list_remove(entry);

  free (frame);
}