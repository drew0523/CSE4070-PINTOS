#include "vm/frame.h"
#include "vm/swap.h"
#include "lib/string.h"
#include "threads/malloc.h"


struct list frame_list;
struct list_elem *frame_clock;
struct lock frame_lock;

void 
ft_init (void)
{
  list_init (&frame_list);
  lock_init (&frame_lock);
  frame_clock = NULL;
}

struct frame *alloc_page (enum palloc_flags flags)
{
  lock_acquire(&frame_lock);

  void* frame_page = palloc_get_page(flags);
  if(frame_page==NULL){   //더 이상 frame x: 따라서 LRU evict
    ft_evict_frame ();  
    frame_page = palloc_get_page (flags);
  }

  struct frame *page = (struct frame *)malloc(sizeof(struct frame)); // page == frame //
  page->thread = thread_current ();
  page->kaddr = frame_page;
  list_push_back (&frame_list, &(page->frame_elem));
  
  lock_release (&frame_lock);

  return page;
}

void 
free_page (void *kaddr)
{
    lock_acquire(&frame_lock);

    struct frame *page;
    struct list_elem *e;
    while (e != list_end(&frame_list)) {
      struct frame *entry = list_entry(e, struct frame, frame_elem);
      if (entry->kaddr == kaddr) {
          page = entry;
          break;
       }
      e = list_next(e); // 반복자 업데이트
    }

    if (page) {
        palloc_free_page(kaddr);
        free(page);
    }

    lock_release(&frame_lock);
}

static struct list_elem* ft_clocking (void)
{
  /* If the iterator reaches the end of the list, then get 
     back to the front of the swap table (list). */
  if (list_empty(&frame_list))
    exit(-1);
    /* Initialize or wrap around the iterator if it reaches the end. */
  if (frame_clock == NULL || frame_clock == list_end(&frame_list)) {
    frame_clock = list_begin(&frame_list);
  }
  else{
    frame_clock = list_next(frame_clock);
  }

  if (frame_clock == list_end (&frame_list)){
    frame_clock = ft_clocking ();
  }

  return frame_clock;
}

static struct frame* ft_get_unaccessed_frame (void)
{
  int n = list_size(&frame_list);
  if (n == 0) exit(-1);

  int iterations = 0;
  while (iterations <= 2 * n) { //아무리 돌아도 최대 2바퀴
    struct list_elem *tmp_frame=ft_clocking();
    struct frame *entry = list_entry(tmp_frame, struct frame, frame_elem);
    if (pagedir_is_accessed(entry->thread->pagedir, entry->pte->vaddr)) { //1이면 0으로 set하고 다음으로 넘어감
      pagedir_set_accessed(entry->thread->pagedir, entry->pte->vaddr, false);
      iterations++;
      continue;
    }
    return entry; //0이면 반환
  }
}

static void ft_evict_frame (void)
{
  struct frame *frame;

  /* Find an unaccessed frame and check the dirtiness of it. */
  frame = ft_get_unaccessed_frame (); //frame to be evicted

  pagedir_clear_page (frame->thread->pagedir, frame->pte->vaddr); //해당 vaddr와 매핑된 물리 프레임 해제 present bit=0
  frame->pte->swap_slot = swap_out (frame->kaddr);
  frame->pte->type = SWAPPED;
  frame->pte->is_loaded = false;

  palloc_free_page (frame->kaddr);  //해당 물리 프레임 반환
  
  //frame table에서 제거
  struct list_elem *entry = &(frame->frame_elem);
  if (frame_clock==entry) //frame clock이 제거되는 frame이면 옮기기
    frame_clock = list_next(frame_clock);
  list_remove(entry);

  free (frame);
}


/* Load a file from the disk onto the physical memory. After loading,
   the remaining part of the given frame will be set to zero. */
bool 
load_file_to_page (void *kaddr, struct pt_entry *pte)
{
  bool success; 

  /* Read(load) the file onto the memory. */
  size_t read_byte = pte->read_bytes;
  size_t temp = (size_t)file_read_at (pte->file, 
    kaddr, pte->read_bytes, pte->offset);
  
  /* Set all the remaining bytes of that frame to zero,
     only if the file read operation was successful. */
  success = (read_byte == temp);
  if (success)
    memset (kaddr + pte->read_bytes, 0, pte->zero_bytes);

  return success;
}