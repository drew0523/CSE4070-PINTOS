#include <string.h>
#include <stdlib.h>
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static unsigned supt_hash_func (const struct hash_elem *h_elem, void *aux UNUSED)
{
  return hash_int((int)hash_entry(h_elem,struct pt_entry,elem)->vaddr);
}

static bool supt_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  return hash_entry(a,struct pt_entry,elem)->vaddr < hash_entry(b,struct pt_entry,elem)->vaddr;
}

//supplementary page table 생성 (process별 소유->startprocess시 호출)
void supt_init (struct hash *supt)
{
  hash_init (supt, supt_hash_func, supt_hash_less, NULL);
}

struct pt_entry* supt_entry_alloc() {
  struct pt_entry *pte = (struct pt_entry *)malloc(sizeof(struct pt_entry));
  return pte;
}

void supt_entry_init(struct pt_entry *pte, void *vaddr, int type, bool writable, bool is_loaded,
  struct file *file, size_t offset, size_t read_bytes, size_t zero_bytes)
{
  memset(pte, 0, sizeof(struct pt_entry));
  pte->vaddr = vaddr;
  pte->type = type;
  pte->writable = writable;
  pte->is_loaded = is_loaded;
  pte->file = file;
  pte->offset = offset;
  pte->read_bytes = read_bytes;
  pte->zero_bytes = zero_bytes;
}

bool supt_insert(struct hash *supt, struct pt_entry *pte)
{
  return hash_insert(supt, &(pte->elem)) != NULL;   //pte삽입
}

//page table에서 vaddr에 대응하는 pte 찾기
struct pt_entry* supt_find(struct hash* supt, void* vaddr)
{
  struct pt_entry carrier;
  carrier.vaddr = pg_round_down(vaddr);
    
  struct hash_elem *e = hash_find(supt, &carrier.elem);
  return e ? hash_entry(e, struct pt_entry, elem) : NULL;
}

static void supt_destroy_func (struct hash_elem *h_elem, void *aux UNUSED)
{
  struct pt_entry *pte = hash_entry(h_elem, struct pt_entry, elem);

  if(pte->slot_idx==NULL)
    swap_free (pte->slot_idx);

  free(pte);
}

//process_exit 시 supt 삭제(메모리 누수 방지)
void supt_destroy (struct hash *supt)
{ 
  hash_destroy (supt, supt_destroy_func);
}