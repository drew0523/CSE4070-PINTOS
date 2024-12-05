#include <string.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static unsigned pt_hash_func (const struct hash_elem *h_elem, void *aux UNUSED)
{
  return hash_int((int)hash_entry(h_elem,struct pt_entry,elem)->vaddr);
}

static bool pt_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  return hash_entry(a,struct pt_entry,elem)->vaddr < hash_entry(b,struct pt_entry,elem)->vaddr;
}

void 
pt_init (struct hash *pt)
{
  hash_init (pt, pt_hash_func, pt_hash_less, NULL);
}

struct pt_entry* pt_alloc_entry() {
  /* Allocate memory for a new pt_entry */
  struct pt_entry *pte = (struct pt_entry *)malloc(sizeof(struct pt_entry));
  return pte;
}

void pt_init_entry(struct pt_entry *pte, void *vaddr, pt_type type, bool writable, bool is_loaded,
  struct file *file, size_t offset, size_t read_bytes, size_t zero_bytes)
{
  memset(pte, 0, sizeof(struct pt_entry));
  pte->type = type;
  pte->file = file;
  pte->vaddr = vaddr;
  pte->offset = offset;
  pte->writable = writable;
  pte->read_bytes = read_bytes;
  pte->is_loaded = is_loaded;
  pte->zero_bytes = zero_bytes;
}

bool 
pt_insert_entry (struct hash *pt, struct pt_entry *pte)
{
  if (!hash_insert (pt, &(pte->elem)))
    return false;

  return true;
}

struct pt_entry* pt_find(struct hash* page_table, void* vaddr)
{
    struct hash_elem* e;
    struct pt_entry carrier;
    struct pt_entry* pte;

    /* Get the proper VPN of the given virtual address. */
    carrier.vaddr = pg_round_down(vaddr);

    /* Find the corresponding PTE of that page. */
    e = hash_find(page_table, &carrier.elem);
    if (e != NULL) {
        pte = hash_entry(e, struct pt_entry, elem);
        return pte;
    } else {
        return NULL;
    }
}

/* It deallocates a corresponding memory space of given element.
   That is, this function is used during destroying routine. */
static void
pt_destroy_func (struct hash_elem *h_elem, void *aux UNUSED)
{
  struct pt_entry *pte = hash_entry(h_elem, struct pt_entry, elem);

  if(pte->swap_slot==NULL)
    swap_free (pte->swap_slot);

  /* Free the memory of entry. */
  free(pte);
}
void 
pt_destroy (struct hash *pt)
{
  hash_destroy (pt, pt_destroy_func);
}