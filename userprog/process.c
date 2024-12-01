#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h" 
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
//proj4
#include "vm/frame.h"
#include "vm/swap.h"


extern struct lock TOTAL_LOCK;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void parsing(char *src, char *dest);

void parsing(char *src, char *dest){
  int i;
  strlcpy(dest, src, strlen(src) + 1);
  for(i=0;dest[i]!=' '&&dest[i]!='\0';i++);
  dest[i]='\0';
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  char first_name[256];

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE); //fn_copy에 file_name 복사 -> race를 피하기 위해
  //결국 start_process에 넘겨주는 건 fn_copy임

  //parsing 진행
  parsing(file_name, first_name);

  //만약 존재하지는 파일이라면 return -1 : exec_missing
  struct file *file = filesys_open(first_name);
  if (file == NULL) return -1;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (first_name, PRI_DEFAULT, start_process, fn_copy);

  sema_down(&thread_current()->wait_for_load);  //자식의 응용이 메모리에 적재될 때까지 대기

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
 
  struct thread* cur = thread_current();
  struct thread* tmp=NULL;
  struct list_elem* e;
  for(e=list_begin(&(cur->children));e!=list_end(&(cur->children));e=list_next(e)){
    tmp=list_entry(e,struct thread,child_elem);
    if(!(tmp->load_flag)){
      return process_wait(tmp->tid);
    }
  }

  return tid;
}
 
//fn_copy가 인자로 들어옴
/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_) 
{ 
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  //Page Table 생성
  pt_init(&(thread_current()->pt));

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  //sema_up(&thread_current()->wait_for_load);
  /* If load failed, quit. */
  palloc_free_page (file_name);

  if(!success){
    thread_current()->load_flag=0;
    sema_up(&thread_current()->parent->wait_for_load);   //적재 실패 락 해제
    exit(-1);
  }

  sema_up(&thread_current()->parent->wait_for_load);  //적재 성공 부모 락 해제

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur = thread_current();  //현재 thread
  struct thread *tmp=NULL;  //search 자식 thread element
  struct list_elem *e;
  int exit_status;
  //printf("CHILD TID: %d\n",child_tid);

  for(e=list_begin(&(cur->children));e!=list_end(&(cur->children));e=list_next(e)){
    tmp=list_entry(e,struct thread,child_elem);
    //printf("Child tid: %d\n", tmp->tid);
    if(tmp->tid==child_tid){  //child_tid인 process found!
      sema_down(&(tmp->wait_for_child));
      //printf("PROCESS_WAIT:EXIT_STATUS1: %d\n", tmp->exit_status);
      exit_status=tmp->exit_status;
      //printf("PROCESS_WAIT:EXIT_STATUS2: %d\n", exit_status);
      //printf("SEMADOWN!!!\n");
      list_remove(&(tmp->child_elem));
      //printf("LIST_REMOVED: %d\n");
      sema_up(&(tmp->wait_for_remove));
      //printf("SEMAUP!!!\n");
      return exit_status;
    }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  unsigned i;

  for (i = 1; i < cur->mm_list_size; i++) munmap (i);
  pt_destroy (&(cur->pt));

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  //printf("EXIT111\n");
  //printf("semaphore2: %d!!!\n", cur->child_lock.value);
  //자식이 종료하면서 wait_for_child 1로 증가 따라서 부모 프로세스 작동
  sema_up(&(cur->wait_for_child));
  //printf("semaphore: %d!!!\n", cur->child_lock.value);
  //printf("EXIT222\n");
  //부모가 list_remove하기 전까지 없어지면 안됨 따라서 부모가 1로 증가시킬 때까지 대기
  sema_down(&(cur->wait_for_remove));
  //printf("EXIT333\n");
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  char first_name[256]; 

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  //parsing 진행
  parsing(file_name, first_name);


  lock_acquire (&TOTAL_LOCK);
  /* Open executable file. */
  file = filesys_open (first_name);
  if (file == NULL) 
    {
      lock_release (&TOTAL_LOCK);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  ///////file_deny_write////////////
  t->currently_running_file=file;
  file_deny_write(t->currently_running_file);
  lock_release (&TOTAL_LOCK);
  /////////////////////////

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

  //construct stack!!
  //+++++++++start+++++++++++
  int argc=0;
  char *ptr;
  char *rest;
  char *token;
  char *copy = (char*)malloc(sizeof(char)*256);
  strlcpy(copy,file_name,strlen(file_name)+1);
  ptr=copy; //초기화
  //argc 세기
  token=strtok_r(ptr," ",&rest);
  argc++;
  ptr=rest;
  while(token!=NULL){
    token=strtok_r(ptr," ",&rest);
    argc++;
    ptr=rest;
  }
  argc--;
  free(copy);
  //argv로 토큰화
  char **argv = (char**)malloc(sizeof(char*)*argc);
  i=0;
  ptr=file_name;
  token=strtok_r(ptr," ", &rest);
  argv[i]=token;
  i++;
  ptr=rest;
  while(token!=NULL){
    token=strtok_r(ptr," ",&rest);
    argv[i]=token;
    i++;
    ptr=rest;
  }
  //printf(">>stack 저장 시작 (argc: %d)\n",argc);
  //printf(">>argv[0] : %s\nargv[1] : %s\n",argv[0],argv[1]);
  //argc만큼의 token 개수가 argv에 저장
  //이제 스택에 push
  int total_length=0; //alignment를 위해
  int word_align=0;
  int argv_i_length=0;
  for(i=argc-1;i>=0;i--){
    argv_i_length=strlen(argv[i])+1;  //argument 길이+'\0'
    *esp -= argv_i_length; //stack크기 늘리기
    strlcpy(*esp,argv[i],argv_i_length);  //stack에 copy
    total_length+=argv_i_length;
    argv[i]=*esp;
  }
  //alignment 추가 (4byte 단위)
  if(total_length%4){ //align이 맞지 않은 경우 추가
    word_align=4-(total_length%4);
    *esp-=word_align;
    memset(*esp,0,word_align);
  }  
  *esp-=4;  //4byte 0000추가
  **(uint32_t **)esp = 0;
  //각각의 argv의 주소 추가
  for(i=argc-1;i>=0;i--){
    *esp -= 4; //stack크기 늘리기
    **(uint32_t**)esp=argv[i];
  }
  //argv, argc 추가
  *esp-=4;
  **(uint32_t**)esp=*esp+4;
  *esp-=4;
  **(uint32_t**)esp=argc;
  *esp-=4;
  **(uint32_t**)esp=0;
  
  free(argv);
  //hex_dump(*esp, *esp, 100, 1); //stack 출력 확인
  //+++++++++end+++++++++++

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  struct pt_entry *pte;

  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Create a page table entry for this, and push to the 
         page table. Note that this is not a loading, this is
         just constructing the page table only. (Lazy Loading) */
      pte = pt_create_entry (upage, BINARY, writable, false,
        file, ofs, page_read_bytes, page_zero_bytes);
      if(pte == NULL) return false;

      pt_insert_entry (&(thread_current ()->pt), pte);
      
      /* Advance. Note that the offset is updated. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
      // /* Calculate how to fill this page.
      //    We will read PAGE_READ_BYTES bytes from FILE
      //    and zero the final PAGE_ZERO_BYTES bytes. */
      // size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      // size_t page_zero_bytes = PGSIZE - page_read_bytes;

      // /* Get a page of memory. */
      // uint8_t *kpage = palloc_get_page (PAL_USER);
      // if (kpage == NULL)
      //   return false;

      // /* Load this page. */
      // if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
      //   {
      //     palloc_free_page (kpage);
      //     return false; 
      //   }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // /* Add the page to the process's address space. */
      // if (!install_page (upage, kpage, writable)) 
      //   {
      //     palloc_free_page (kpage);
      //     return false; 
      //   }

      // /* Advance. */
      // read_bytes -= page_read_bytes;
      // zero_bytes -= page_zero_bytes;
      // upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  // uint8_t *kpage;
  struct frame *kpage;
  bool success = false;

  // kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  // if (kpage != NULL) 
  //   {
  //     success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
  //     if (success)
  //       *esp = PHYS_BASE;
  //     else
  //       palloc_free_page (kpage);
  //   }
  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      /* Record this new frame to the 'read(non-supplemental)' page table.
         And then, set the esp pointer value as recommended. */
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage->kaddr, true);
      if (success) 
        {
          *esp = PHYS_BASE;

          /* After installing pages for the stack segment, then 
             create a page table entry for these pages and push 
             it to the supplemental page table of current thread. */
          kpage->pte = pt_create_entry (((uint8_t *)PHYS_BASE) - PGSIZE, 
            SWAPPED, true, true, NULL, 0, 0, 0);
          if (kpage->pte == NULL) return false;

          pt_insert_entry (&(thread_current ()->pt), kpage->pte);
        }
      else
        free_page (kpage->kaddr);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

bool 
handle_mm_fault (struct pt_entry *pte)
{
  struct frame *kpage;
  bool success = false;

  /* Allocate a new physical frame and map to the passed PTE.
     This frame possibly replaces the original virtual page.*/
  kpage = alloc_page (PAL_USER);
  kpage->pte = pte;

  /* What is a type of the virtual page of the faulting address?
      --> here are two cases by type of page, just like below. 
     (1) If it's the binary file or the mmapped file, then simply
       load related data from the same file in the disk-side.*/
  if (pte->type == BINARY || pte->type == MAPPED)
    {
      if (load_file_to_page (kpage->kaddr, pte))
        success = install_page (pte->vaddr, kpage->kaddr, pte->writable);
    }

  /* (2) If it's the page that are from the swap space but not in
       the memory right now, just swapping in that frame. Note that in 
       both cases we just install the newly created frame into system. */
  else if (pte->type == SWAPPED)
    { 
      swap_in (pte->swap_slot, kpage->kaddr);
      success = install_page (pte->vaddr, kpage->kaddr, pte->writable);
    }

  /* If installation(frame-to-page mapping in 'real' 
     page table) is done, then set this page as 'loaded'. 
     If installation failed, then free that newly created frame. */
  if (success) 
    pte->is_loaded = true;
  else 
    free_page (kpage->kaddr);

  return success;
  /* If it reaches here with success == true, then the loading is successful.
     Thus, 'page_fault()' will return properly, and the system will execute
     the faulting instruction once again. (fault exception handling) */
}

bool 
expand_stack (void *addr, void *esp)
{
  void *upage;
  struct frame *kpage;
  bool success = false;
  
  /* Is it OK to expand the stack in this case? That is, check if the 
     faulting address can be within the 8MB range from the current stack 
     pointer address, and whether it's from the user-virtual area, and 
     qualify the PUSHA condition also. All these 3 checks should be passed. */
  if (!is_user_vaddr (addr)) return false;
  if (addr < (PHYS_BASE - MAX_STACK_SIZE)) return false;
  if (addr < (esp - 32)) return false;
  
  /* Get the nearest page boudary, to 'upage'. */
  upage = pg_round_down (addr);

  /* If the previous checking was successful, then expand 
     the stack just like the way we set up the stack, except
     for the setting routine of the esp pointer. */
  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (upage, kpage->kaddr, true);
      if (success)
        {
          kpage->pte = pt_create_entry (upage, SWAPPED, true, true,
            NULL, 0, 0, 0);
          if (kpage->pte == NULL) return false;

          pt_insert_entry (&(thread_current ()->pt), kpage->pte);
        }
      else
        free_page (kpage->kaddr);
    }

  return success; 
}