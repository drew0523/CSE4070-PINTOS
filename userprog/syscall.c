#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"
#include <stdbool.h>
#include "threads/synch.h"

struct lock TOTAL_LOCK;

static void syscall_handler (struct intr_frame *);
void check_address(void* vaddr);
//prj1 syscall 함수
void halt();
void exit(int status);
tid_t exec(const char *cmd_line);
int wait(tid_t pid);
int read(int fd, void *buffer, unsigned int size);
int write(int fd, void *buffer, unsigned int size);
//additional.c 구현
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);
//proj2 filesystem syscall 구현
// create, remove, open, close, filesize, seek, tell , / read,write수정
bool create(const char *file, off_t initial_size);
bool remove(const char *file);
int open(const char *file);
void close(int fd);
int filesize(int fd);
void seek(int fd, off_t offset);
off_t tell(int fd);
// mapid_t
// mmap (int fd, void *addr);
// void 
// munmap (mapid_t mapid);


//usermemoryaccess구현!
void check_address(void* vaddr){
  //1. kernel 영역 2. NULL pointer 인 경우 예외처리
  struct thread *cur = thread_current();
  if(vaddr==NULL || is_kernel_vaddr(vaddr)){
    exit(-1);
  }
}


void
syscall_init (void) 
{ 
  lock_init(&TOTAL_LOCK);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
 
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf("syscall# : %d!!\n",(int)*(char*)(f->esp));
  // hex_dump(f->esp,f->esp,300,true);
  //printf ("system call!\n");
  void *stack_pointer = f->esp;
  uint32_t *esp = f->esp;
  switch(*(uint32_t*)stack_pointer){
    case SYS_HALT:  //0
      //printf("SYS_HALT!!\n");
      halt();
      break;
    
    case SYS_EXIT:  //1
      //printf("SYS_EXIT!!\n");
      check_address(stack_pointer+4);
      exit(*(uint32_t*)(stack_pointer+4));
      break;
    
    case SYS_EXEC:  //2
      //printf("SYS_EXEC!!\n");
      check_address(stack_pointer+4);
      f->eax=exec((const char*)*(uint32_t*)(stack_pointer+4));
      break;
    
    case SYS_WAIT:  //3
      //printf("SYS_WAIT!!\n");
      check_address(stack_pointer+4);
      f->eax=wait(*(uint32_t*)(stack_pointer+4));
      break;

    case SYS_CREATE:  //4
      check_address(stack_pointer+4);
      check_address(stack_pointer+8);
      f->eax=create((const char*)*(uint32_t*)(stack_pointer+4),*(uint32_t*)(stack_pointer+8));
      break;

    case SYS_REMOVE:  //5
      check_address(stack_pointer+4);
      f->eax=remove((const char*)*(uint32_t*)(stack_pointer+4));
      break;

    case SYS_OPEN:  //6
      check_address(stack_pointer+4);
      f->eax=open((const char*)*(uint32_t*)(stack_pointer+4));
      break;

    case SYS_FILESIZE:  //7
      check_address(stack_pointer+4);
      f->eax=filesize((int)*(uint32_t*)(stack_pointer+4));
      break;

    case SYS_READ:  //8
      //printf("SYS_READ!!\n");
      check_address(stack_pointer+4);
      check_address(stack_pointer+8);
      check_address(stack_pointer+12);
      f->eax=read((int)*(uint32_t*)(stack_pointer+4),(void*)*(uint32_t*)(stack_pointer+8),(unsigned int)*(uint32_t*)(stack_pointer+12));
      break;

    case SYS_WRITE: //9
      //printf("SYS_WRITE!!\n");
      check_address(stack_pointer+4);
      check_address(stack_pointer+8);
      check_address(stack_pointer+12);
      f->eax=write((int)*(uint32_t*)(stack_pointer+4),(void*)*(uint32_t*)(stack_pointer+8),(unsigned int)*(uint32_t*)(stack_pointer+12));
      break;

    case SYS_SEEK:  //10
      check_address(stack_pointer+4);
      check_address(stack_pointer+8);
      seek((int)*(uint32_t*)(stack_pointer+4),*(uint32_t*)(stack_pointer+8));
      break;

    case SYS_TELL:  //11
      check_address(stack_pointer+4);
      f->eax=tell((int)*(uint32_t*)(stack_pointer+4));
      break;

    case SYS_CLOSE: //12
      check_address(stack_pointer+4);
      close((int)*(uint32_t*)(stack_pointer+4));
      break;

    case SYS_FIBONACCI:
      check_address(stack_pointer+4);
      f->eax=fibonacci((int)*(uint32_t*)(stack_pointer+4));
      break;

    case SYS_MAX_OF_FOUR_INT:
      check_address(stack_pointer+4);
      check_address(stack_pointer+8);
      check_address(stack_pointer+12);
      check_address(stack_pointer+16);
      f->eax=max_of_four_int((int)*(uint32_t*)(stack_pointer+4),(int)*(uint32_t*)(stack_pointer+8),(int)*(uint32_t*)(stack_pointer+12),(int)*(uint32_t*)(stack_pointer+16));
      break;
  }
}

void halt(){
  shutdown_power_off();
}

void exit(int status){
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n",thread_name(),status);
  cur->exit_status=status;

  ///proj2 추가
  /////////////////////////////////////////////////////////////////////////////////
  struct thread* tmp=NULL;
  struct list_elem* e;
  for(e=list_begin(&(cur->children));e!=list_end(&(cur->children));e=list_next(e)){
    tmp=list_entry(e,struct thread,child_elem);
    process_wait(tmp->tid); //부모가 먼저 죽지 않도록 : 메모리 누수 방지
  }

  //현재 running file 쓰기 허용 : file_allow_write(running_file) == file_close
  file_close(cur->currently_running_file);
  for(int i=3;i<128;i++){
    if(cur->file_table[i]!=NULL){ //메모리 누수 방지 fd 전부 닫기
      close(i);
    }
  }
  /////////////////////////////////////////////////////////////////////////////////
  
  thread_exit();
}

tid_t exec(const char *cmd_line){
  return process_execute(cmd_line);
}
 
int wait(tid_t pid){
  return process_wait(pid);
}

//fd에서 size만큼 읽어와서 buffer에 저장
int read(int fd, void *buffer, unsigned int size){
  check_address(buffer);
  ///////////////////////////
  lock_acquire(&TOTAL_LOCK);
  ///////////////////////////

  if (fd==0) {  //STDIN
    for (unsigned i = 0; i < size; i++) {
      *((uint8_t *)buffer + i) = input_getc();
    }
    
    ///////////////////////////
    lock_release(&TOTAL_LOCK);
    ///////////////////////////

    return size;
  }
  else if(fd>=3&&fd<=127){
    struct thread* t = thread_current();
    if(t->file_table[fd]==NULL){  //없는 경우
      
      ///////////////////////////
      lock_release(&TOTAL_LOCK);
      ///////////////////////////

      exit(-1);
    }
    int ret = file_read(t->file_table[fd],buffer,size);
    
    ///////////////////////////
    lock_release(&TOTAL_LOCK);
    ///////////////////////////

    return ret;
  }
  else{
    
    ///////////////////////////
    lock_release(&TOTAL_LOCK);
    ///////////////////////////

    exit(-1);
  }
}

int write(int fd, void *buffer, unsigned int size){
  check_address(buffer);

  ///////////////////////////
  lock_acquire(&TOTAL_LOCK);
  ///////////////////////////
  
  if(fd==1){  //STDOUT
    putbuf(buffer,size);

    ///////////////////////////
    lock_release(&TOTAL_LOCK);
    ///////////////////////////

    return size;
  }
  else if(fd>=3&&fd<=127){  //else
    struct thread* t = thread_current();  
    if(t->file_table[fd]==NULL){  //해당 file_descriptor가 NULL인 경우 exit(-1)

      ///////////////////////////
      lock_release(&TOTAL_LOCK);
      ///////////////////////////

      exit(-1);
    }
    int ret = file_write(t->file_table[fd],buffer,size);

    ///////////////////////////
    lock_release(&TOTAL_LOCK);
    ///////////////////////////

    return ret;
  }
  else{

    ///////////////////////////
    lock_release(&TOTAL_LOCK);
    ///////////////////////////

    exit(-1);
  }
}
 
//additional.c 구현
int fibonacci(int n) {
  if(n==0) return 0;
  else if(n==1) return 1;
  else return fibonacci(n-1)+fibonacci(n-2);
}

int max_of_four_int(int a, int b, int c, int d) {
  int max=a;
  if(b>max) max=b;
  if(c>max) max=c;
  if(d>max) max=d;
  return max;
}

//proj2 filesystem syscall 구현
// create, remove, open, close, filesize, seek, tell , / read,write수정
bool create(const char *file, off_t initial_size){
  check_address(file);
  return filesys_create(file, initial_size);
}

bool remove(const char *file){
  check_address(file);
  return filesys_remove(file);
}

int open(const char *file){
  check_address(file);
  struct file *open_file;
  struct thread* t = thread_current();

  ///////////////////////////
  lock_acquire(&TOTAL_LOCK);
  ///////////////////////////

  open_file = filesys_open(file);
  if(open_file==NULL){  //해당 file이 없는 경우

    ///////////////////////////
    lock_release(&TOTAL_LOCK);
    ///////////////////////////

    return -1;
  }
  for(int i=3;i<128;i++){
    if(t->file_table[i]==NULL){ //가장 작은 빈 fd에 할당
      t->file_table[i]=open_file;

      ///////////////////////////
      lock_release(&TOTAL_LOCK);
      ///////////////////////////

      return i;
    }
  }

  ///////////////////////////
  lock_release(&TOTAL_LOCK);
  ///////////////////////////

  return -1;  //fd table이 full인 경우
}

void close(int fd){
  struct thread* t = thread_current();
  if(t->file_table[fd]==NULL){
    exit(-1);
  }
  file_close(t->file_table[fd]);  //free
  t->file_table[fd]=NULL; //초기화
}

int filesize(int fd){
  struct thread* t = thread_current();
  if(t->file_table[fd]==NULL){
    exit(-1);
  }
  return file_length(t->file_table[fd]);
}

void seek(int fd, off_t offset){
  struct thread* t = thread_current();
  if(t->file_table[fd]==NULL){
    exit(-1);
  }
  file_seek(t->file_table[fd], offset);
}

off_t tell(int fd){
  struct thread* t = thread_current();
  if(t->file_table[fd]==NULL){
    exit(-1);
  }
  return file_tell(t->file_table[fd]);
}