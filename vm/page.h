#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

#define VM_BIN 0
#define VM_MMAP 1
#define VM_ANON 2 

struct PTE{
    void *VPN;
    bool is_loaded;
    bool is_writable;
    struct file* file;
    size_t offset;
    size_t read_bytes;
    size_t write_bytes;
    size_t swap_slot;

    // struct list_elem mm_elem;
    struct hash_elem elem;
    int page_type; 
};

void init_PageTable(struct hash *page_table);   //supplementary page table 생성 함수: 프로세스 별로 소유
bool insert_PTE(struct hash *page_table, struct PTE *pte);  //SPT에 page table entry 삽입 함수
bool delete_PTE(struct hash *page_table, struct PTE *pte);  //SPT에 page table entry 삭제 함수
struct PTE *search_PTE(void *vaddr);    //현재 thread의 SPT에서 VA에 대응하는 PTE 탐색 함수
void destroy_PageTable(struct hash *page_table);    //SPT 제거 함수

#endif