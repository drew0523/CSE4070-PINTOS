#include <stdio.h>
#include <syscall.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  if(argc != 5) {
      printf("Usage: ./additional [num 1] [num 2] [num 3] [num 4]\n");
      return EXIT_FAILURE;
  }
  
  printf("%d %d\n", fibonacci(atoi(argv[1])), 
    max_of_four_int(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4])));

  return EXIT_SUCCESS;
}
