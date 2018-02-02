
#include <stdio.h>

extern void self_test(void);

int main(void) {
   self_test();
   printf("Done\n");

   return 0;
}
