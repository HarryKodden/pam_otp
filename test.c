
#include <stdio.h>
#include <time.h>

#include "otp.h"

extern void self_test(void);

int main(int argc, char **argv) {
   if (argc == 2) {
     printf("Token: %06d\n", token(argv[1], time(NULL)));
   } else {
     self_test();
   }
   printf("Done\n");

   return 0;
}
