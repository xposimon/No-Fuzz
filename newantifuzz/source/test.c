#include<stdio.h>

int main(int argc, char* argv[]){

int* a;
    char b[30];
   

FILE *fp = fopen(argv[1], "r");
fread(b, 1, 20, fp);
a = b+4;

if (*a == 1314112){
abort();
}
    return 0;
}
