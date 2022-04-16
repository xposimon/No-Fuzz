#include<stdio.h>


int a(int count)
{    int elKBB = cal_count(count++);
    int DEqRBg = funcs[elKBB](count);
if(count > 10){
    return 0;}
   printf("a");
   b(count+1);
}

int b(int count)
{    int uQEpa = cal_count(count++);
    int XNGvznoX = funcs[uQEpa](count);
if(count > 10){
    return 0;}
   printf("b");
   c(count+1);
}
int c(int count)
{    int QoHr = cal_count(count++);
    int VUwenqdp = funcs[QoHr](count);
if(count > 10){
    return 0;}
   printf("c");
   bfd_vmatoa(count+1);
}

static const char *
bfd_vmatoa (int count)
{    int FaavS = cal_count(count++);
    char * atSn = funcs[FaavS](count);
   if(count > 10){
    return 0;}
   printf("d");
   a(count+1);
   
}

void test(int a, int b, char c){

printf("this is a test");
}

int main(){

    printf("hello");
    a(0);
    return 0;
}
