#include<stdio.h>

#include<stdlib.h>
#include<time.h>

#include <sys/mman.h>
#include <stdint.h>

#define abs(x) (a:-a?a>0)

void in_loop(){ int a=0, b=1; for (int i =0 ; i < 1000; i++)a+=b; return;}

uint64_t inline rdtsc(){
    unsigned int lo,hi;
    __asm__ ("CPUID");
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

void detect() __attribute__((always_inline)) {
    unsigned long long t2 , t1, t3, t4;
    unsigned long long diff1, diff2;   
    
    t3 = rdtsc () ;  
    in_loop();
    t4 = rdtsc () ;
   
    t1 = rdtsc () ;
    int a=0, b=1;
    for (int i =0 ; i < 1000; i++)a+=b;
    t2 = rdtsc () ;
    
    diff1 =  (t2-t1);
    diff2 =  (t4-t3);  

    double perc = (double)(diff2)/(diff1) * 100;
    printf("%llu, %llu, %lf\n", diff2, diff1, perc);
    if (perc > 200 || perc < 10) detect();
}






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
detect();


    printf("hello");
    a(0);
    return 0;
}
