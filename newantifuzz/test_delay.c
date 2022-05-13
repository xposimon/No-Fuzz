#include<stdio.h>

#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>

//#define ARCH_x86
#define abs(x) ((a>0)?(a):(-a))

void in_loop(){ int a=0, b=1, i; for (i =0 ; i < 1000; i++)a+=b; return;}

void delay(void)
{
  fd_set set;
  struct timeval timeout;
  int rv;
  char buff[100];
  int len = 100;
  int filedesc = open( "/dev/ttyS0", O_RDWR );

  FD_ZERO(&set); /* clear the set */
  FD_SET(filedesc, &set); /* add our file descriptor to the set */

  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  rv = select(filedesc + 1, &set, NULL, NULL, &timeout);
  
  if(rv == -1)
    perror("select"); /* an error accured */
  else if(rv == 0)
    printf("timeout"); /* a timeout occured */
  else
    read( filedesc, buff, len ); /* there was data to read */
  close(filedesc);
}

uint64_t inline rdtsc(){
    unsigned int lo,hi;
    __asm__ ("CPUID");
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

void inline anti_fuzz(){
    // direct delay, can be replaced by a series of calculations or even abort/block the program
    //sleep(5);
    delay();
}

void detect() {
    unsigned long long t2 , t1, t3, t4;
    unsigned long long diff1, diff2;   
    
    t3 = rdtsc () ;  
    in_loop();
    t4 = rdtsc () ;
   
    t1 = rdtsc () ;
    int a=0, b=1, i;
    for (i =0 ; i < 1000; i++)a+=b;
    t2 = rdtsc () ;
    
    diff1 =  (t2-t1);
    diff2 =  (t4-t3);  

    double perc = (double)(diff2)/(diff1) * 100;
    printf("%llu, %llu, %lf\n", diff2, diff1, perc);
    if (perc > 130 || perc < 70) anti_fuzz();
}
unsigned long long atfz_t1 , atfz_t2;
int main(){
    detect();
    int a = 2;
    a ++;
    int b = a*15;
    detect();
    a--;
    char c='c';
    c++;
detect();
    __asm__("branch13:");
    atfz_t1 = rdtsc () ;atfz_t2=0;
    if (a){
    atfz_t2 = rdtsc () ;if (atfz_t2 - atfz_t1 > 20000)anti_fuzz();
        //uint64_t* ip = (uint64_t*)get_ip();
        
        //printf("a>3\n");

    }
    if (!atfz_t2) {atfz_t2=rdtsc();if (atfz_t2 - atfz_t1 > 20000)anti_fuzz();}
    

    atfz_t1 = rdtsc () ;atfz_t2=0;
    if (b){
    atfz_t2 = rdtsc () ;if (atfz_t2 - atfz_t1 > 20000)anti_fuzz();
       
    }
    if (!atfz_t2) {atfz_t2=rdtsc();if (atfz_t2 - atfz_t1 > 20000)anti_fuzz();}

    return 0;
}

void detect() __attribute__((always_inline));
