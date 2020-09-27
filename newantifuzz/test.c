#include<stdlib.h>
#include<time.h>
#include<stdio.h>
#include<stdio.h>
void ** func_ptr;

typedef int (*intf)(int);

void (*funcs[4]) = {};
int COUNT=10;
int index[1000] = {};

int a(const int count){
    if (count > COUNT){
        return 0;
    }
    printf("a ");
    ((intf)func_ptr[rand()%4])(count+1);
    
}

int b(int count){
if (count > COUNT){
        return 0;
    }
printf("b ");
    ((intf)func_ptr[rand()%4])(count+1);
}

int c(int count){
if (count > COUNT){
        return 0;
    }
printf("c ");
    ((intf)func_ptr[rand()%4])(count+1);
}

int d(int count){
if (count > COUNT){
        return 0;
    }
printf("d ");
    ((intf)func_ptr[rand()%4])(count+1);

}

int cal_count(int count)
{
    if(!count)for (int i = 0; i < 1000; index[i++]=i-1);
    int idx = rand()%(1000-count);
    for (int i = idx; i < 1000-count-1; i++)index[i] = index[i+1];
    return idx;
}



int entry_func()
{

// reset funcs array
// call a randomly call one of them
}

int dec()
{
printf("test");
}

int dec();
int dec();

int main(){
   /*
    printf("pop: %d\n", cal_count(0));
    printf("pop: %d\n", cal_count(1));
    
    time_t t;
    srand((unsigned) time(&t));
    
    funcs[0] = a;funcs[1] = b;
funcs[2] = c; funcs[3] = d;

    func_ptr = funcs;
    int m = dec();
    printf("m:%d\n", m); 
    ((intf)func_ptr[rand()%4])(0);
*/

printf("test\n");
}
