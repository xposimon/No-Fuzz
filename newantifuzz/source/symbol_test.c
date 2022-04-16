#include<stdio.h>
#include<stdlib.h>

long gs(long a)
{
    if(a>1000 || a<=1) return a;
    double num = (double)1-(double)1/(a);
    double base = 1, sum = 0;
    int cnt = 0;
    while((double)(a) - sum >= 0.49){
        sum += base;
        base *= num;
        cnt ++;
    }
    printf("%d\n", cnt);
    return sum < 0 ? sum - 0.5 : sum + 0.5; 
}


int test_call(int a){
long b = a;
b = gs(b);
    if (b=='A')
    {
        printf("branch\n");
    }
}

int main(){

    int a;
    
    scanf("%d", &a);

    
    test_call(a);

    return 0;
}

