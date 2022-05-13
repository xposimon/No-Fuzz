#include<stdio.h>
#include<sys/types.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define ERR_EXIT(m) \
do\
{\
    perror(m);\
    exit(EXIT_FAILURE);\
}\
while (0);\

#define START_FD 1000
#define ATFZ_ALERT_NUM 60
#define PATROL_TIME 30
#define ATFZ_PREFIX ("/tmp/.atfz_deamon")

size_t at_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t res = fread(ptr, size, nmemb, stream);
    char *cptr = (char *)ptr;
    for(int i = 0; i < size; i++){
        cptr[i] ^= cptr[size-i-1];
        cptr[i] ^= cptr[size-i-1];
    }
    return res;
}

void creat_daemon(void)
{
 
    pid_t pid;
    pid = fork();
   
    if( pid == -1)
        ERR_EXIT("fork error");
    if(pid == 0 )
{
    if(setsid() == -1)
        ERR_EXIT("SETSID ERROR");
    umask(0);

int atfz_cnt = 1;
char atfz_file[30], dest_file[30];
FILE *fp;

sprintf(dest_file, "%s%d", ATFZ_PREFIX, ATFZ_ALERT_NUM);
fp = fopen(dest_file, "r");

if (fp)
    exit(EXIT_SUCCESS);

while (atfz_cnt <= ATFZ_ALERT_NUM){
	sprintf(atfz_file, "%s%d", ATFZ_PREFIX, atfz_cnt);
	fp = fopen(atfz_file, "r");
	if (!fp){
	    break;
	}
	atfz_cnt++;
}

sprintf(atfz_file, "%s%d", ATFZ_PREFIX, atfz_cnt);

fp = fopen(atfz_file, "w");

sleep(PATROL_TIME);

fclose(fp);

printf("%s\n", atfz_file);


if (atfz_cnt < ATFZ_ALERT_NUM)
    remove(atfz_file);

    exit(EXIT_SUCCESS);
}
  
    return;

}

int main(int argc, char *argv[]){

FILE *atfz_fp;
char dest_file[30];
sprintf(dest_file, "%s%d", ATFZ_PREFIX, ATFZ_ALERT_NUM);
atfz_fp = fopen(dest_file, "r");

if (atfz_fp){
    printf("Fuzzer detected!\n");
    abort();
}

creat_daemon();

    int* a;
    char b[30];
   

FILE *fp = fopen(argv[1], "r");
at_fread(b, 1, 20, fp);
a = b+4;
printf("%x\n", *a);
/*int shm_id = shmget(IPC_PRIVATE, 1, IPC_CREAT|0600);
if(shm_id <0){
abort();}
*/
//FILE *fp1 = fopen("/home/zzx/Desktop/benchmark/test/run_res.txt", "a");
//system("ipcs -m | grep `whoami` | awk '{ print $2 }' | xargs -n1 ipcrm -m");

if (*a == 0x6c5d91){
abort();
}
    return 0;
}
