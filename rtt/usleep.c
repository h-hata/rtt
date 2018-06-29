#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <pthread.h>

static int flag=0;
void *callin_start(void *ctx);
typedef void (*c100_t)(void);
int thread_create_linux(pthread_t *tid, void *(*entry)(void *), void *arg);
static c100_t c100;
void callin_100ms(c100_t callback){
	pthread_t tid;
	if(flag==1){
		return;
	}
	c100=callback;
	thread_create_linux(&tid,	callin_start,NULL);
}
static void called(void)
{
	if(c100 != NULL){
		c100();
	}
}

void *callin_start(void *ctx)
{
	struct timeval now,old;
	gettimeofday(&old,NULL);
	for(flag=1;flag;){
		usleep(20000);
		gettimeofday(&now,NULL);
		if(now.tv_usec/100000 != old.tv_usec/100000){
			called();
			old=now;
		}
	}
	return NULL;
}

int thread_create_linux(pthread_t *tid, void *(*entry)(void *), void *arg)
{
  pthread_attr_t  attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr,256*1024);
	pthread_attr_setdetachstate(&attr , PTHREAD_CREATE_DETACHED);
	return pthread_create(tid,&attr,entry,arg);
}
void ccc(void){
	printf("ccc\n");
}
#ifdef USLEEP
void main(void)
{
	callin_100ms(ccc);
	sleep(5);
}
#endif

