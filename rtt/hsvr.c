/*
===================================================
Name        : hsvr.c  libevent wrapper
Author      : H.Hata
Version     :
Copyright   : NTTcom
Description : Ansi-style
======================================================
*/
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#define strcasecmp(x,y) _stricmp(x,y)
#define THREAD_CC   __cdecl
#define THREAD_TYPE DWORD
#define THREAD_CREATE(tid, entry, arg) do{ _beginthread((entry),0,(arg));\
            (tid)=GetCurrentThreadId();\
        }while(0)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#define THREAD_CC *
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(tid, entry, arg) thread_create_linux(&(tid), (entry),     (arg))
#endif
#include <event2/bufferevent.h>
#include <event2/bufferevent_compat.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/thread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "hsvr.h"
#include "storage.h"
#define STACK_SIZE (256*1024)
#define	SESSION_MAX		4000
#define BUFF_LEN	64000
#define PORT 3002
#define PEERPORT 80
#define PEERADDR "127.0.0.1"
#define THREAD_NUM	16
#define RECV_TIMER 60 
#define OUTPUT_BUFFER_LOWER 128000
#define OUTPUT_BUFFER_UPPER 1024000

unsigned int accept_counter=0;
unsigned int session_highwatermark=0;
unsigned int session_gauge=0;
unsigned int session_error=0;
unsigned int discarded_octet=0;
unsigned int discarded_packet=0;
unsigned int rxoctet=0;
unsigned int rx=0;
unsigned int txoctet=0;
unsigned int tx=0;
unsigned int rxtimeout=0;
unsigned int connect_error=0;
unsigned int pool_session[THREAD_NUM]={0};


static char msg[1024];
static struct event_base *base;
static struct event_base *base_pool[THREAD_NUM];
static int use_ssl = 0;
static unsigned int session_max=SESSION_MAX;
static SSL_CTX *ssl_ctx = NULL;
static pthread_mutex_t *lock_cs;
static pthread_mutex_t free_lock;
static int thread_num=1;

//---------------------------------------------
static void signal_cb(evutil_socket_t sig, short events, void *ctx);
static void freeSession(SESSION *self);
static void writecb_forClose(struct bufferevent *bev,void *ctx);
static void writecb_forRelease(struct bufferevent *bev,void *ctx);
static void readcb(struct bufferevent *bev,void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);
static void acceptcb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *a, int slen, void *p);
static void fatal_cb(int err);
static void timecb(evutil_socket_t fd, short what, void *ctx);
static int seed_prng(void);
static int  init_OpenSSL(void);
static SSL_CTX  *setup_server_ctx(char *cert_file,char *priv_file);
static int TLS_Init(void);
static unsigned long pthreads_thread_id(void);
static void pthreads_locking_callback(int mode, int type, 
	          const char *file, int line);
static int thread_setup(void);
static void thread_cleanup(void);
static int thread_create_linux(pthread_t *tid,
	void *(*entry)(void *), void *arg);
static void exec_s_stop(evutil_socket_t sig, short events, void *ctx);
//---------------------------------------------

static	CALLBACK_T callback=NULL;

#define LOG_MSG
#ifdef LOG_MSG
void log_msg(char *msg)
{
	puts(msg);
}
#else
extern void log_out(char *msg);
#define log_msg log_out
#endif
static void exec_s_stop(evutil_socket_t sig, short events, void *ctx)
{
	int i;
	struct event_base *base = (struct event_base*)ctx;
	struct timeval delay = { 0, 100 };
	event_base_loopexit(base, &delay);
	sprintf(msg,"session_gauge=%u",session_gauge);log_msg(msg);
	sprintf(msg,"session_high=%u",session_highwatermark);log_msg(msg);
	sprintf(msg,"accept_counter=%u",accept_counter);log_msg(msg);
	sprintf(msg,"session_error=%u",session_error);log_msg(msg);
	sprintf(msg,"rxoctet=%u",rxoctet);log_msg(msg);
	sprintf(msg,"rxcount=%u",rx);log_msg(msg);
	sprintf(msg,"txoctet=%u",txoctet);log_msg(msg);
	sprintf(msg,"txcount=%u",tx);log_msg(msg);
	sprintf(msg,"rxtimeout=%u",rxtimeout);log_msg(msg);
	sprintf(msg,"discarded_octet=%u",discarded_octet);log_msg(msg);
	sprintf(msg,"discarded_packet=%u",discarded_packet);log_msg(msg);
	sprintf(msg,"connect_error=%u",connect_error);log_msg(msg);
	for(i=0;i<thread_num;i++){
		sprintf(msg,"thread %d session=%u",i,pool_session[i]);
		log_msg(msg);
	}
}
static void signal_cb(evutil_socket_t sig, short events, void *ctx)
{
	log_msg("Caught an SIG");
	exec_s_stop(sig, events, ctx);
}

static void freeSession(SESSION *self)
{
	struct evbuffer *ev;
	struct bufferevent *bev;
	size_t len;
	if(0!=pthread_mutex_lock(&free_lock)){
		return ;
	}
	self->status=99;
	bev=self->ubev;
	ev=bufferevent_get_output(bev);
	/*送信データ残があるか？*/
	len=evbuffer_get_length(ev);
	if(len!=0){
		/*送信完了通知ハンドラをセットする*/
		bufferevent_setwatermark(bev,EV_WRITE,0,0);
		bufferevent_setcb(bev,readcb,writecb_forClose,eventcb,self);
		//bufferevent_disable(self->bev,EV_READ);//受信停止
		pthread_mutex_unlock(&free_lock);
		return;
	}
	/*自端を閉じる*/
	bufferevent_free(self->bev);
	releaseSession(self);
#ifdef DEBUG
	sprintf(msg,
		"closed session(%d)\n Rx:%zd / %zd octet\n Tx:%zd /  %zd octet",
		self->id,self->rx,self->rxoctet,self->tx,self->txoctet);
	log_msg(msg);
#endif
	rx+=(unsigned int)self->rx;
	rxoctet+=(unsigned int)self->rxoctet;
	tx+=(unsigned int)self->tx;
	txoctet+=(unsigned int)self->txoctet;
	rxtimeout+=(unsigned int)self->timeout;
	free(self);
	session_gauge--;
	pthread_mutex_unlock(&free_lock);
}
static void writecb_forClose(struct bufferevent *bev,void *ctx)
{
#ifdef DEBUG
	log_msg("writecb");
#endif
	freeSession((SESSION *)ctx);
}

static void writecb_forRelease(struct bufferevent *bev,void *ctx)
{
	SESSION *s=(SESSION *)ctx;
	bufferevent_setcb(bev, readcb, NULL,eventcb,ctx);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	s->writewait=0;//輻輳解除
}

static void readcb(struct bufferevent *bev,void *ctx)
{
	SESSION *self;
	struct evbuffer *src ;
	//size_t len;
	int n;
	unsigned char sbuff[BUFF_LEN];
	
#ifdef DEBUG
	//sprintf(msg,"readcb <<<<<<IN %u",pthread_self());
	//log_msg(msg);
#endif
	self = (SESSION *)ctx;
	src = bufferevent_get_input(bev);//自側
	//len = evbuffer_get_length(src);
	memset(sbuff,0,BUFF_LEN);
	self->buff=sbuff;
	n=evbuffer_remove(src,self->buff,BUFF_LEN-8);
	if(n<=0){
		sprintf(msg,"event_remove error %d",n);
		log_msg(msg);
		return ;
	}
	self->blen = (size_t)n;
	self->rx++;
	self->rxoctet+=(size_t)n;
	//ここでコールバックcallback
	if(callback && self->status!=99){
		(*callback)(TYP_READ,self);
	}
	return;
}


static void eventcb(struct bufferevent *bev, short what, void *ctx)
{
	SESSION *self;
	unsigned long err;
	int err2;
	char *emsg;
	char *lib;
	char *func;

#ifdef DEBUG
	sprintf(msg,"eventcb %X",what);
	if(what & 1) log_msg("EV_READ");
	if(what & 2) log_msg("EV_WRITE");
	if(what & 0x10) log_msg("EV_EOF");
	if(what & 0x20) log_msg("EV_ERR");
	if(what & 0x40) log_msg("EV_TIMEOUT");
	if(what & 0x80) log_msg("EV_CONNECT");
	log_msg(msg);
#endif
	self=ctx;
	if (what&BEV_EVENT_ERROR) {//エラー発生
		err2 = EVUTIL_SOCKET_ERROR();
		sprintf(msg, "Got an error %d (%s) on the listener. ",
						err2, evutil_socket_error_to_string(err2));
		log_msg(msg);
		//エラー出力
		while ((err = (bufferevent_get_openssl_error(bev)))) {
			emsg=(char *)ERR_reason_error_string(err);
			lib=(char*)ERR_lib_error_string(err);
			func=(char*)ERR_func_error_string(err);
			sprintf(msg,"OpenSSL Error: %s in %s %s",emsg,lib,func);
			log_msg(msg);
		}
		if (errno){
			sprintf(msg,"Connection Error errno=%d",errno);
			log_msg(msg);
		}
		//コネクションが閉じられます
		freeSession(self);
	}else if(what & BEV_EVENT_EOF){//ピア端クローズ
		//ここでコールバック callback
		if(callback && self->status!=99){
			(*callback)(TYP_TERM,self);
		}
		//コネクションが閉じられます
		freeSession(self);
	}else if(what & BEV_EVENT_TIMEOUT){//受信タイムアウト
		self->timeout++;
#ifdef DEBUG
		log_msg("Session Timeout");
#endif
		//ここでコールバック callback
		if(callback && self->status!=99){
			(*callback)(TYP_TIMEOUT,self);
		}
	}else if (what & BEV_EVENT_CONNECTED) {
		//このライブラリはサーバようなので
		//CONNECTEDイベントは発生しないはず
	}
}

static void acceptcb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *a, int slen, void *p)
{
	struct bufferevent *bev_cli;
	struct bufferevent *bev_ssl=NULL;
	struct sockaddr_in *sa;
	unsigned int  tid;
	SESSION *ses_cli;

#ifdef DEBUG
	sprintf(msg,"acceptcb sid=%d tid=%u",
			accept_counter+1,(int)pthread_self());
	log_msg(msg);
#endif
	sa=(struct sockaddr_in *)a;
	tid=accept_counter%(unsigned int)thread_num;
	pool_session[tid]++;
	bev_cli = bufferevent_socket_new(base_pool[tid], fd,
	    BEV_OPT_CLOSE_ON_FREE
		|BEV_OPT_DEFER_CALLBACKS
		|BEV_OPT_THREADSAFE
			);
	if(session_gauge>session_max){
//#ifdef DEBUG
		sprintf(msg," session max limit gauge=%u",session_gauge);
		log_msg(msg);
//#endif
		//セッション数過大でTCP切断
		//何らかの代理応答を返す場合はここでそのプロシージャを呼ぶ
		//Todo: ReplyError(brv_cli);
		bufferevent_free(bev_cli);
		printf("Error1\n");
		session_error++;
		//exit(0);//For debug
		return;
	}
	//SSLならハンドシェークを行う
	if (ssl_ctx) {
		SSL *ssl = SSL_new(ssl_ctx);
		bev_ssl = bufferevent_openssl_filter_new(base_pool[tid],
		    bev_cli, ssl, BUFFEREVENT_SSL_ACCEPTING,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		if (!bev_ssl) {
			log_msg("bufferevent_openssl_filter_new Error");
			bufferevent_free(bev_cli);
			return;
		}
		//クライアント側イベントをTLSイベントで上書きする
#ifdef DEBUG
		log_msg("TLS Handshake Success");
#endif
	}

	ses_cli=(SESSION *)malloc(sizeof(SESSION));
	if(ses_cli==NULL){
		log_msg(" malloc error");
		if(bev_ssl!=NULL){
			bufferevent_free(bev_ssl);
		}else{
			bufferevent_free(bev_cli);
		}
		printf("ERROR2");
		return;
	}
	if(0!=pthread_mutex_lock(&free_lock)){
		return ;
	}
	session_gauge++;//Racing with freeSession
	pthread_mutex_unlock(&free_lock);
	if(session_highwatermark<session_gauge){
		session_highwatermark=session_gauge;
	}
	accept_counter++;
	memset(ses_cli,0,sizeof(SESSION));
	ses_cli->id=accept_counter;
	ses_cli->ubev=bev_cli;//アンダーレイ
	if(bev_ssl!=NULL){
		ses_cli->bev=bev_ssl;//ＳＳＬ
	}else{
		ses_cli->bev=bev_cli;
	}
	strncpy(ses_cli->host,inet_ntoa(sa->sin_addr),31);
	ses_cli->port=ntohs((uint16_t)sa->sin_port);
	addSession(ses_cli);
#ifdef DEBUG
	sprintf(msg,"session start counter=%d gauge=%d",
			accept_counter,session_gauge);
	log_msg(msg);
	sprintf(msg,"peer=%s port=%d",ses_cli->host,ses_cli->port);
	log_msg(msg);
#endif
	//ここでコールバックcallback
	bufferevent_settimeout(ses_cli->bev,RECV_TIMER,0);
	if(callback){
		(*callback)(TYP_ACCEPT,ses_cli);
	}
	bufferevent_setcb(ses_cli->bev, readcb, NULL, eventcb, ses_cli);
	bufferevent_enable(ses_cli->bev, EV_READ|EV_WRITE);
}

static void fatal_cb(int err)
{
	sprintf(msg,"Err:%d\n",err);
	log_msg(msg);
	_exit(1);
}
static void timecb(evutil_socket_t fd, short what, void *ctx)
{
	return ;
}

void *thread_start(void *ctx){
	struct event_base *base = (struct event_base*)ctx;
	struct event *ev;
	struct timeval tv = {1,0};
	pthread_t pt; 
#ifdef DEBUG
	sprintf(msg,"Thread %u start",(int)pthread_self());
	log_msg(msg);
#endif
	pt=pthread_self();
	ev=event_new(base, -1,EV_TIMEOUT|EV_PERSIST, timecb,&pt);
	event_add(ev,&tv);
	event_base_dispatch(base);
	event_free(ev);
	event_base_free(base);
#ifdef DEBUG
	sprintf(msg,"Thread %d quit ",(int)pthread_self());
	log_msg(msg);
#endif
	return NULL;
}
/**
 *   @brief 乱数初期化
 *     */
static int seed_prng(void)
{
	unsigned short rand_ret;
	int i;
	srand((unsigned int)time(NULL));
	RAND_poll();
	for(i=1; i<1000; i++){
		rand_ret = (unsigned short)(rand() % 65536);
		RAND_seed(&rand_ret, sizeof(rand_ret));
		if(RAND_status()!=0) return i;
	}
	return 0;
}
static int  init_OpenSSL(void)
{
	if(!SSL_library_init()){
		log_msg("** OpenSSL init failed");
		return -1;
	}
	SSL_load_error_strings();
	return 0;
}

/*Create Server CTX*/
static SSL_CTX  *setup_server_ctx(char *cert_file,char *priv_file)
{
	SSL_CTX *actx;
	//actx=SSL_CTX_new(TLSv1_1_server_method());
	actx=SSL_CTX_new(SSLv23_method());
	if(actx==NULL) {
		log_msg("setup_server_ctx is ");
	return NULL;
	}
	//Read Server certification
	if(SSL_CTX_use_certificate_chain_file(actx,cert_file)!=1){
		log_msg("setup_server_ctx Server Cert invalid");
		SSL_CTX_free(actx);
		return NULL;
	}
	//Read private key file
	if(SSL_CTX_use_RSAPrivateKey_file(actx,priv_file,SSL_FILETYPE_PEM)!=1){
		SSL_CTX_free(actx);
		log_msg("setup_server_ctx RSA Keyfile invalid");
		return NULL;
	}
	return actx;
}


static int TLS_Init(void)
{
	static int init=0;
	if(init){
		return 0;
	}
	init_OpenSSL();
	if(0==seed_prng()){
		return -10;
	}
	if(0!=thread_setup()){
		return -30;
	}
	init=1;
	return 0;
}

SESSION* S_search(char *ip,uint16_t port)
{
	int iport;
	iport=(int)port & 0xFFFF;
	return searchSession(ip,iport);
}


void S_settimer(SESSION *s,int t)
{
	struct bufferevent *bev;
	if(s==NULL){
		return ;
	}
	if(s->bev==NULL){
		return ;
	}
	bev=s->bev;
	bufferevent_settimeout(bev,t,0);
}
int S_send(SESSION *s,unsigned char *data,size_t slen)
{
	struct bufferevent *bev;
	struct bufferevent *ubev;
	struct evbuffer *ev;
	size_t blen;
	int ret;
	if(s==NULL){
		return -1;
	}
	if(s->bev==NULL){
		return -1;
	}
	bev=s->bev;
	if(data==NULL || slen==0){
		return -2;
	}
	//輻輳検査
	//すでに規制中
	if(s->writewait!=0){
		return -4;
	}
	//バッファ長検査
	
	ubev=s->ubev;
	bufferevent_lock(bev);
	ev=bufferevent_get_output(ubev);
	blen=evbuffer_get_length(ev);
	if(blen!=0){printf("blen=%zd\n",blen);}
	if(blen>OUTPUT_BUFFER_UPPER){
		//輻輳レベル
		s->writewait=1;
		bufferevent_setwatermark(ubev,EV_WRITE,
				OUTPUT_BUFFER_LOWER,OUTPUT_BUFFER_UPPER);
		bufferevent_setcb(ubev,readcb,writecb_forRelease,eventcb,s);
		bufferevent_unlock(bev);
		return -4;
	}
	ret=bufferevent_write(bev,(const void *)data,slen);
	if(ret!=0){printf("ret=%d\n",ret);}
	bufferevent_unlock(bev);
	if(ret==0){
		s->txoctet+=slen;
		s->tx++;
	}
	return ret;
}
void S_close(SESSION *s)
{
	freeSession(s);
}

int S_start(
		uint16_t port,
		int limit,
		int multi,
		CALLBACK_T cb,
		int tls,
		char *cert,
		char *priv)
{
	int socklen;
	struct evconnlistener *listener;
	struct sockaddr localaddr;
	struct sockaddr_in *sin;
	struct event *signal_event;
	struct sigaction sa;
	pthread_t thread;
	int i;
	use_ssl=tls;
	if(limit<=0){
		session_max=SESSION_MAX;
	}else{
		session_max=(unsigned int)limit;
	}
	if(multi<=0){
		thread_num=1;
	}else if(multi>=THREAD_NUM){
		thread_num=THREAD_NUM;
	}else{
		thread_num=multi;
	}
	callback=cb;
	/* Ignore SIPGPIPE due to rude peers*/
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&(sa.sa_mask));
	sigaction(SIGPIPE, &sa, 0);

	pthread_mutex_init(&free_lock,NULL);
	initStorage();	
	event_set_fatal_callback(fatal_cb);
	/* Self IP Address Information */
	memset(&localaddr, 0, sizeof(struct sockaddr));
	socklen = sizeof(struct sockaddr_in);
	sin = (struct sockaddr_in*)&localaddr;
	sin->sin_port = htons(port);
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	sin->sin_family = AF_INET;
	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		return 1;
	}
	if (use_ssl) {
		int r;
		r=TLS_Init();
		if (r != 0) {
			fprintf(stderr, "RAND_poll() failed.%d \n",r);
			return 1;
		}
		ssl_ctx = setup_server_ctx(cert,priv);
		if(ssl_ctx==NULL){
			log_msg("TLS Server setup Error");
			return 2;
		}

	}
	evthread_use_pthreads();
	  /* スレッド生成*/
	for(i=0;i<thread_num;i++){
		base_pool[i] = event_base_new();
		if(THREAD_CREATE(thread, thread_start,base_pool[i])  !=0)
			log_msg("THREAD_CREATE Error");
	}
	listener = evconnlistener_new_bind(base, acceptcb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|
			LEV_OPT_REUSEABLE,
	    -1, &localaddr, socklen);
	if (! listener) {
		log_msg("Couldn't open listener.");
		event_base_free(base);
		return 1;
	}
	signal_event = evsignal_new(base, SIGINT, signal_cb, (void *)base);
	if (!signal_event || event_add(signal_event, NULL)<0) {
		log_msg("Could not create/add a signal event!");
		return 1;
	}
	signal_event = evsignal_new(base, SIGTERM, signal_cb, (void *)base);
	if (!signal_event || event_add(signal_event, NULL)<0) {
		log_msg("Could not create/add a signal event!");
		return 1;
	}
	event_base_dispatch(base);
	log_msg("event_base_dispatch exits");
	evconnlistener_free(listener);
	event_base_free(base);
	if (use_ssl) {
		thread_cleanup();
	}
	return 0;
}

/************************************
 *  * Mutithreading Facilities         *
 *   * **********************************/
static unsigned long pthreads_thread_id(void)
{
	  return(unsigned long)pthread_self();
}
static void pthreads_locking_callback(int mode, int type, 
	          const char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lock_cs[type]));
  } else {
    pthread_mutex_unlock(&(lock_cs[type]));
  }
}
static int thread_setup(void)
{
	int i;
	int n;
	n=CRYPTO_num_locks();
	lock_cs=OPENSSL_malloc(n*(int)sizeof(pthread_mutex_t));
	if(lock_cs==NULL){
		return -1; 
	}
	for (i=0; i<n; i++){
		pthread_mutex_init(&(lock_cs[i]),NULL);
	}
	CRYPTO_set_id_callback(pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
 	return 0;
}

static void thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
}

int thread_create_linux(pthread_t *tid, void *(*entry)(void *), void *arg)
{
	pthread_attr_t  attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr,STACK_SIZE);
	pthread_attr_setdetachstate(&attr , PTHREAD_CREATE_DETACHED);
	return pthread_create(tid,&attr,entry,arg);

}

