#include <windows.h>
#include <time.h>
#include <stdio.h>


#pragma comment(lib,"Ws2_32.lib")


#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif


extern void dump_packet(void *, size_t len);
SOCKET  s;
typedef struct {
	DWORD type;
	DWORD reply;
	struct timeval t;
	long delay;
}MEMO;
MEMO memo[1024];



long difft(struct timeval *t1, struct timeval *t2)
{
	long d = 0;
	d = (t2->tv_sec - t1->tv_sec) * 1000000;
	if (t1->tv_usec > t2->tv_usec) {
		d -= (t1->tv_usec - t2->tv_usec);
	}
	else {
		d += (t2->tv_usec - t1->tv_usec);
	}
	return d;
}

DWORD gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned __int64 tmpres = 0;
	static int tzflag;

	if (NULL != tv)
	{
		GetSystemTimeAsFileTime(&ft);

		tmpres |= ft.dwHighDateTime;
		tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;

		/*converting file time to unix epoch*/
		tmpres -= DELTA_EPOCH_IN_MICROSECS;
		tmpres /= 10;  /*convert into microseconds*/
		tv->tv_sec = (long)(tmpres / 1000000UL);
		tv->tv_usec = (long)(tmpres % 1000000UL);
	}
	return 0;
}


DWORD check_packet(char *b, DWORD l)
{
	DWORD *ptr;
	DWORD n, sqc;
	struct timeval t;
	DWORD timer;
	long d;
	gettimeofday(&t, NULL);
	ptr = (DWORD *)b;
	if (123 != ntohl(*ptr)) {
		printf("MAGIC error =%ud\n", ntohl(*ptr));
		//dump_packet(b,(size_t)l);
		return -1;
	}
	ptr++;
	n = ntohl(*ptr);
	ptr++;
	sqc = ntohl(*ptr);
	ptr++;
	if (n == 4 || n == 5) {
		if (n != memo[sqc].type) {
			printf("type unmatch\n");
			return -1;
		}
		d = difft(&memo[sqc].t, &t);
		memo[sqc].delay = d;
		memo[sqc].reply = 1;
		printf("recv n=%-6u sqc=%-6u delay=%-8ld\n", n, sqc, d / 1000);
		return n;
	}
	if (n == 7) {
		timer = 10000;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timer, sizeof(timer));
		return n;
	}
	if (n == 2) {
		printf("recv dummy\n");
		return 2;
	}
	return -1;
}
void sendPacket(int s, unsigned char *start, DWORD total)
{
	int j;
	DWORD  len;
	DWORD 	slen = 0;
	for (j = 0; j<10; j++) {
		len = send(s, start + slen, total - slen,0);
		if (len<0) {
			printf("Send error \n");
			s = -1;
			return;
		}
		slen += (size_t)len;
		if (slen<total) {
			continue;
		}
		break;
	}
}

void send_data(DWORD type, DWORD len)
{
	char			buff[2048];
	static int sqc = 0;
	DWORD *ptr;
	struct timeval t;

	memset(buff, 0, 2048);
	ptr = (DWORD *)buff;
	*ptr = htonl(123);//MAGIC
	ptr++;
	*ptr = htonl(type);
	ptr++;
	*ptr = htonl(sqc);
	gettimeofday(&t, NULL);
	memo[sqc].t = t;
	memo[sqc].type = type;
	sendPacket(s, buff, len);
	sqc++;
}

void pattern1(void) {
	int i;

	send_data(7, 32);//START
	for (i = 0; i<10; i++) {
		Sleep(100);
		send_data(4, 64);
	}
	send_data(2,64);
	Sleep(5000);
	send_data(5, 64);
	for (i = 0; i<10; i++) {
		Sleep(100);
		send_data(4, 64);
	}
	send_data(9, 64);
}
void pattern2(void) {
	int i;

	send_data(7, 32);//START
	for (i = 0; i<10; i++) {
		Sleep(100);
		send_data(4, 64);
	}
	Sleep(5000);
	send_data(5, 64);
	for (i = 0; i<10; i++) {
		Sleep(100);
		send_data(4, 64);
	}
	send_data(9, 64);
}

void pattern3(void) {
	int i;

	send_data(7, 32);//START
	for (i = 0; i<50; i++) {
		Sleep(100);
		send_data(4, 64);
	}
	for (i = 0; i<50; i++) {
		Sleep(100);
		send_data(4, 64);
	}
	send_data(9, 64);
}

void *sending_thread(void *p)
{
	Sleep(1000);
	pattern3();
	return NULL;
}

int main(int argc, char **argv)
{
	int 	i;
	char ip[126];
	WORD port;
	struct hostent  	*hent;
	struct sockaddr_in      p_addr;
	char* localIP;
	DWORD 			len;
	DWORD 	ret;
	char			recb[2048];
	struct timeval tv;
	WSADATA wsaData;
	DWORD timer;
	for (i = 0; i<128; i++) {
		memset(&memo[i], 0, sizeof(MEMO));
	}
	strcpy(ip, "www.olt.link");
	port = 9999;
	if (argc == 3) {
		port = (WORD)atoi(argv[2]);
	}
	if (argc >= 2) {
		strncpy(ip, argv[1], 64);
	}

	WSAStartup(MAKEWORD(2, 0), &wsaData);

	s = socket(AF_INET, SOCK_STREAM, 0);

	//*Convert HOST to IP Address**********************************
	//*peerIP
	p_addr.sin_addr.s_addr = inet_addr(ip);
	if (p_addr.sin_addr.s_addr == INADDR_NONE) {
		hent = gethostbyname(ip);
		if (hent == NULL) {
			close(s);
			return -1;
		}
	}
	localIP = inet_ntoa(*(struct in_addr *)*hent->h_addr_list);
	p_addr.sin_addr.s_addr = inet_addr(localIP);
	//p_addr.sin_addr.s_addr=inet_addr(localIP);*(struct in_addr *)hent->h_addr_list[0];
	p_addr.sin_family = AF_INET;
	p_addr.sin_port = htons(port);
	printf("Trying...");
	ret = connect(s, (struct sockaddr *)&p_addr, sizeof(p_addr));
	if (ret == -1) {
		printf("connect error.\n");
		exit(-1);
	}
	printf("connected.\n");
	timer = 5000;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timer, sizeof(timer));
	_beginthread((sending_thread), 0, NULL);
	len = recv(s, recb, 2048,0);
	if (len>0) {
		if (check_packet(recb, len) != 7) {
			printf("illegal recv1\n");
			close(s);
			return -1;
		}
		printf("Start\n");
	}
	else {
		printf("recv1 err\n");
		close(s);
		return -1;
	}
	for (;;) {
		len = recv(s, recb, 2048,0);
		if (len <= 0) {
			break;
		}
		if (check_packet(recb, len)<0) {
			break;
		}
	}
	shutdown(s, 2);
	closesocket(s);
	printf(" completed.\n");
	WSACleanup();
	return 0;
}

