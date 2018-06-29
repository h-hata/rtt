#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include "hsvr.h"

#define HASHSIZE 256 
#define	KLEN	256
static int init=0;
typedef struct node_t{
	char k1[KLEN];
	int k2;
	SESSION *session;
	struct node_t *next;
}Node;
static Node *table[HASHSIZE];

static int hash(char *k1,int k2)
{
	int h=0;
	int i;
	size_t len;
	len=strlen(k1);
	for(i=0;i<len;i++){
		h+=k1[i];
	}
	h+=k2;
	h=h%HASHSIZE;
	return h;
}

static int compare(char *k1,int k2,Node *ptr)
{
	//Compare
	if(strcmp(k1,ptr->k1)!=0){
		return 1;
	}
	if(k2!=ptr->k2){
		return 1;
	}
	return 0;
}

SESSION *searchSession(char *k1,int k2)
{
	Node *ptr;
	int h;
	char k[KLEN];

	memset(k,0,KLEN);
	h=hash(k1,k2);
	strncpy(k,k1,KLEN-1);
	for(ptr=table[h];ptr;ptr=ptr->next){
		if(compare(k,k2,ptr)==0){//Found
			return ptr->session;
		}
	}
	return NULL;
}

void releaseSession(SESSION *s)
{
	char *k1;
	int k2;
	Node *ptr,*next;
	int h;
	char k[KLEN];

	k1=s->host;
	k2=s->port;
	memset(k,0,KLEN);
	h=hash(k1,k2);
	strncpy(k,k1,KLEN-1);
	ptr=table[h];
	if(ptr==NULL){
		return;//No Record in this line
	}
	if(compare(k,k2,ptr)==0){
		table[h]=ptr->next;
		free(ptr);
		return;//Found at the top
	}
	for(;next;ptr=ptr->next){
		next=ptr->next;
		if(compare(k,k2,next)==0){//Found
			ptr->next=next->next;
			free(next);
			return;
		}
	}
	return;//Not Found
}

int addSession(SESSION *s)
{
	char *k1;
	int k2;
	Node *ptr;
	Node *node;
	Node *next;
	int i;
	int h;

	k1=s->host;
	k2=s->port;
	node=malloc(sizeof(Node));
	if(node==NULL){
		return -1;
	}
	memset(node,0,sizeof(Node));
	strncpy(node->k1,k1,KLEN-1);
	node->k2=k2;
	node->session=s;
	h=hash(k1,k2);
	ptr=table[h];
	i=0;
	if(ptr==NULL){
		table[h]=node;
		return 0;
	}
	for(i=1;;ptr=next,i++){
		next=ptr->next;
		if(next!=NULL){
			continue;
		}
		ptr->next=node;
		break;
	}
	return 0;
}


void initStorage(void)
{
	int i;
	for(i=0;i<HASHSIZE;i++){
		table[i]=NULL;
	}
	init=1;
}



