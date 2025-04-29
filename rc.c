#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include "network.h"

#define BUFLEN 100
#define QUEUE_SIZE 16
#define MAX_PLAYERS 100
#define MOVE_TIMEOUT_MS (5 * 60 * 1000)  // 5 minutes

volatile sig_atomic_t active = 1;
static char *active_names[MAX_PLAYERS];
static int active_count = 0;
static pthread_mutex_t name_mutex = PTHREAD_MUTEX_INITIALIZER;

struct client { int sock; char name[64]; };
static struct client *waiting = NULL;
static pthread_mutex_t wait_mutex = PTHREAD_MUTEX_INITIALIZER;

void handle_sigint(int sig) { (void)sig; active = 0; }
void install_handlers(void) {
    struct sigaction act = {0};
    act.sa_handler = handle_sigint;
    sigaction(SIGINT, &act, NULL);
}

int register_name(const char *name) {
    pthread_mutex_lock(&name_mutex);
    if (active_count >= MAX_PLAYERS) { pthread_mutex_unlock(&name_mutex); return -1; }
    for (int i = 0; i < active_count; i++) if (strcmp(active_names[i], name)==0) { pthread_mutex_unlock(&name_mutex); return -1; }
    active_names[active_count++] = strdup(name);
    pthread_mutex_unlock(&name_mutex);
    return 0;
}
void unregister_name(const char *name) {
    pthread_mutex_lock(&name_mutex);
    for (int i = 0; i < active_count; i++) {
        if (strcmp(active_names[i], name)==0) {
            free(active_names[i]);
            active_names[i] = active_names[--active_count];
            break;
        }
    }
    pthread_mutex_unlock(&name_mutex);
}

ssize_t read_until_delim(int sock, char *buf, size_t maxlen) {
    size_t total=0;
    while (total+1<maxlen) {
        ssize_t n=read(sock, buf+total,1);
        if (n<=0) return n;
        total+=n;
        if (total>=2 && buf[total-2]=='|' && buf[total-1]=='|') { buf[total]='\0'; return total; }
    }
    return -1;
}
int write_all(int sock, const void *buf, size_t count) {
    const char *p=buf; size_t rem=count;
    while(rem>0) {
        ssize_t n=write(sock,p,rem);
        if(n<0) { if(errno==EINTR) continue; return -1; }
        p+=n; rem-=n;
    }
    return 0;
}
void send_msg(int sock, const char *msg) { write_all(sock,msg,strlen(msg)); }
int validate_move(const char *b) {
    if(strncmp(b,"M|",2)!=0) return 0;
    size_t len=strlen(b); if(len<5) return 0;
    char mv[16]; size_t ml=len-4; if(ml>=sizeof(mv)) return 0;
    memcpy(mv,b+2,ml); mv[ml]='\0';
    return !strcmp(mv,"ROCK")||!strcmp(mv,"PAPER")||!strcmp(mv,"SCISSORS");
}

struct game_args { struct client a,b; };

void *game_thread(void *arg) {
    struct game_args g = *(struct game_args*)arg;
    free(arg);
    int p1=g.a.sock, p2=g.b.sock;
    char *name1=g.a.name, *name2=g.b.name;
    char mv1[BUFLEN], mv2[BUFLEN], buf[BUFLEN];
    while(active) {
        // Begin round
        snprintf(buf,sizeof(buf),"B|%s||",name2); send_msg(p1,buf);
        snprintf(buf,sizeof(buf),"B|%s||",name1); send_msg(p2,buf);
        struct pollfd pf[2]={{p1,POLLIN,0},{p2,POLLIN,0}};
        int moves=0, to=0;
        memset(mv1,0,sizeof(mv1)); memset(mv2,0,sizeof(mv2));
        while(moves<2 && !to) {
            int r=poll(pf,2,MOVE_TIMEOUT_MS);
            if(r<=0){to=1;break;}
            for(int i=0;i<2;i++) if(pf[i].revents&POLLIN) {
                char *dst = (i==0?mv1:mv2);
                if(read_until_delim(pf[i].fd,dst,BUFLEN)<=0){ send_msg(i?g.a.sock:g.b.sock,"R|F|||"); to=1; break; }
                if(!validate_move(dst)){ send_msg(pf[i].fd,"R|L|Invalid||"); send_msg(i?g.a.sock:g.b.sock,"R|W||"); to=1; break; }
                moves++; pf[i].events=0;
            }
        }
        if(to) break;
        // decide
        char m1=mv1[2], m2=mv2[2], r1,r2;
        if(m1==m2) r1=r2='D';
        else if((m1=='R'&&m2=='S')||(m1=='S'&&m2=='P')||(m1=='P'&&m2=='R')) r1='W',r2='L';
        else r1='L',r2='W';
        snprintf(buf,sizeof(buf),"R|%c|%c||",r1,m2); send_msg(p1,buf);
        snprintf(buf,sizeof(buf),"R|%c|%c||",r2,m1); send_msg(p2,buf);
        // rematch
        if(read_until_delim(p1,buf,BUFLEN)<=0||buf[0]!='C'){ send_msg(p2,"R|W||"); break; }
        if(read_until_delim(p2,buf,BUFLEN)<=0||buf[0]!='C'){ send_msg(p1,"R|W||"); break; }
    }
    unregister_name(name1); unregister_name(name2);
    close(p1); close(p2);
    return NULL;
}

int main(int c,char**v){ if(c!=2){fprintf(stderr,"Usage: %s port\n",v[0]);exit(1);} install_handlers();
    int ln=open_listener(v[1],QUEUE_SIZE); if(ln<0) exit(1);
    fprintf(stderr,"[LOG] Listening on %s\n",v[1]);
    while(active){
        struct sockaddr_storage cl; socklen_t sl=sizeof(cl);
        int s=accept(ln,(void*)&cl,&sl); if(s<0) continue;
        char buf[BUFLEN]; int n=read_until_delim(s,buf,BUFLEN);
        if(n<=0||strncmp(buf,"P|",2)||buf[n-1]!='|'||buf[n-2]!='|'){ close(s); continue; }
        struct client me={s,{0}}; strncpy(me.name,buf+2,n-4);
        if(register_name(me.name)<0){ send_msg(s,"R|L|Logged in||"); close(s); continue; }
        send_msg(s,"W|1||");
        pthread_mutex_lock(&wait_mutex);
          if(!waiting){ waiting=malloc(sizeof*waiting); *waiting=me; }
          else{
            struct game_args *g=malloc(sizeof* g);
            g->a=*waiting; g->b=me; free(waiting); waiting=NULL;
            pthread_t t; pthread_create(&t,NULL,game_thread,g); pthread_detach(t);
          }
        pthread_mutex_unlock(&wait_mutex);
    }
    close(ln); return 0;
}
