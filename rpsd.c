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

void handle_sigint(int sig) {
    (void)sig;
    active = 0;
}

void install_handlers(void) {
    struct sigaction act;
    act.sa_handler = handle_sigint;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT, &act, NULL);
}

int register_name(const char *name) {
    pthread_mutex_lock(&name_mutex);
    if (active_count >= MAX_PLAYERS) {
        pthread_mutex_unlock(&name_mutex);
        return -1;
    }
    for (int i = 0; i < active_count; i++) {
        if (strcmp(active_names[i], name) == 0) {
            pthread_mutex_unlock(&name_mutex);
            return -1;
        }
    }
    active_names[active_count++] = strdup(name);
    pthread_mutex_unlock(&name_mutex);
    return 0;
}

void unregister_name(const char *name) {
    pthread_mutex_lock(&name_mutex);
    for (int i = 0; i < active_count; i++) {
        if (strcmp(active_names[i], name) == 0) {
            free(active_names[i]);
            active_names[i] = active_names[--active_count];
            break;
        }
    }
    pthread_mutex_unlock(&name_mutex);
}

ssize_t read_until_delim(int sock, char *buf, size_t maxlen) {
    size_t total = 0;
    while (total + 1 < maxlen) {
        ssize_t n = read(sock, buf + total, 1);
        if (n <= 0) return n;
        total += n;
        if (total >= 2 && buf[total-2]=='|' && buf[total-1]=='|') {
            buf[total] = '\0';
            return total;
        }
    }
    return -1;
}

int write_all(int sock, const void *buf, size_t count) {
    const char *p = buf;
    size_t remaining = count;
    while (remaining > 0) {
        ssize_t n = write(sock, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        remaining -= n;
    }
    return 0;
}

void send_msg(int sock, const char *msg) {
    write_all(sock, msg, strlen(msg));
}

int validate_name(const char *name) {
    return strchr(name,'|') == NULL;
}

int validate_move(const char *buf) {
    if (strncmp(buf,"M|",2)!=0) return 0;
    size_t len = strlen(buf);
    if (len<5) return 0;
    char mv[16]; size_t mv_len=len-4;
    if (mv_len>=sizeof(mv)) return 0;
    memcpy(mv,buf+2,mv_len); mv[mv_len]='\0';
    return strcmp(mv,"ROCK")==0||strcmp(mv,"PAPER")==0||strcmp(mv,"SCISSORS")==0;
}

void *handle_game(void *arg) {
    int *ps = arg;
    int p1 = ps[0], p2 = ps[1];
    free(ps);

    fprintf(stderr,"[LOG] New game thread: sockets %d & %d\n", p1, p2);

    char buf1[BUFLEN], buf2[BUFLEN];
    char *name1=NULL, *name2=NULL;
    int reg1=0, reg2=0, handshake_ok=0;

    // Tightened handshake: require 'P|' prefix and trailing '||'
    if (read_until_delim(p1,buf1,BUFLEN)>0 && strncmp(buf1,"P|",2)==0 && buf1[strlen(buf1)-2]=='|' &&
        read_until_delim(p2,buf2,BUFLEN)>0 && strncmp(buf2,"P|",2)==0 && buf2[strlen(buf2)-2]=='|') {
        name1=strdup(buf1+2); name1[strlen(name1)-2]='\0';
        name2=strdup(buf2+2); name2[strlen(name2)-2]='\0';
        fprintf(stderr,"[LOG] Players: %s vs %s\n", name1, name2);
        if (validate_name(name1) && register_name(name1)==0) { reg1=1; }
        if (validate_name(name2) && register_name(name2)==0) { reg2=1; }
        if (reg1 && reg2) {
            handshake_ok=1;
            send_msg(p1,"W|1||"); send_msg(p2,"W|1||");
        } else {
            if (!reg1) send_msg(p1,"R|L|Logged in||"); else send_msg(p1,"R|W||");
            if (!reg2) send_msg(p2,"R|L|Logged in||"); else send_msg(p2,"R|W||");
        }
    }

    if (handshake_ok) {
        while (active) {
            char out[BUFLEN];
            snprintf(out,BUFLEN,"B|%s||",name2); send_msg(p1,out);
            snprintf(out,BUFLEN,"B|%s||",name1); send_msg(p2,out);

            struct pollfd pfds[2]={{p1,POLLIN,0},{p2,POLLIN,0}};
            int moves=0,timed_out=0;
            char mv1[BUFLEN]={0}, mv2[BUFLEN]={0};

            while(moves<2 && !timed_out) {
                int r=poll(pfds,2,MOVE_TIMEOUT_MS);
                if(r<=0){timed_out=1;break;}
                if(pfds[0].revents & POLLIN) {
                    if(read_until_delim(p1,mv1,BUFLEN)<=0){ send_msg(p2,"R|F|||"); timed_out=1; break; }
                    moves++; pfds[0].events=0;
                }
                if(pfds[1].revents & POLLIN) {
                    if(read_until_delim(p2,mv2,BUFLEN)<=0){ send_msg(p1,"R|F|||"); timed_out=1; break; }
                    moves++; pfds[1].events=0;
                }
            }
            if(timed_out) break;

            size_t len1=strlen(mv1), arg1_len=len1-4;
            char move_str1[16]; memcpy(move_str1, mv1+2, arg1_len); move_str1[arg1_len]='\0';
            size_t len2=strlen(mv2), arg2_len=len2-4;
            char move_str2[16]; memcpy(move_str2, mv2+2, arg2_len); move_str2[arg2_len]='\0';

            char r1, r2;
            if (strcmp(move_str1, move_str2) == 0) r1=r2='D';
            else if ((strcmp(move_str1,"ROCK")==0 && strcmp(move_str2,"SCISSORS")==0) ||
                     (strcmp(move_str1,"SCISSORS")==0 && strcmp(move_str2,"PAPER")==0) ||
                     (strcmp(move_str1,"PAPER")==0 && strcmp(move_str2,"ROCK")==0)) r1='W',r2='L';
            else r1='L',r2='W';

            fprintf(stderr,"[LOG] Moves: %s:%s vs %s:%s -> %c/%c\n",
                    name1, move_str1, name2, move_str2, r1, r2);

            snprintf(out,BUFLEN,"R|%c|%s||", r1, move_str2); send_msg(p1,out);
            snprintf(out,BUFLEN,"R|%c|%s||", r2, move_str1); send_msg(p2,out);

            // Rematch: read single-byte commands
            char c1, c2;
            if (read(p1, &c1, 1) != 1 || (c1 != 'C')) { send_msg(p2, "R|W||"); break; }
            if (read(p2, &c2, 1) != 1 || (c2 != 'C')) { send_msg(p1, "R|W||"); break; }
            fprintf(stderr,"[LOG] Both players requested rematch\n");
        }
    }

    if(reg1) unregister_name(name1);
    if(reg2) unregister_name(name2);
    free(name1); free(name2);
    close(p1); close(p2);
    fprintf(stderr,"[LOG] Game thread exiting\n");
    return NULL;
}

int main(int argc,char **argv){
    if(argc!=2){fprintf(stderr,"Usage: %s <port>\n",argv[0]);exit(1);}  
    install_handlers();
    int listener=open_listener(argv[1],QUEUE_SIZE);
    if(listener<0)exit(1);
    fprintf(stderr,"[LOG] Listening on port %s\n",argv[1]);
    while(active){
        struct sockaddr_storage cl; socklen_t clsz=sizeof(cl);
        int p1=accept(listener,(struct sockaddr*)&cl,&clsz);
        if(p1<0) continue;
        fprintf(stderr,"[LOG] Connection accepted: fd %d\n",p1);
        int p2=accept(listener,(struct sockaddr*)&cl,&clsz);
        if(p2<0){close(p1);continue;}
        fprintf(stderr,"[LOG] Connection accepted: fd %d (paired with %d)\n",p2,p1);
        pthread_t tid; int *args=malloc(2*sizeof(int)); args[0]=p1; args[1]=p2;
        pthread_create(&tid,NULL,handle_game,args);
        pthread_detach(tid);
    }
    close(listener);
    return 0;
}
