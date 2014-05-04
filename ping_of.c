#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

int main(int argc, char *argv[]) {
    struct sockaddr_in saddr;
    unsigned i, count = -10 ;
    if(argc >= 2){
        count = atoi(argv[1]);
    }
    printf("count %i\n",count);
    for(i = 0 ; i < count;i++ ){
        socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if ( i % ( 1 << 24 ) == 0 )
            printf("%i \n",i);
    }
    printf("executed %u ping_init_sock() calls\n",i);
}
