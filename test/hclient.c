/*
    C ECHO client example using sockets
*/
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr

 
int main(int argc , char *argv[])
{
    int sock, readsize;
    struct sockaddr_in server;
    char message[1000] , server_reply[2000];
     
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    server.sin_addr.s_addr = inet_addr("17.125.253.5");
    server.sin_family = AF_INET;
    server.sin_port = htons(443);
 
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
     
    puts("Connected\n");
     
    //keep communicating with server
    while(1)
    {
		bzero( message, 100);
		bzero( server_reply, 100);//must bzero, or will have dirty char printed out

        printf("Enter message : ");
        scanf("%s" , message);
         
		
		write(sock,message,strlen(message)+1);
		read(sock,server_reply,100);
		printf("%s\n",server_reply);

    }
     
    close(sock);
    return 0;
}

