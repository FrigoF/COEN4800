//  TLS_syslog.c - send message to TLS SYSLOG server 
//
//  Marquette University 
//  Fred J. Frigo
//
//  08-Mar-2025  - Version for OpenSSL 3.0 (TLSv1.3)
//
//  To compile: gcc -Wall -o TLS_syslog TLS_syslog.c -lssl -lcrypto 
//
//  See https://docs.openssl.org/3.4/man7/ossl-guide-tls-client-block/#creating-the-ssl_ctx-and-ssl-objects
//

#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#define MAX 256 
#define PORT 6514 
#define SA struct sockaddr 

void get_syslog_message( char *tls_syslog_msg) 
{ 
    char rfc3164_syslog_msg[4*MAX] = {0};
    char rfc5424_syslog_msg[4*MAX] = {0};;
    char rfc3164_time[MAX];
    char rfc5424_time[MAX];
    char myHost[MAX];
    char myMessage[MAX];
    char *username;
    int pri = (13*8)+6;  // RFC 3164: priority 13 = log audit, priority = 6 infoa
    int version = 1;     // RFC 5424: version
    struct timespec current_time;
    int pid, usec;
    struct tm *time;
    int tz_hour, tz_min; 
    char* c_time_string;

    // Get username and local host name
    username = getenv("USER");
    gethostname(myHost, MAX);

    // Get message
    printf("Enter message to send to server: ");
    fgets(myMessage, sizeof(myMessage), stdin);
    myMessage[strlen(myMessage)-1] = 0; // get rid of the '/n' character

    // Obtain current time. 
    clock_gettime( CLOCK_REALTIME, &current_time);

    // RFC 3164 message 
    c_time_string = ctime(&current_time.tv_sec);
    strncpy(rfc3164_time, &c_time_string[4], 15);  // copy only characters needed
    sprintf(rfc3164_syslog_msg, "<%d>%s %s TCP: RFC3164 message from %s: %s", pri, rfc3164_time, myHost, username, myMessage );

    // RFC 5425 message with NO Structured Data
    time = localtime(&current_time.tv_sec);
    tz_hour = (int)(time->tm_gmtoff/(60*60)); 
    tz_min = (int)(labs(time->tm_gmtoff/60) - labs(tz_hour*60));
    pid = (int)getpid();
    usec = (int)current_time.tv_nsec/1000;
    sprintf(rfc5424_time,"%4.4d%c%2.2d%c%2.2dT%2.2d:%2.2d:%2.2d.%6.6d%+2.2d:%2.2d",
       time->tm_year+1900, '-', time->tm_mon+1, '-', time->tm_mday, time->tm_hour, time->tm_min, time->tm_sec, usec, tz_hour, tz_min ); 
    sprintf(rfc5424_syslog_msg, "<%d>%d %s %s TLS %s %d %c RFC5424 message from %s: %s", 
       pri, version, rfc5424_time, myHost, "TLS_syslog", pid, '-', username,  myMessage );

    // Return Syslog mesage
    strcpy( tls_syslog_msg, rfc5424_syslog_msg);     
} 
  
int main(int argc, char *argv[]) 
{ 
    int sockfd; 
    struct sockaddr_in servaddr; 
    struct addrinfo hints, *infoptr; 
    struct addrinfo *p;
    SSL_CTX *ctx;
    SSL *ssl;
    char syslog_message[4*MAX] = {0};
    char host[256];

    // Validate the parameters
    if (argc != 2) {
        printf("usage: %s server-name\n", argv[0]);
        return 1;
    }

    // SSL Initialization
    SSL_library_init();

    // Create an SSL_CTX which we can use to create SSL objects from. We
    // want an SSL_CTX for creating clients so we use TLS_client_method()
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("Failed to create the SSL_CTX\n");
        exit(1);
    }

    // /* Create an SSL object to represent the TLS connection */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Failed to create the SSL object\n");
        exit(1);
    }

    // Create a client socket and connect to the server
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    int result = getaddrinfo(argv[1], NULL, &hints, &infoptr);
    if (result) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        exit(1);
    }

    for (p = infoptr; p != NULL; p = p->ai_next) 
    {
        getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof (host), NULL, 0, NI_NUMERICHOST);
    }
    freeaddrinfo(infoptr);

    // socket create and varification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation to SYSLOG server failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr)); 
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(host); 
    servaddr.sin_port = htons(PORT); 
  
    // connect the client socket to server socket 
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
        printf("connection with the SYSLOG server failed...\n"); 
        exit(0); 
    } 
    else
        printf("Connected to the SYSLOG server: %s at port %d\n", host, PORT); 
 
    // Create the SSL connection
    SSL_set_fd(ssl, sockfd);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) != 1 )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        get_syslog_message( syslog_message );
        SSL_write(ssl, syslog_message, strlen(syslog_message));   /* encrypt & send message */
        printf("SYSLOG message sent: %s\n",syslog_message);
        SSL_shutdown(ssl);        /* release connection state */
    }
    SSL_CTX_free(ctx);   
    close(sockfd); 
} 
