// TLS_client.c - a simple TLS client example  (connects on port 8080)
// 
// Marquette University  
// Fred J. Frigo
// 13-Mar-2021
//
// 06-May-2023 - Updated to send message to server 
//
//  To install OpenSSL see INSTALL at https://www.openssl.org/source/
//  To compile: gcc -Wall -o TLS_client TLS_client.c -lssl -lcrypto 
//
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h> 

#define FAIL -1
#define MAX 256

// Send message to server and wait for response
void say_hello(SSL *ssl)
{
    char buff[MAX*3];
    char myHost[MAX];
    char myMessage[MAX];
    char *username;
    int status;

    // Get username and local host name
    username = getenv("USER");
    gethostname(myHost, MAX);

    // Get message
    printf("Enter message to send to server: ");
    fgets(myMessage, sizeof(myMessage), stdin);
    myMessage[strlen(myMessage)-1] = 0; // get rid of the '/n' character

    // Send message to server
    sprintf( buff, "%s :: from %s on %s\n", myMessage, username, myHost);
    SSL_write(ssl, buff, sizeof(buff));

    // Read response from server 
    bzero(buff, sizeof(buff));
    status = SSL_read(ssl, buff, sizeof(buff));
    if (status > 0)
    {
        printf("From Server : %s\n", buff);
    }
    else
    {
        printf("No response from Server.\n");
    }
}
 
int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = (SSL_METHOD *)TLS_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}


int main(int arc, char *argv[])
{

    SSL_CTX *ctx;
    int server;
    SSL *ssl;

    char *hostname, *portnum;
    if ( arc != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", argv[0]);
        exit(0);
    }
    hostname =  argv[1];
    portnum = argv[2];

    SSL_library_init();
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */

        /* send message to server  */
        say_hello(ssl);

        SSL_shutdown(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
