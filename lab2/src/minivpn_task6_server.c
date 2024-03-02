/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>

#include "openssl_utils.h"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}
int crecv(int fd, char *buf, int n, struct sockaddr* remote_addr, socklen_t* addrlen){
  
  int nrecv;

  if((nrecv=recvfrom(fd, buf, n, 0, remote_addr, addrlen))<0){
    perror("Receiving data");
    exit(1);
  }
  return nrecv;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}
int csend(int fd, char *buf, int n, const struct sockaddr* remote_addr, socklen_t addrlen) {
  
  int nsend;

  if((nsend=sendto(fd, buf, n, MSG_CONFIRM, remote_addr, addrlen))<0){
    perror("Sending data");
    exit(1);
  }
  return nsend;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}
int recv_n(int fd, char *buf, int n, struct sockaddr *remote_addr, socklen_t* addrlen) {

  int nrecv, left = n;

  while(left > 0) {
    if ((nrecv = crecv(fd, buf, left, remote_addr, addrlen))==0){
      return 0 ;      
    }else {
      left -= nrecv;
      buf += nrecv;
    }
  }
  return n;  
}
/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
//  uint16_t total_len, ethertype;
  char recv_buffer[HMAC_SIZE + BUFSIZE + AES_BLOCK_SIZE];
  char encdec_buffer[HMAC_SIZE + BUFSIZE + AES_BLOCK_SIZE]; // hmac + ciphertext + padding
  char hmac_buffer[HMAC_SIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int ssl_port = PORT;
  unsigned short int udp_port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        // port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  // if(*if_name == '\0'){
  //   my_err("Must specify interface name!\n");
  //   usage();
  // }else if(cliserv < 0){
  if(cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  // ============================================================
  // key, iv
  // ============================================================
  unsigned char key[AES_KEY_SIZE];
  unsigned char iv[IV_SIZE];

  // ============================================================
  // SSL authentication server side
  // ============================================================
  /* Initialize OpenSSL */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  /* Create SSL context */
  SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
  if (ctx == NULL)
    handleErrorsSSL("SSL_CTX_new() error occured");

  /* Load certificate and private key */
  if (SSL_CTX_use_certificate_file(ctx, "openssl_files/server.crt", SSL_FILETYPE_PEM) <= 0)
    handleErrorsSSL("SSL_CTX_use_certificate_file() error occured");
  if (SSL_CTX_use_PrivateKey_file(ctx, "openssl_files/server.key", SSL_FILETYPE_PEM) <= 0)
    handleErrorsSSL("SSL_CTX_use_PrivateKey_file() error occured");

  /* Load CA certificate */
  if (!SSL_CTX_load_verify_locations(ctx, "openssl_files/ca.crt", NULL))
    handleErrorsSSL("SSL_CTX_load_verify_locations() error occured");
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  /* tcp socket for ssl */
  struct sockaddr_in local_ssl, remote_ssl;
  socklen_t remote_ssl_len;
  int ssl_sock_fd, ssl_net_fd, optval_ssl;
  if ( (ssl_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }
  if(setsockopt(ssl_sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval_ssl, sizeof(optval_ssl)) < 0){
    perror("setsockopt()");
    exit(1);
  }
  memset(&local_ssl, 0, sizeof(local_ssl));
  local_ssl.sin_family = AF_INET;
  local_ssl.sin_addr.s_addr = htonl(INADDR_ANY);;
  local_ssl.sin_port = htons(ssl_port);
  if (bind(ssl_sock_fd, (struct sockaddr *)&local_ssl, sizeof(local_ssl)) < 0) {
    perror("bind()");
    exit(1);
  }

  // do_debug("[Server] wainting for ssl tcp connection ...  ");
  if (listen(ssl_sock_fd, 5) < 0) {
    perror("listen()");
    exit(1);
  }

  // support multiple connection using fork
  int connection_id = 0;
  while (1) {
    remote_ssl_len = sizeof(remote_ssl);
    memset(&remote_ssl, 0, remote_ssl_len);
    if ((ssl_net_fd = accept(ssl_sock_fd, (struct sockaddr *)&remote_ssl, &remote_ssl_len)) < 0) {
      perror("accept()");
      exit(1);
    }


    int connection_pid = fork();
    if (connection_pid < 0) {
      perror("fork()");
      exit(1);
    }
    if (connection_pid == 0) {
      memset(if_name, 0, IFNAMSIZ);
      sprintf(if_name, "tun%d", connection_id);
      break; // child, handling connection
    }
    else { // parent, receive next connection
      connection_id++;
      udp_port++;
    }
  }


  // do_debug("done.\n");

  /* ssl connection */
  SSL *ssl = SSL_new(ctx);
  if (ssl == NULL)
    handleErrorsSSL("SSL_new() error occured");
  SSL_set_fd(ssl, ssl_net_fd);

  /* accept ssl handshake */
  do_debug("[Server] wainting for ssl handshake ... ");
  if (SSL_accept(ssl) <= 0)
    handleErrorsSSL("SSL_accept() error occured");
  do_debug("done.\n");

  /* test ssl connection */
  ssl_hello_response(ssl);

  /* udp port assign */
  ssl_assign_udp_port(ssl, &udp_port);

  /* key exchange */
  ssl_keyiv_response(ssl, key, iv);

  int pipe_fd[2];
  if (pipe(pipe_fd) == -1) {
    perror("pipe()");
    exit(1);
  }

  int p = fork();
  if (p < 0) {
    perror("fork()");
    exit(1);
  }

  if (p > 0) { // parent: handle ssl connection
    close(pipe_fd[0]); // only need to write to child process
    
    ssl_close_response(ssl); // block for close request
    write(pipe_fd[1], "close", strlen("close"));

    /* free ssl resources */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(ssl_net_fd);
    SSL_CTX_free(ctx);

    kill(p, SIGTERM);

    return 0;
  }

  // child: handle vpn traffic
  close(pipe_fd[1]); // only need to listen from parent process


  // ============================================================
  // vpn traffic interface
  // ============================================================
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  // ============================================================
  // bind
  // ============================================================
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY); // any non-tun/tap interface
  local.sin_port = htons(udp_port);
  if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
    perror("bind()");
    exit(1);
  }
  net_fd = sock_fd;

  remotelen = sizeof(remote);
  memset(&remote, 0, remotelen);
  
  // ============================================================
  // traffic handling
  // ============================================================
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
  maxfd = (maxfd > pipe_fd[0])?maxfd:pipe_fd[0];

  while(1) {
    int ret;
    fd_set rd_set;

    FD_SET(pipe_fd[0], &rd_set);
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(pipe_fd[0], &rd_set)){
      nread = cread(pipe_fd[0], recv_buffer, HMAC_SIZE + BUFSIZE + AES_BLOCK_SIZE);
      if (nread > 0)
        recv_buffer[nread] = '\0';
      if (strcmp(recv_buffer, "close") == 0) {
        // release resources
        close(net_fd);
        // close(tap_fd);
        return 0;
      }
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, recv_buffer, HMAC_SIZE + BUFSIZE + AES_BLOCK_SIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* hmac & encryption */
      int ciphertext_len = 0, hmac_len = 0;
      ciphertext_len = aes_encrypt(recv_buffer, nread, key, iv, encdec_buffer + HMAC_SIZE);
      hmac_sha256(key, encdec_buffer + HMAC_SIZE, ciphertext_len, encdec_buffer, &hmac_len);
      if (hmac_len != HMAC_SIZE) {
        perror("HMAC size error");
        exit(1);
      }
      nread = hmac_len + ciphertext_len;

      /* write length + hmac + packet ciphertext */
      plength = htons(nread);
      nwrite = csend(net_fd, (char *)&plength, sizeof(plength), (const struct sockaddr*)&remote, remotelen);
      nwrite += csend(net_fd, encdec_buffer, nread, (const struct sockaddr*)&remote, remotelen);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */      
      nread = recv_n(net_fd, (char *)&plength, sizeof(plength), (struct sockaddr*)&remote, &remotelen);
      if(nread == 0) {
        /* ctrl-c at the other end */
        break;
      }

      net2tap++;

      /* read packet */
      nread = recv_n(net_fd, recv_buffer, ntohs(plength), (struct sockaddr*)&remote, &remotelen);
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* verify hmac */
      int ciphertext_len = nread - HMAC_SIZE, hmac_len = 0;
      hmac_sha256(key, recv_buffer + HMAC_SIZE, ciphertext_len, hmac_buffer, &hmac_len);
      if (hmac_len != HMAC_SIZE) {
        perror("HMAC size error");
        exit(1);
      }
      if (memcmp(recv_buffer, hmac_buffer, hmac_len) != 0) {
        do_debug("HMAC verification failed, drop packet\n");
      }
      else {
        do_debug("HMAC verification succeed: 0x");
        int i;
        for (i = 0; i < HMAC_SIZE; i++) {
          do_debug("%02x", *((unsigned char*)hmac_buffer + i));
        }
        do_debug("\n");
      }

      /* decryption */
      int plaintext_len = aes_decrypt(recv_buffer + HMAC_SIZE, ciphertext_len, key, iv, encdec_buffer);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, encdec_buffer, plaintext_len);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, plaintext_len);
    }
  }
  
  return(0);
}
