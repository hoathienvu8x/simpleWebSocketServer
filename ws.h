#ifndef _WS_H
#define _WS_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>

#define BUFFER_SIZE 1024
#define MAX_EVENTS 1024

typedef struct frame {
  int opcode;
  char *payload;
  size_t payload_len;
} ws_frame;

enum opcode {
  CONT = 0,
  TEXT = 1,
  BINARY = 2,
  CLOSE = 8,
  PING = 9,
  PONG = 10,
};
typedef struct _client ws_client;
typedef struct _server ws_server;

struct ringbuf_t {
  char data[BUFFER_SIZE];
  size_t pos;
  size_t len;
};

struct _client {
  int fd;
  struct ringbuf_t buf;
  int state;
  ws_server *server;
  pthread_mutex_t mtx_snd;
  pthread_mutex_t mtx_sta;
};

struct ws_event_list {
  void (*onopen)(ws_client *);
  void (*onclose)(ws_client *);
  void (*onping)(ws_client *);
  void (*onpong)(ws_client *);
  void (*onmessage)(ws_client *, int, const char *, size_t);
  void (*onperodic)(ws_server *);
};

struct _server {
  ws_client *clients;           //all of the connection client
  int client_size;              // client scale
  int epollfd;                  //epoll listenfd
  int time_fd;
  int listen_sock;
  struct ws_event_list events;
  int current_event_size;
  int max_fd;                   //current max fd
  unsigned int timeout;
  pthread_mutex_t mtx;
};

void ws_send_broadcast (ws_client *cli, const char *msg);
void ws_send_bytes_broadcast (ws_client *cli, const char *msg, size_t msg_len, int op);

void ws_send_all(ws_server *server, const char *msg);
void ws_send_bytes_all(ws_server *server, const char *msg, size_t msg_len, int op);

void ws_send(ws_client *client, const char *msg);
void ws_send_bytes(ws_client *client, const char *msg, size_t len, int op);
void ws_event_close(ws_client *client, const char *reason);
ws_server *ws_event_create_server (const char *port);
void ws_event_set_timeout(ws_server *srv, unsigned int timeout);
void ws_event_loop (ws_server * server);
void ws_event_dispose(ws_server *server);

#endif
