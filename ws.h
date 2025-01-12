#ifndef _WS_H
#define _WS_H

#include <stdint.h>
#include <pthread.h>

typedef struct _client ws_client;

#define BUFFER_SIZE 1024

struct ringbuf_t {
  char data[BUFFER_SIZE];
  size_t pos;
  size_t len;
};

enum opcode {
  WS_FR_OP_CONT = 0,
  WS_FR_OP_TEXT = 1,
  WS_FR_OP_BINARY = 2,
  WS_FR_OP_CLOSE = 8,
  WS_FR_OP_PING = 9,
  WS_FR_OP_PONG = 10,
};

struct ws_event_list {
  void (*onopen)(ws_client *);
  void (*onclose)(ws_client *);
  void (*onping)(ws_client *);
  void (*onpong)(ws_client *);
  void (*onmessage)(ws_client *, int, const char *, size_t);
  void (*onperodic)(ws_client *);
};

struct _client {
  int epollfd;
  int time_fd;
  int listen_sock;
  struct ringbuf_t buf;
  int state;
  struct ws_event_list events;
  unsigned int timeout;
  pthread_t thread;
  pthread_mutex_t mtx_snd;
  pthread_mutex_t mtx_sta;
  size_t id;
  void *data;
  int is_stop;
  const char *url;
  const char *origin;
};

void ws_send(ws_client *client, const char *msg);
void ws_send_bytes(ws_client *client, const char *msg, size_t len, int op);
void ws_event_close(ws_client *client, const char *reason);
ws_client *ws_event_create_client (void *data);
void ws_client_connect(ws_client *client, const char *url, const char *origin);
void ws_event_set_timeout(ws_client *client, unsigned int timeout);
void ws_event_listen (ws_client * client, int as_thread);
void ws_event_dispose(ws_client *client);
void ws_event_hold(ws_client *client);

#endif
