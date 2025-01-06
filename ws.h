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
#include "sha1.h"

#define BUFFER_SIZE 4096
#define MAX_EVENTS 1024

typedef struct frame {
  int opcode;
  char *payload;
  size_t payload_len;
} ws_frame;

enum opcode {
  TEXT = 1,
  BINARY = 2,
  CLOSE = 8,
  PING = 9,
  PONG = 10,
};
typedef struct client ws_client;
typedef struct server ws_server;

struct client {
  int fd;
  char *data;
  int size;
  int assgined;
  int state;
  ws_server *server;
};

struct server {
  ws_client *clients;           //all of the connection client
  int client_size;              // client scale
  int epollfd;                  //epoll listenfd
  int listen_sock;
  struct epoll_event *events;   //monitor event list
  int event_size;               //
  int current_event_size;
  int max_fd;                   //current max fd
  unsigned int timeout;
  void (*onopen)(ws_client *);
  void (*onclose)(ws_client *);
  void (*onping)(ws_client *);
  void (*onpong)(ws_client *);
  void (*onmessage)(ws_client *, int, const char *, size_t);
};

char *unmask (char *mask_bytes, char *buffer, int buffer_size);
void handle_all_frame (ws_client * client, ws_frame * frame);
void handle_ping (ws_client * client);
void handle_data (ws_client * client, char *data, int data_size);
void handle_close (ws_client * client, int code, char *reason);
void handle_text (ws_client * client, char *payload, int payload_size);
void broadcast (ws_server *server, char *msg);
ws_server *create_server (const char *port);
void ws_server_set_timeout(ws_server *srv, unsigned int timeout);
void event_loop (ws_server * server);
void event_loop_dispose(ws_server *server);

#endif
