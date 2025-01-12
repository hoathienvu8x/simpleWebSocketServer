#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <endian.h>
#include <sys/timerfd.h>
#include <netinet/tcp.h>

#include "ws.h"
#include "sha1.h"

#define MAX_WS_PAD (BUFFER_SIZE - 11)

static size_t ws_client_counter = 0;

#define __ws_disponse(p) do { if (p) { free(p); p = NULL; } } while (0)

static int __ws_close_socket(int fd) {
  shutdown(fd, SHUT_RDWR);
  return close(fd);
}
static int create_and_bind (const char *port) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, sfd, on = 1;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_UNSPEC;  /* Return IPv4 and IPv6 choices */
  hints.ai_socktype = SOCK_STREAM;      /* We want a TCP socket */
  hints.ai_flags = AI_PASSIVE;  /* All interfaces */

  s = getaddrinfo (NULL, port, &hints, &result);
  if (s != 0) {
    #ifndef NDEBUG
    fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
    #endif
    return -1;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket (rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
    if (sfd == -1)
      continue;

    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
      __ws_close_socket(sfd);
      continue;
    }
    
    if (setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on)) < 0) {
      __ws_close_socket(sfd);
      continue;
    }
    
    if (setsockopt(sfd, IPPROTO_TCP, TCP_QUICKACK, (char *)&on, sizeof(on)) < 0) {
      __ws_close_socket(sfd);
      continue;
    }

    s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0) {
      /* We managed to bind successfully! */
      break;
    }

    __ws_close_socket (sfd);
  }

  if (rp == NULL) {
    freeaddrinfo (result);
    #ifndef NDEBUG
    fprintf (stderr, "Could not bind\n");
    #endif
    return -1;
  }

  freeaddrinfo (result);

  return sfd;
}

static int __ws_set_non_blocking (int sfd) {
  int flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1) {
    #ifndef NDEBUG
    perror ("fcntl");
    #endif
    return -1;
  }
  if (fcntl (sfd, F_SETFL, flags | O_NONBLOCK) == -1) {
    #ifndef NDEBUG
    perror ("fcntl");
    #endif
    return -1;
  }

  return 0;
}

static int __ws_epoll_add(int epoll_fd, int fd, uint32_t events) {
  struct epoll_event event;

  /* Shut the valgrind up! */
  memset(&event, 0, sizeof(struct epoll_event));

  event.events  = events;
  event.data.fd = fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
    #ifndef NDEBUG
    perror("__ws_epoll_add(): ");
    #endif
    return -1;
  }
  return 0;
}

static int __ws_epoll_delete(int epoll_fd, int fd) {
  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
    #ifndef NDEBUG
    perror("__ws_epoll_delete(): ");
    #endif
    return -1;
  }
  return 0;
}

static ssize_t ws_client_restrict_read(ws_client *cli, void *buf, size_t len) {
  size_t i;
  ssize_t n;
  char *p = buf;
  for (i = 0; i < len;) {
    if (cli->buf.pos == 0 || cli->buf.pos == cli->buf.len) {
      memset(cli->buf.data, 0, sizeof(cli->buf.data));
      n = recv(cli->fd, cli->buf.data, sizeof(cli->buf.data), 0);
      if (n <= 0) return -1;
      cli->buf.pos = 0;
      cli->buf.len = (size_t)n;
    }
    *(p++) = cli->buf.data[cli->buf.pos++];
    i++;
  }
  return (ssize_t)i;
}

static int ws_client_restrict_write(int fd, const void *buf, size_t len) {
  size_t left = len;
  const char *buf2 = buf;
  int rc = 0;
  do {
    rc = send(fd, buf2, left, MSG_NOSIGNAL);
    if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (rc <= 0) break;
    buf2 += rc;
    left -= (size_t)rc;
  } while (left > 0);
  if (left != 0) return -1;
  return (int)len;
}

static int __ws_get_client_state(ws_client* _self) {
  int state;
  if (!_self) return -1;
  pthread_mutex_lock(&_self->mtx_sta);
  state = _self->state;
  pthread_mutex_unlock(&_self->mtx_sta);
  return state;
}

static int __ws_set_client_state(ws_client* _self, int state) {
  if (!_self) return -1;
  if (state < 0 || state > 3)
    return -1;
  pthread_mutex_lock(&_self->mtx_sta);
  if (_self->state != state)
    _self->state = state;
  pthread_mutex_unlock(&_self->mtx_sta);
  return 0;
}

static ws_client * __ws_get_client(ws_server *server, int fd) {
  ws_client *cli = NULL;
  if (!server) return NULL;
  pthread_mutex_lock(&server->mtx);
  ws_client *p = server->clients.head;
  while (p != NULL) {
    if (p->fd == fd) {
      cli = p;
      break;
    }
    p = p->next;
  }
  pthread_mutex_unlock(&server->mtx);
  return cli;
}

static void *create_client (int fd, ws_server * server) {
  if (!server) return NULL;

  ws_client *client = calloc(1, sizeof(struct _client));
  if (!client) return NULL;

  if (pthread_mutex_init(&client->mtx_sta, NULL)) {
    __ws_disponse(client);
    return NULL;
  }

  if (pthread_mutex_init(&client->mtx_snd, NULL)) {
    pthread_mutex_destroy(&client->mtx_sta);
    __ws_disponse(client);
    return NULL;
  }

  memset(&client->buf, 0, sizeof(client->buf));
  __ws_set_client_state(client, 0);
  client->fd = fd;
  client->server = server;

  client->next = client->prev = NULL;

  client->id = ws_client_counter++;
  server->client_size++;

  pthread_mutex_lock(&server->mtx);
  if (server->clients.head == NULL) {
    server->clients.head = server->clients.tail = client;
  } else {
    client->prev = server->clients.tail;
    server->clients.tail->next = client;
    server->clients.tail = client;
  }
  pthread_mutex_unlock(&server->mtx);

  return client;
}

static void close_client (ws_client * client) {
  if (!client) return;

  ws_server *server = client->server;
  if (server) {
    __ws_epoll_delete(server->epollfd, client->fd);
    server->client_size--;
  }

  __ws_close_socket (client->fd);

  pthread_mutex_destroy(&client->mtx_sta);
  pthread_mutex_destroy(&client->mtx_snd);

  if (client->prev)
    client->prev->next = client->next;

  if (client->next)
    client->next->prev = client->prev;

  __ws_disponse(client);
}

static void __ws_close_client(ws_client *client) {
  if (!client) return;
  ws_server *srv = client->server;
  
  if (srv)
    pthread_mutex_lock(&srv->mtx);

  close_client(client);

  if (srv)
    pthread_mutex_unlock(&srv->mtx);
}

static int handle_verify (ws_client * client) {
  if (!client) return -1;
  if (__ws_get_client_state(client) != 0) return 0;
  //get all http request data and then parse it
  //split the request and then get the  header "sec-websocket-key" and the get the value
  char buf[BUFFER_SIZE] = {0};
  int rc, blen = 0;
  do {
    rc = ws_client_restrict_read(client, buf + blen, 1);
    if (rc < 0) return -1;
    blen += rc;
    if (strstr(buf, "\r\n\r\n")) break;
    if (blen >= BUFFER_SIZE) return -1;
  } while (strstr(buf, "\r\n\r\n") == NULL && rc > 0);
  if (strstr(buf, "\r\n\r\n") == NULL) return -1;
  buf[blen] = '\0';
  if (strncasecmp(buf, "GET ", 4) != 0) return -1;
  if (client->server->events.is_route) {
    char path[256] = {0};
    size_t p = strcspn(buf + 4, "?# ");
    if (p != strlen(buf + 4)) {
      memcpy(path, buf + 4, p);
      path[p] = '\0';
    } else {
      memcpy(path, buf + 4, strlen(buf + 4));
    }
    if (!client->server->events.is_route(client, path)) return -1;
  }

  char *start = NULL;
  start = strstr (buf, "Sec-WebSocket-Key");
  if (!start) return -1;
  char *end = strstr (start, "\r\n");
  char sec[255] = { 0 };
  strncpy (sec, start, end - start);

  static char *const_key = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char secure_key[255] = { 0 };
  char *key = strstr (sec, ":") + 2;
  sprintf (secure_key, "%s%s", key, const_key);
  key = get_socket_secure_key ((const unsigned char *)secure_key);
  if (!key) return -1;
  char *res_header_str =
    "HTTP/1.1 101 Web Socket Protocol Handshake\r\nUpgrade: "
    "WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s%s";
  char *double_newline = "\r\n\r\n";;
  char msg[255] = { 0 };
  if (sprintf (msg, res_header_str, key, double_newline) <= 0) {
    return -1;
  }
  __ws_disponse (key);
  size_t slen = strlen(msg);
  pthread_mutex_lock(&client->mtx_snd);
  if (ws_client_restrict_write(client->fd, msg, slen) != (ssize_t)slen) {
    pthread_mutex_unlock(&client->mtx_snd);
    return -1;
  }
  pthread_mutex_unlock(&client->mtx_snd);
  __ws_set_client_state(client, 1);
  return 0;
}

static void send_frame (
  ws_client * client, int opcode, const char *payload, size_t payload_size
) {
  if (!client) return;
  if (opcode == TEXT || opcode == BINARY) {
    if (!payload || payload_size == 0) return;
  }
  if (__ws_get_client_state(client) != 1) return;
  int i;
  int frame_count = ceil((float)payload_size / (float)MAX_WS_PAD);
  if (frame_count == 0) frame_count = 1;
  unsigned char frame_data[BUFFER_SIZE] = {0};
  for (i = 0; i < frame_count; i++) {
    uint64_t frame_size = i != frame_count - 1 ? MAX_WS_PAD : payload_size % MAX_WS_PAD;
    char op_code = i != 0 ? 0 : opcode;
    char fin = i != frame_count - 1 ? 0 : 1;
    memset(frame_data, 0, sizeof(frame_data));
    uint64_t frame_length = frame_size;
    int offset = 2;
    frame_data[0] |= (fin << 7) & 0x80;
    frame_data[0] |= op_code & 0xf;
    if (frame_size <= 125) {
      frame_data[1] = frame_size & 0x7f;
      frame_length += 2;
    } else if (frame_size >= 126 && frame_size <= 65535) {
      frame_data[1] = 126;
      frame_data[2] = (frame_size >> 8) & 255;
      frame_data[3] = (frame_size & 255);
      frame_length += 4;
      offset += 2;
    } else {
      frame_data[1] = 127;
      frame_data[2] = (unsigned char)((frame_size >> 56) & 255);
      frame_data[3] = (unsigned char)((frame_size >> 48) & 255);
      frame_data[4] = (unsigned char)((frame_size >> 40) & 255);
      frame_data[5] = (unsigned char)((frame_size >> 32) & 255);
      frame_data[6] = (unsigned char)((frame_size >> 24) & 255);
      frame_data[7] = (unsigned char)((frame_size >> 16) & 255);
      frame_data[8] = (unsigned char)((frame_size >> 8) & 255);
      frame_data[9] = (unsigned char)(frame_size & 255);
      frame_length += 10;
      offset += 8;
    }
    memcpy (frame_data + offset, &payload[i * MAX_WS_PAD], frame_size);
    frame_data[frame_length] = '\0';
    pthread_mutex_lock(&client->mtx_snd);
    if ((uint64_t)ws_client_restrict_write(client->fd, frame_data, frame_length) != frame_length) {
      #ifndef NDEBUG
      if (frame_length > 0) {
        printf("send frame data is not completed\n");
      }
      #endif
    }
    pthread_mutex_unlock(&client->mtx_snd);
  }
}

static void handle_ping (ws_client * client)
{
  if (!client) return;
  enum opcode enum_opcode = PONG;
  send_frame (client, enum_opcode, NULL, 0);
}

static void handle_close (ws_client * client, int code, const char *reason)
{
  if (!client) return;
  //handle the close
  int reason_size = reason ? strlen (reason) : 0;
  enum opcode close_opcode = CLOSE;
  int payload_size = reason_size + 2;
  char *payload = (char *) malloc (sizeof (char) * payload_size);
  if (!payload)
    return;
  payload[0] = (code >> 24) & 0xFF;
  payload[1] = (code >> 16) & 0xFF;
  if (reason)
    memcpy (payload, reason, 2);
  send_frame (client, close_opcode, payload, payload_size);
  // remove the fd in epoll event set and close the socket
  __ws_disponse (payload);
  if (client->server->events.onclose)
    client->server->events.onclose(client);

  __ws_close_client (client);
}

static void handle_all_frame (ws_client * client, ws_frame * frame)
{
  if (frame == NULL || client == NULL) {
    return;
  }
  //handle the ws_frame
  enum opcode enum_opcode = (enum opcode) frame->opcode;
  switch (enum_opcode) {
  case TEXT: case BINARY: {
      if (client->server->events.onmessage)
        client->server->events.onmessage(
          client, frame->opcode, frame->payload, frame->payload_len
        );
    } break;
  case CLOSE: {
      char *reason = NULL;
      if (strlen (frame->payload) > 2) {
        reason = &frame->payload[2];
      }
      short close_code = (short) *(frame->payload);
      handle_close (client, close_code, reason);
    } break;
  case PING: {
    if (client->server->events.onping)
      client->server->events.onping(client);
    else
      handle_ping (client);
    } break;
  case PONG: {
      if (client->server->events.onpong)
        client->server->events.onpong(client);
    } break;
  default:
    handle_close (client, 1002, "unknown opcode");
  }
  if (frame) {
    //case the opcode and then execute specify  opcode-handler
    __ws_disponse (frame->payload);
    __ws_disponse (frame);
  }
}

static void *__ws_handle_client (void *_self)
{
  ws_client * client = (ws_client *)_self;
  if (!client) return NULL;

  if (__ws_get_client_state(client) != 1) {
    int result = handle_verify (client);
    if (result) {
      if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
      __ws_close_client(client);
      return NULL;
    }
    if (client->server->events.onopen)
      client->server->events.onopen(client);
  }
  if (__ws_get_client_state(client) != 1) return NULL;
  char *payload = NULL;
  uint64_t recv_len = 0;
  for (;;) {
    uint8_t data[10] = {0};
    if (ws_client_restrict_read(client, data, 2) < 2) {
      if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
      __ws_close_client(client);
      goto clean_up;
    }

    uint8_t opcode = data[0] & 15;
    int beg = opcode != CONT;
    int fin = data[0] >> 7;
    int mask = data[1] >> 7;
    uint8_t mask_key[4] = {0};

    uint64_t pl_len = data[1] & 127;

    if (pl_len == 126) {
      memset(data, 0, sizeof(data));
      if (ws_client_restrict_read(client, data, 2) < 2) {
        if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
        pthread_mutex_lock(&client->server->mtx);
        close_client(client);
        pthread_mutex_unlock(&client->server->mtx);
        goto clean_up;
      }
      pl_len = be16toh(*(uint16_t*)data);
    } else if (pl_len == 127) {
      memset(data, 0, sizeof(data));
      if (ws_client_restrict_read(client, data, 8) < 8) {
        if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
        __ws_close_client(client);
        goto clean_up;
      }
      pl_len = be64toh(*(uint64_t*)data) & ~(1ULL << 63);
    }
    if (mask) {
      memset(data, 0, sizeof(data));
      if (ws_client_restrict_read(client, data, 4) < 4) {
        if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
        __ws_close_client(client);
        goto clean_up;
      }
      *(uint32_t*)mask_key = *(uint32_t*)data;
    }
    char *tmp = realloc(payload, recv_len + pl_len + 1);
    if (!tmp) {
      __ws_close_client(client);
      goto clean_up;
    }
    payload = tmp;
    if (ws_client_restrict_read(client, payload + recv_len, pl_len) <= 0) {
      if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
      __ws_close_client(client);
      goto clean_up;
    }
    if (mask) {
      uint64_t i = 0;
      char *p = payload + recv_len;
      for (i = 0; i < pl_len; i++) {
        p[i] = p[i] ^ mask_key[i & 3];
      }
    }
    recv_len += pl_len;
    if (fin && beg) {
      ws_frame *frame = (ws_frame *)malloc(sizeof(ws_frame));
      if (!frame) goto clean_up;
      *(payload + recv_len) = '\0';
      frame->opcode = opcode;
      frame->payload = payload;
      frame->payload_len = recv_len;
      handle_all_frame(client, frame);
      break;
    }
  }
  return NULL;

clean_up:
  __ws_disponse(payload);
  return NULL;
}

static void * __ws_call_periodic(void *_self) {
  ws_server * server = (ws_server *)_self;
  if (!server || !server->events.onperodic) return NULL;
  server->events.onperodic(server);
  return NULL;
}

static void * __ws_event_loop (void *data)
{
  ws_server * server = (ws_server *)data;
  /* Code to set up listening socket, 'listen_sock',
     (socket(), bind(), listen()) omitted */
  int conn_sock, nfds;
  struct sockaddr_in servaddr;
  socklen_t addrlen = sizeof(servaddr);

  struct epoll_event events[MAX_EVENTS] = {0};

  if (server->timeout > 0 && server->events.onperodic) {
    int time_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (time_fd > 0) {
      if (__ws_epoll_add(server->epollfd, time_fd, EPOLLIN | EPOLLET) < 0) {
        __ws_close_socket(time_fd);
      } else {
        server->time_fd = time_fd;
        struct itimerspec its;
        its.it_value.tv_sec = server->timeout > 1000 ? server->timeout / 1000 : 0;
        its.it_value.tv_nsec = server->timeout > 1000 ? (server->timeout % 1000) % 1000 : server->timeout;
        its.it_interval = its.it_value;
        if (timerfd_settime(server->time_fd, 0, &its, NULL) != 0) {
          __ws_epoll_delete(server->epollfd, server->time_fd);
          __ws_close_socket(server->time_fd);
        }
      }
    }
  }

  const uint32_t err_mask = EPOLLERR | EPOLLHUP;
  for (;;) {
    nfds = epoll_wait (server->epollfd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
      #ifndef NDEBUG
      perror ("epoll_wait");
      #endif
      return NULL;
    }
    int n;
    for (n = 0; n < nfds; ++n) {
      if (events[n].data.fd == server->listen_sock) {
        if (!(events[n].events & EPOLLIN)) continue;
        conn_sock = accept (server->listen_sock,
                            (struct sockaddr *) &servaddr, &addrlen);
        if (conn_sock == -1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
          #ifndef NDEBUG
          perror ("accept");
          #endif
          return NULL;
        }
        if (__ws_set_non_blocking (conn_sock) < 0) {
          __ws_close_socket(conn_sock);
          continue;
        }

        if (server->timeout > 1000) {
          struct timeval tv;
          tv.tv_sec = server->timeout / 1000;
          tv.tv_usec = (server->timeout % 1000) * 1000;
          if (setsockopt(conn_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
            __ws_close_socket(conn_sock);
            continue;
          }

          if (setsockopt(conn_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
            __ws_close_socket(conn_sock);
            continue;
          }
        }
        if (__ws_epoll_add (server->epollfd, conn_sock, EPOLLIN | EPOLLET) == -1) {
          __ws_close_socket(conn_sock);
          continue;
        }
        server->current_event_size += 1;
        if (NULL == create_client (conn_sock, server)) {
          __ws_epoll_delete(server->epollfd, conn_sock);
          __ws_close_socket(conn_sock);
        }
      } else if (events[n].data.fd == server->time_fd) {
        if (events[n].events & EPOLLIN) {
          unsigned long long val;
          static int n_id;
          if (read(events[n].data.fd, &val, sizeof(val)) > 0) {
            printf("Received timerfd event via epoll: %d\n", n_id++);
          }
          if (server->events.onperodic) {
            pthread_t periodic_thread;
            if (pthread_create(&periodic_thread, NULL, __ws_call_periodic, server)) {
              #ifndef NDEBUG
              perror ("pthread_create");
              #endif
              exit(EXIT_FAILURE);
            }
            pthread_detach(periodic_thread);
          }
        }
      } else {
        ws_client *cli = __ws_get_client(server, events[n].data.fd);
        if (events[n].events & err_mask) {
          if (cli) {
            __ws_close_client(cli);
          } else {
            __ws_close_socket(events[n].data.fd);
          }
          continue;
        }
        if (!(events[n].events & EPOLLIN)) continue;
        if (cli != NULL) {
          pthread_t client_thread;
          if (pthread_create(
            &client_thread, NULL, __ws_handle_client, cli
          )) {
            #ifndef NDEBUG
            perror ("pthread_create");
            #endif
            exit(EXIT_FAILURE);
          }
          pthread_detach(client_thread);
        }
      }
    }
  }
  return NULL;
}

ws_server *ws_event_create_server (const char *port)
{
  int s;
  int listen_sock = create_and_bind (port);

  s = listen (listen_sock, MAX_EVENTS);
  if (s < 0) {
    #ifndef NDEBUG
    printf ("error listen");
    #endif
    return NULL;
  }
  ws_server *server = (ws_server *) calloc (1, sizeof (ws_server));
  if (!server)
    return NULL;

  if (pthread_mutex_init(&server->mtx, NULL))
    goto clean_up;

  server->epollfd = epoll_create1 (0);
  memset(&server->events, 0, sizeof(struct ws_event_list));
  server->listen_sock = listen_sock;
  server->timeout = 10000;
  server->time_fd = -1;

  if (server->epollfd == -1) {
    #ifndef NDEBUG
    perror ("epoll_create1");
    #endif
    goto clean_up;
  }

  if (__ws_epoll_add (server->epollfd, listen_sock, EPOLLIN | EPOLLET) == -1) {
    #ifndef NDEBUG
    perror ("epoll_ctl: listen_sock");
    #endif
    goto clean_up;
  }

  server->clients.head = server->clients.tail = NULL;

  return server;

clean_up:
  if (server->epollfd != -1) __ws_close_socket(server->epollfd);
  __ws_disponse(server);
  return NULL;
}

void ws_send_broadcast (ws_client *cli, const char *msg)
{
  ws_send_bytes_broadcast(cli, msg, msg ? strlen(msg) : 0, TEXT);
}
void ws_send_bytes_broadcast (ws_client *cli, const char *msg, size_t msg_len, int op)
{
  if (!cli || !msg || msg_len == 0) return;
  ws_server *server = cli->server;
  if (!server) return;

  pthread_mutex_lock(&server->mtx);
  ws_client *client = server->clients.head;
  while (client != NULL) {
    if (client->fd != cli->fd) {
      if (__ws_get_client_state(client) == 1) {
        send_frame(client, op, msg, msg_len);
      }
    }
    client = client->next;
  }
  pthread_mutex_unlock(&server->mtx);
}
void ws_send_all(ws_server *server, const char *msg) {
  ws_send_bytes_all(server, msg, msg ? strlen(msg) : 0, TEXT);
}
void ws_send_bytes_all(ws_server *server, const char *msg, size_t msg_len, int op) {
  if (!server || !msg || msg_len == 0) return;

  pthread_mutex_lock(&server->mtx);
  ws_client *client = server->clients.head;
  while (client != NULL) {
    if (__ws_get_client_state(client) == 1) {
      send_frame(client, op, msg, msg_len);
    }
    client = client->next;
  }
  pthread_mutex_unlock(&server->mtx);
}
void ws_event_dispose(ws_server *server) {
  if (!server) return;
  pthread_mutex_destroy(&server->mtx);
  __ws_close_socket(server->epollfd);
  __ws_close_socket(server->listen_sock);
  __ws_close_socket(server->time_fd);

  ws_client *client = server->clients.head;
  ws_client *tmp = NULL;
  while (client != NULL) {
    tmp = client->next;
    close_client(client);
    client = tmp;
  }

  __ws_disponse(server);
}
void ws_event_set_timeout(ws_server *srv, unsigned int timeout) {
  if (!srv) return;
  srv->timeout = timeout;
}
void ws_send(ws_client *client, const char *msg) {
  if (!client || !msg || strlen(msg) == 0) return;
  send_frame(client, TEXT, msg, strlen(msg));
}
void ws_send_bytes(ws_client *client, const char *msg, size_t len, int opcode) {
  send_frame(client, opcode, msg, len);
}
void ws_event_close(ws_client *client, const char *reason) {
  handle_close(client, 1000, reason);
}
void ws_event_listen (ws_server * server, int as_thread) {
  if (!server) return;
  if (as_thread) {
    if (pthread_create(&server->thread, 0, __ws_event_loop, server)) {
      exit(EXIT_FAILURE);
    }
  } else {
    __ws_event_loop(server);
  }
}

void ws_event_hold(ws_server *server) {
  if (!server) return;
  if (server->thread) {
    pthread_join(server->thread, 0);
  }
}
