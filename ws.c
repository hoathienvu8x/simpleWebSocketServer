#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <math.h>
#include <endian.h>
#include <sys/timerfd.h>
#include <netinet/tcp.h>

#include "ws.h"

#define MAX_WS_PAD (BUFFER_SIZE - 15)

#define WS_STATE_CONNECTING 0
#define WS_STATE_OPEN       1
#define WS_STATE_CLOSING    2
#define WS_STATE_CLOSED     3

typedef struct frame {
  int opcode;
  char *payload;
  size_t payload_len;
} ws_frame;

static size_t ws_client_counter = 0;

#ifndef MAX_EVENTS
  #define MAX_EVENTS 1024
#endif

#define __ws_disponse(p) do { if (p) { free(p); p = NULL; } } while (0)

static int __ws_close_socket(int fd) {
  shutdown(fd, SHUT_RDWR);
  return close(fd);
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
static int __ws_epoll_mod(int epoll_fd, int fd, uint32_t events) {
  struct epoll_event event;

  /* Shut the valgrind up! */
  memset(&event, 0, sizeof(struct epoll_event));

  event.events  = events;
  event.data.fd = fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0) {
    #ifndef NDEBUG
    perror("__ws_epoll_mod(): ");
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

static ssize_t __ws_restrict_read(ws_client *cli, void *buf, size_t len) {
  size_t i;
  ssize_t n;
  char *p = buf;
  for (i = 0; i < len;) {
    if (cli->buf.pos == 0 || cli->buf.pos == cli->buf.len) {
      memset(cli->buf.data, 0, sizeof(cli->buf.data));
      n = recv(cli->listen_sock, cli->buf.data, sizeof(cli->buf.data), 0);
      if (n <= 0) return -1;
      cli->buf.pos = 0;
      cli->buf.len = (size_t)n;
    }
    *(p++) = cli->buf.data[cli->buf.pos++];
    i++;
  }
  return (ssize_t)i;
}

static int __ws_restrict_write(int fd, const void *buf, size_t len) {
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

static int __ws_parse_url(const char *url, struct url_t *p) {
  if (!url || strlen(url) == 0) return -1;
  if (sscanf(url, "ws://%[^:/]:%d/%s", p->host, &p->port, p->path) == 3) {
    return 0;
  }
  if (sscanf(url, "ws://%[^:/]/%s", p->host, p->path) == 2) {
    p->port = 80;
    return 0;
  }
  if (sscanf(url, "ws://%[^:/]:%d", p->host, &p->port) == 2) {
    p->path[0] = '\0';
    return 0;
  }
  if (sscanf(url, "ws://%[^:/]", p->host) == 1) {
    p->port = 80;
    p->path[0] = '\0';
  }
  return -1;
}

static int create_and_connect (const char *host, const char *port) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, sfd, on = 1;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_UNSPEC;  /* Return IPv4 and IPv6 choices */
  hints.ai_socktype = SOCK_STREAM;      /* We want a TCP socket */
  hints.ai_flags = AI_PASSIVE;  /* All interfaces */

  s = getaddrinfo (host, port, &hints, &result);
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

    s = connect (sfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0) {
      /* We managed to bind successfully! */
      break;
    }

    __ws_close_socket (sfd);
  }

  if (rp == NULL) {
    freeaddrinfo (result);
    #ifndef NDEBUG
    fprintf (stderr, "Could not connect\n");
    #endif
    return -1;
  }

  freeaddrinfo (result);

  return sfd;
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
  if (state < WS_STATE_CONNECTING || state > WS_STATE_CLOSED)
    return -1;
  pthread_mutex_lock(&_self->mtx_sta);
  if (_self->state != state)
    _self->state = state;
  pthread_mutex_unlock(&_self->mtx_sta);
  return 0;
}

static int __ws_handshake(ws_client *cli) {
  if (!cli) return -1;
  __ws_set_client_state(cli, WS_STATE_OPEN);
  __ws_epoll_mod(cli->epollfd, cli->listen_sock, EPOLLIN);
  return 0;
}

static void __ws_send_frame(
  ws_client *cli, const char *payload, size_t payload_size, int op
) {
  if (!cli) return;
  if (op == WS_FR_OP_BINARY || op == WS_FR_OP_TEXT) {
    if (!payload || payload_size == 0) return;
  }

  int i, mask_int = 0;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  srand(tv.tv_usec * tv.tv_sec);
  mask_int = rand();

  int frame_count = ceil((float)payload_size / (float)MAX_WS_PAD);
  if (frame_count == 0) frame_count = 1;
  unsigned char frame_data[BUFFER_SIZE] = {0};
  for (i = 0; i < frame_count; i++) {
    uint64_t frame_size = i != frame_count - 1 ? MAX_WS_PAD : payload_size % MAX_WS_PAD;
    char op_code = i != 0 ? WS_FR_OP_CONT : op;
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
    frame_data[1] |= 0x80;
    memcpy(&frame_data[offset], &mask_int, 4);
    offset += 4;
    memcpy (frame_data + offset, &payload[i * MAX_WS_PAD], frame_size);
    frame_data[frame_length] = '\0';
    pthread_mutex_lock(&cli->mtx_snd);
    if ((uint64_t)__ws_restrict_write(cli->listen_sock, frame_data, frame_length) != frame_length) {
      #ifndef NDEBUG
      if (frame_length > 0) {
        printf("send frame data is not completed\n");
      }
      #endif
    }
    pthread_mutex_unlock(&cli->mtx_snd);
  }
}

static void __ws_send_close(ws_client *client, int code, const char *reason) {
  if (!client) return;
  int reason_size = reason ? strlen (reason) : 0;
  int payload_size = reason_size + 2;
  char *payload = (char *) malloc (sizeof (char) * payload_size);
  if (!payload) return;
  payload[0] = (code >> 24) & 0xFF;
  payload[1] = (code >> 16) & 0xFF;
  if (reason)
    memcpy (payload, reason, 2);
  __ws_send_frame(client, payload, payload_size, WS_FR_OP_CLOSE);
  __ws_disponse (payload);
}

static void __ws_close_client(ws_client *cli) {
  if (!cli) return;
  cli->is_stop = 1;
}

static void __ws_handle_ping (ws_client * client) {
  if (!client) return;
  __ws_send_frame(client, NULL, 0, WS_FR_OP_PONG);
}

static void __ws_handle_all_frame(ws_client * client, ws_frame * frame) {
  if (frame == NULL || client == NULL) {
    return;
  }
  enum opcode enum_opcode = (enum opcode) frame->opcode;
  switch (enum_opcode) {
    case WS_FR_OP_TEXT: case WS_FR_OP_BINARY: {
        if (client->events.onmessage)
          client->events.onmessage(
            client, frame->opcode, frame->payload, frame->payload_len
          );
      } break;
    case WS_FR_OP_CLOSE: {
      if (__ws_get_client_state(client) == WS_STATE_CLOSING) {
          char *reason = NULL;
          if (frame->payload_len > 2) {
            reason = &frame->payload[2];
          }
          short close_code = (short) *(frame->payload);
          __ws_send_close (client, close_code, reason);
        }
      } break;
    case WS_FR_OP_PING: {
      if (client->events.onping)
        client->events.onping(client);
      else
        __ws_handle_ping (client);
      } break;
    case WS_FR_OP_PONG: {
        if (client->events.onpong)
          client->events.onpong(client);
      } break;
    default: break;
  }
  if (frame) {
    __ws_disponse (frame->payload);
    __ws_disponse (frame);
  }
}

static void *__ws_parse_frame(void *self) {
  ws_client *cli = (ws_client *)self;
  if (!cli) return NULL;
  if (__ws_get_client_state(cli) == WS_STATE_CONNECTING) {
    if (__ws_handshake(cli)) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return NULL;
      return NULL;
    }
    if (cli->events.onopen)
      cli->events.onopen(cli);
  }
  if (__ws_get_client_state(cli) != WS_STATE_OPEN) return NULL;
  char *payload = NULL;
  uint64_t recv_len = 0;
  for (;;) {
    uint8_t data[10] = {0};
    if (__ws_restrict_read(cli, data, 2) < 2) {
      if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
      __ws_close_client(cli);
      goto clean_up;
    }

    uint8_t opcode = data[0] & 15;
    int beg = opcode != WS_FR_OP_CONT;
    int fin = data[0] >> 7;
    int mask = data[1] >> 7;
    uint8_t mask_key[4] = {0};

    uint64_t pl_len = data[1] & 127;

    if (pl_len == 126) {
      memset(data, 0, sizeof(data));
      if (__ws_restrict_read(cli, data, 2) < 2) {
        if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
        __ws_close_client(cli);
        goto clean_up;
      }
      pl_len = be16toh(*(uint16_t*)data);
    } else if (pl_len == 127) {
      memset(data, 0, sizeof(data));
      if (__ws_restrict_read(cli, data, 8) < 8) {
        if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
        __ws_close_client(cli);
        goto clean_up;
      }
      pl_len = be64toh(*(uint64_t*)data) & ~(1ULL << 63);
    }
    if (mask) {
      memset(data, 0, sizeof(data));
      if (__ws_restrict_read(cli, data, 4) < 4) {
        if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
        __ws_close_client(cli);
        goto clean_up;
      }
      *(uint32_t*)mask_key = *(uint32_t*)data;
    }
    char *tmp = realloc(payload, recv_len + pl_len + 1);
    if (!tmp) {
      __ws_close_client(cli);
      goto clean_up;
    }
    payload = tmp;
    if (__ws_restrict_read(cli, payload + recv_len, pl_len) <= 0) {
      if((errno == EWOULDBLOCK || errno == EAGAIN)) return NULL;
      __ws_close_client(cli);
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
      __ws_handle_all_frame(cli, frame);
      break;
    }
  }
  return NULL;

clean_up:
  __ws_disponse(payload);
  return NULL;
}

static void * __ws_call_periodic(void *_self) {
  ws_client * cli = (ws_client *)_self;
  if (!cli || !cli->events.onperodic) return NULL;
  cli->events.onperodic(cli);
  return NULL;
}

static void *__ws_client_loop(void *self) {
  ws_client *cli = (ws_client *)self;
  if (!cli) return NULL;

  if (cli->timeout > 0 && cli->events.onperodic) {
    int time_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (time_fd > 0) {
      if (__ws_epoll_add(cli->epollfd, time_fd, EPOLLIN | EPOLLET) < 0) {
        __ws_close_socket(time_fd);
      } else {
        cli->time_fd = time_fd;
        struct itimerspec its;
        its.it_value.tv_sec = cli->timeout > 1000 ? cli->timeout / 1000 : 0;
        its.it_value.tv_nsec = cli->timeout > 1000 ? (cli->timeout % 1000) % 1000 : cli->timeout;
        its.it_interval = its.it_value;
        if (timerfd_settime(cli->time_fd, 0, &its, NULL) != 0) {
          __ws_epoll_delete(cli->epollfd, cli->time_fd);
          __ws_close_socket(cli->time_fd);
        }
      }
    }
  }

  struct epoll_event events[MAX_EVENTS] = {0};

  int i, fds;
  const uint32_t err_mask = EPOLLERR | EPOLLHUP;
  for (;;) {
    if (cli->is_stop) break;
    fds = epoll_wait(cli->epollfd, events, MAX_EVENTS, -1);
    if (fds < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
      break;
    }
    for (i = 0; i < fds; i++) {
      if (events[i].data.fd == cli->listen_sock) {
        // if (!(events[i].events & (EPOLLIN | EPOLLOUT)) continue;
        if (events[i].events & err_mask) break;
        pthread_t client_thread;
        if (pthread_create(
          &client_thread, NULL, __ws_parse_frame, cli
        )) {
          #ifndef NDEBUG
          perror ("pthread_create");
          #endif
          exit(EXIT_FAILURE);
        }
        pthread_detach(client_thread);
      } else if (events[i].data.fd == cli->time_fd) {
        if (events[i].events & EPOLLIN) {
          unsigned long long val;
          static int n_id;
          if (read(events[i].data.fd, &val, sizeof(val)) > 0) {
            printf("Received timerfd event via epoll: %d\n", n_id++);
          }
          if (cli->events.onperodic) {
            pthread_t periodic_thread;
            if (pthread_create(&periodic_thread, NULL, __ws_call_periodic, cli)) {
              #ifndef NDEBUG
              perror ("pthread_create");
              #endif
              exit(EXIT_FAILURE);
            }
            pthread_detach(periodic_thread);
          }
        }
      }
    }
  }
  if (cli->events.onclose)
    cli->events.onclose(cli);
  return NULL;
}

void ws_send(ws_client *client, const char *msg) {
  ws_send_bytes(client, msg, msg ? strlen(msg) : 0, WS_FR_OP_TEXT);
}
void ws_send_bytes(ws_client *client, const char *msg, size_t len, int op) {
  if (__ws_get_client_state(client) != WS_STATE_OPEN) return;
  __ws_send_frame(client, msg, len, op);
}
void ws_event_close(ws_client *client, const char *reason) {
  __ws_send_close (client, 1000, reason);
  __ws_set_client_state(client, WS_STATE_CLOSING);
  __ws_close_client(client);
}
ws_client *ws_event_create_client (void *data) {
  ws_client *rv = calloc(1, sizeof(struct _client));
  if (!rv) return NULL;

    if (pthread_mutex_init(&rv->mtx_sta, NULL)) {
    __ws_disponse(rv);
    return NULL;
  }

  if (pthread_mutex_init(&rv->mtx_snd, NULL)) {
    pthread_mutex_destroy(&rv->mtx_sta);
    __ws_disponse(rv);
    return NULL;
  }

  memset(&rv->buf, 0, sizeof(rv->buf));
  memset(&rv->url, 0, sizeof(struct url_t));

  __ws_set_client_state(rv, WS_STATE_CONNECTING);

  rv->data = data;

  rv->id = ws_client_counter++;
  return rv;
}
void ws_client_connect(ws_client *client, const char *url, const char *origin) {
  if (!client || !url) return;
  if (__ws_parse_url(url, &client->url)) return;
  char port[50] = {0};
  if (snprintf(port, sizeof(port) - 1, "%d", client->url.port) <= 0) {
    return;
  }
  int fd = create_and_connect(client->url.host, port);
  if (fd < 0) return;
  int ep = epoll_create1(0);
  if (ep < 0) return;
  client->listen_sock = fd;
  client->epollfd = ep;
  if (__ws_epoll_add(ep, fd, EPOLLOUT) < 0) {
    return;
  }
  client->url.origin = origin;
}
void ws_event_set_timeout(ws_client *cli, unsigned int timeout) {
  if (!cli) return;
  cli->timeout = timeout;
}
void ws_event_listen (ws_client * client, int as_thread) {
  if (!client) return;
  if (as_thread) {
    if (pthread_create(&client->thread, 0, __ws_client_loop, client)) {
      exit(EXIT_FAILURE);
    }
  } else {
    __ws_client_loop(client);
  }
}
void ws_event_dispose(ws_client *client) {
  if (!client) return;

  ws_client_counter--;

  __ws_epoll_delete(client->epollfd, client->listen_sock);

  __ws_close_socket (client->listen_sock);

  pthread_mutex_destroy(&client->mtx_sta);
  pthread_mutex_destroy(&client->mtx_snd);

  __ws_disponse(client);
}
void ws_event_hold(ws_client *client) {
  if (!client) return;
  if (client->thread) {
    pthread_join(client->thread, 0);
  }
}
