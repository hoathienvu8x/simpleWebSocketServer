#include "ws.h"
#include <unistd.h>
#include <errno.h>
#include <sys/timerfd.h>

static int handle_verify (ws_client * client);
static int closesocket(int fd) {
  shutdown(fd, SHUT_RDWR);
  return close(fd);
}
static int create_and_bind (const char *port)
{

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
      closesocket(sfd);
      continue;
    }

    s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0) {
      /* We managed to bind successfully! */
      break;
    }

    closesocket (sfd);
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

int setNonblocking (int sfd)
{

  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1) {
    #ifndef NDEBUG
    perror ("fcntl");
    #endif
    return -1;
  }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1) {
    #ifndef NDEBUG
    perror ("fcntl");
    #endif
    return -1;
  }

  return 0;
}

static int my_epoll_add(int epoll_fd, int fd, uint32_t events)
{
  struct epoll_event event;

  /* Shut the valgrind up! */
  memset(&event, 0, sizeof(struct epoll_event));

  event.events  = events;
  event.data.fd = fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
    #ifndef NDEBUG
    perror("my_epoll_add(): ");
    #endif
    return -1;
  }
  return 0;
}

static int my_epoll_delete(int epoll_fd, int fd)
{
  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
    #ifndef NDEBUG
    perror("my_epoll_delete(): ");
    #endif
    return -1;
  }
  return 0;
}

void *create_client (int fd, ws_server * server)
{
  if (!server) return NULL;
  if (server->max_fd < fd) {
    //server->clients = realloc(server->client);
    server->max_fd = fd;
    server->clients =
      (ws_client *) realloc (server->clients, fd * sizeof (ws_client));
    if (!server->clients) {
      exit (EXIT_FAILURE);
    }
  }
  ws_client *client = &server->clients[fd];
  client->data = (char *) malloc (sizeof (char) * BUFFER_SIZE + 1);
  client->size = BUFFER_SIZE;
  client->data[client->size] = '\0';
  client->assgined = 0;
  client->state = 0;
  client->fd = fd;
  client->server = server;
  return client;
}

void close_client (ws_client * client)
{
  if (client != NULL) {
    ws_server *server = client->server;
    my_epoll_delete(server->epollfd, client->fd);
    closesocket (client->fd);
    free (client->data);
    if (client->fd < server->max_fd) {
      server->clients[client->fd] = (struct client) { 0 };      // delete the client
    }
  }
}

void get_frame (ws_client * client)
{
  if (!client) return;
  char buffer[BUFFER_SIZE];
  int read_size = read (client->fd, buffer, BUFFER_SIZE);
  if (read_size <= 0) {
    if (read_size < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
      return;
    }
    close_client (client);
    return;
  }
  if (read_size > client->size - client->assgined) {
    //reallocate the client's buffer
    client->data =
      (char *) realloc (client->data, client->size + read_size * 2 + 1);
    if (client->data) {
      client->size = client->size + read_size * 2;
      client->data[client->size] = '\0';
    } else {
      return;
    }

  }
  int offset = client->assgined;
  char *copy_str = client->data + offset;
  memcpy (copy_str, buffer, read_size);
  client->assgined += read_size;

  if (!client->state) {
    int result = handle_verify (client);
    if (result) {
      close_client(client);
      return;
    }
    if (client->server->onopen)
      client->server->onopen(client);
  }
  //get websocket frame
  if (client->data && client->state == 1) {
    int idx = 2;
    char byte_one = client->data[0];
    uint opcode = byte_one & 0x0f;
    char byte_two = client->data[1];
    int mask = byte_two & 0x80;
    uint64_t len = byte_two & 0x7f;
    if (opcode > 125) {
      if (client->assgined < 8) {
        close_client (client);
        return;
      }
    }
    if (len == 126) {
      len = ((((uint64_t)client->data[2])) << 8 | client->data[3]);
      idx += 2;
    } else if (len == 127) {
      len = (
        (((uint64_t)client->data[2]) << 56) |
        (((uint64_t)client->data[3]) << 48) |
        (((uint64_t)client->data[4]) << 40) |
        (((uint64_t)client->data[5]) << 32) |
        (((uint64_t)client->data[6]) << 24) |
        (((uint64_t)client->data[7]) << 16) |
        (((uint64_t)client->data[8]) << 8) |
        (uint64_t)client->data[9]
      );
      idx += 8;

    }
    if ((uint64_t)client->assgined < idx + 4 + len) {
      return;
    }
    char *payload = NULL;
    if (mask) {
      char mask_bytes[4];
      memcpy (mask_bytes, client->data + idx, 4);
      idx += 4;
      payload = unmask (mask_bytes, client->data + idx, len);        //get payload to handle_all_frame and end  have to destory the memory area
    } else {
      payload = client->data + idx;
    }
    memset (client->data, '0', idx + len);      //
    char *remain = client->data + idx + len;
    client->assgined = client->assgined - idx - len;
    memcpy (client->data, remain, client->assgined);

    //construct ws frame
    ws_frame *frame = (ws_frame *) malloc (sizeof (ws_frame));
    if (!frame)
      return;
    frame->opcode = opcode;
    frame->payload = payload;
    frame->payload_len = len;
    handle_all_frame (client, frame);
  }
}


/*verify the http handshark and then hjack to websocket else close the client*/
static int handle_verify (ws_client * client)
{
  if (!client) return -1;
  if (client->state) return 0;
  //get all http request data and then parse it
  //split the request and then get the  header "sec-websocket-key" and the get the value

  char *http_header = strstr (client->data, "\r\n\r\n");
  if (!http_header) return -1;
  if (strncasecmp(client->data, "GET ", 4) != 0) return -1;
  char *start = NULL;
  start = strstr (client->data, "Sec-WebSocket-Key");
  if (!start) return -1;
  char *end = strstr (start, "\r\n");
  char sec[255] = { 0 };
  strncpy (sec, start, end - start);

  static char *const_key = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char secure_key[255] = { 0 };
  char *key = strstr (sec, ":") + 2;
  sprintf (secure_key, "%s%s", key, const_key);
  key = get_socket_secure_key ((const unsigned char *)secure_key);
  if (!key)
    return -1;
  char *res_header_str =
    "HTTP/1.1 101 Web Socket Protocol Handshake\r\nUpgrade: "
    "WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s%s";
  char *double_newline = "\r\n\r\n";;
  char msg[255] = { 0 };
  if (sprintf (msg, res_header_str, key, double_newline) <= 0) {
    return -1;
  }
  free (key);
  char *buf2 = msg;
  size_t slen = strlen(msg);
  int retval = 0;
  do {
    retval = write (client->fd, buf2, slen);
    if (retval < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (retval == 0) {
      break;
    }
    buf2 += retval;
    slen -= (size_t)retval;
  } while ((errno == EAGAIN || errno == EWOULDBLOCK) && slen > 0);

  if (slen != 0) return -1;

  int http_header_len = http_header - client->data + 4;
  //copy the remain data
  memset (client->data, '0', http_header_len);    //
  char *remain = client->data + http_header_len;
  client->assgined = client->assgined - http_header_len;
  memcpy (client->data, remain, client->assgined);
  client->state = 1;
  return 0;
}

void send_frame (
  ws_client * client, int opcode, char *payload, int payload_size
) {
  if (!client) return;
  int frame_size = payload_size;
  int retval = 0;
  char op_code = 0x80 | opcode;
  char b2 = 0;
  char *frame_data = NULL;
  char *buf2 = NULL;
  if (payload_size < 126) {
    frame_size += 2;
    frame_data = (char *) malloc (sizeof (char) * frame_size + 1);
    if (!frame_data)
      return;

    frame_data[0] = op_code;
    b2 |= payload_size;
    frame_data[1] = b2;
    memcpy (frame_data + 2, payload, payload_size);
  } else if (payload_size == 126) {
    frame_size += 4;
    frame_data = (char *) malloc (sizeof (char) * frame_size + 1);
    if (!frame_data)
      return;

    frame_data[0] = op_code;
    b2 |= payload_size;
    frame_data[1] = b2;
    char *payload_size_extra = (char *) &payload_size;
    frame_data[2] = payload_size_extra[0];
    frame_data[3] = payload_size_extra[1];
    memcpy (frame_data + 4, payload, payload_size);
  } else {
    frame_size += 10;
    b2 |= 127;
    frame_data = (char *) malloc (sizeof (char) * frame_size + 1);
    if (!frame_data)
      return;

    frame_data[0] = op_code;
    frame_data[1] = b2;
    frame_data[2] = (0 >> 24) & 0xFF;
    frame_data[3] = (0 >> 16) & 0xFF;
    frame_data[4] = (0 >> 8) & 0xFF;
    frame_data[5] = 0 & 0xFF;
    frame_data[6] = (payload_size >> 24) & 0xFF;
    frame_data[7] = (payload_size >> 16) & 0xFF;
    frame_data[8] = (payload_size >> 8) & 0xFF;
    frame_data[9] = payload_size & 0xFF;
    memcpy (frame_data + 10, payload, payload_size);

  }
  if (frame_data) {
    frame_data[frame_size] = '\0';
    buf2 = frame_data;
    do {
      retval = write (client->fd, buf2, frame_size);
      if (retval < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) break;
      frame_size -= retval;
      buf2 += retval;
    } while ((errno == EAGAIN || errno == EWOULDBLOCK) && frame_size > 0);
    #ifndef NDEBUG
    if (frame_size > 0) {
      printf("send frame data is not completed\n");
    }
    #endif
    free (frame_data);
  }
}

void handle_all_frame (ws_client * client, ws_frame * frame)
{
  if (frame == NULL || client == NULL) {
    return;
  }
  //handle the ws_frame
  enum opcode enum_opcode = (enum opcode) frame->opcode;
  switch (enum_opcode) {
  case TEXT: {
      //handle_text(client,frame->payload,strlen(frame->payload));
      //broadcast (client->server, frame->payload);
      if (client->server->onmessage)
        client->server->onmessage(
          client, frame->opcode, frame->payload, frame->payload_len
        );
    } break;
  case BINARY:
    break;
  case CLOSE: {
      char *reason = NULL;
      if (strlen (frame->payload) > 2) {
        reason = &frame->payload[2];
      }
      short close_code = (short) *(frame->payload);
      handle_close (client, close_code, reason);
    } break;
  case PING: {
    if (client->server->onping)
      client->server->onping(client);
    else
      handle_ping (client);
    } break;
  case PONG: {
      if (client->server->onpong)
        client->server->onpong(client);
    } break;
  default:
    handle_close (client, 1002, "unknown opcode");
  }
  if (frame) {
    //case the opcode and then execute specify  opcode-handler
    free (frame->payload);
    free (frame);
  }
}

void handle_text (ws_client * client, char *payload, int payload_size)
{
  if (!client) return;
//handler the raw data
  enum opcode enum_opcode = TEXT;
  send_frame (client, enum_opcode, payload, payload_size);
}

void handle_ping (ws_client * client)
{
  if (!client) return;
//handler ping data send pong
  char *payload = "pong pong";
  enum opcode enum_opcode = PONG;
  send_frame (client, enum_opcode, payload, strlen (payload));
}

void handle_close (ws_client * client, int code, char *reason)
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
  free (payload);
  if (client->server->onclose)
    client->server->onclose(client);
  close_client (client);
}

char *unmask (char *mask_bytes, char *buffer, int buffer_size)
{
  char *payload = (char *) malloc (sizeof (char) * buffer_size + 1);
  int mod = 0;
  int i;
  for (i = 0; i < buffer_size; i++) {
    mod = i % 4;
    payload[i] = mask_bytes[mod] ^ buffer[i];
  }
  payload[buffer_size] = '\0';
  return payload;
}


void event_loop (ws_server * server)
{
  /* Code to set up listening socket, 'listen_sock',
     (socket(), bind(), listen()) omitted */
  int conn_sock, nfds;
  struct sockaddr_in servaddr;
  socklen_t addrlen = sizeof(servaddr);
  if (server->timeout > 0) {
    int time_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (time_fd > 0) {
      if (my_epoll_add(server->epollfd, time_fd, EPOLLIN | EPOLLET) < 0) {
        closesocket(time_fd);
      } else {
        server->time_fd = time_fd;
        struct itimerspec its;
        its.it_value.tv_sec = server->timeout > 1000 ? server->timeout / 1000 : 0;
        its.it_value.tv_nsec = server->timeout > 1000 ? (server->timeout % 1000) % 1000 : server->timeout;
        its.it_interval = its.it_value;
        if (timerfd_settime(server->time_fd, 0, &its, NULL) != 0) {
          my_epoll_delete(server->epollfd, server->time_fd);
          closesocket(server->time_fd);
        } else {
          printf("time_fd = %d init\n", server->time_fd);
        }
      }
    }
  }

  for (;;) {
    nfds = epoll_wait (server->epollfd, server->events, MAX_EVENTS, -1);
    if (nfds == -1) {
      #ifndef NDEBUG
      perror ("epoll_wait");
      #endif
      exit(EXIT_FAILURE);
    }
    int n, client_index;
    for (n = 0; n < nfds; ++n) {
      if (server->events[n].data.fd == server->listen_sock) {
        conn_sock = accept (server->listen_sock,
                            (struct sockaddr *) &servaddr, &addrlen);
        if (conn_sock == -1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
          #ifndef NDEBUG
          perror ("accept");
          #endif
          exit(EXIT_FAILURE);
        }
        if (setNonblocking (conn_sock) < 0) {
          closesocket(conn_sock);
          continue;
        }

        if (server->timeout > 1000) {
          struct timeval tv;
          tv.tv_sec = server->timeout / 1000;
          tv.tv_usec = (server->timeout % 1000) * 1000;
          if (setsockopt(conn_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
            closesocket(conn_sock);
            continue;
          }

          if (setsockopt(conn_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
            closesocket(conn_sock);
            continue;
          }
        }
        if (my_epoll_add (server->epollfd, conn_sock, EPOLLIN | EPOLLET) == -1) {
          closesocket(conn_sock);
          continue;
        }
        server->current_event_size += 1;
        if (NULL == create_client (conn_sock, server)) {
          my_epoll_delete(server->epollfd, conn_sock);
          closesocket(conn_sock);
        }

      } else if (server->events[n].data.fd == server->time_fd) {
        unsigned long long val;
        static int n_id;
        int rcc = 0;
        printf("%d\n", server->events[n].data.fd);
        if ((rcc = read(server->events[n].data.fd, &val, sizeof(val))) > 0) {
          printf("Received timerfd event via epoll: %d\n", n_id++);
        }
        printf("rcc = %d\n",rcc);
      } else {
        client_index = server->events[n].data.fd;
        get_frame (&server->clients[client_index]);
      }
    }
  }

}

ws_server *create_server (const char *port)
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
  ws_server *server = (ws_server *) malloc (sizeof (ws_server));
  if (!server)
    return NULL;

  server->epollfd = epoll_create1 (0);
  server->events = calloc (MAX_EVENTS, sizeof (struct epoll_event));
  server->listen_sock = listen_sock;
  server->timeout = 10000;
  server->time_fd = -1;

  if (!server->events) {
    goto clean_up;
  }
  server->max_fd = MAX_EVENTS;
  server->clients = (ws_client *) malloc (sizeof (ws_client) * MAX_EVENTS);
  if (!server->clients) {
    goto clean_up;
  }
  if (server->epollfd == -1) {
    #ifndef NDEBUG
    perror ("epoll_create1");
    #endif
    goto clean_up;
  }
  if (my_epoll_add (server->epollfd, listen_sock, EPOLLIN) == -1) {
    #ifndef NDEBUG
    perror ("epoll_ctl: listen_sock");
    #endif
    goto clean_up;
  }
  server->onopen = NULL;
  server->onmessage = NULL;
  server->onclose = NULL;
  server->onping = NULL;
  server->onpong = NULL;
  return server;

clean_up:
  if (server->epollfd != -1) closesocket(server->epollfd);
  if (server->events) free (server->events);
  if (server->clients) free (server->clients);
  free(server);
  return NULL;
}

void broadcast (ws_server *server, char *msg)
{
  if (!server || !msg || strlen(msg) == 0) return;
  int msg_len = strlen (msg);
  int client_idx;
  for (client_idx = 0; client_idx < server->max_fd; client_idx++) {
    ws_client *client = &server->clients[client_idx];
    if (client != NULL && client->state != 0) {
      handle_text (client, msg, msg_len);
    }
  }
}
void event_loop_dispose(ws_server *server) {
  if (!server) return;
  closesocket(server->epollfd);
  closesocket(server->listen_sock);
  closesocket(server->time_fd);
  if (server->clients) {
    for (int i = 0; i < server->max_fd; i++) {
      close_client(&server->clients[i]);
    }
  }
  free(server->clients);
  free(server);
}
void ws_server_set_timeout(ws_server *srv, unsigned int timeout) {
  if (!srv) return;
  srv->timeout = timeout;
}
