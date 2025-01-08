#include "ws.h"

static void onopen(ws_client *cli) {
  (void)cli;
  printf("connected\n");
}

static void onclose(ws_client *cli) {
  (void)cli;
  printf("disconected\n");
}

static void ondata(ws_client *cli, int opcode, const char *data, size_t len) {
  if (opcode == TEXT) {
    if (len < BUFFER_SIZE)
      printf("recv (%ld): %s\n", len, data);
    else
      printf("recv (%ld)\n", len);
  } else {
    printf("recv (%ld)\n", len);
  }
  const char *resp = "s[\"good job\"]";
  ws_send(cli, (char *)resp);
}

static void onperodic(ws_server *srv) {
  ws_send_all(srv, "3");
}

int main (int argc, char **argv)
{
  const char *port = "8088";
  if (argc > 1) {
    port = argv[1];
  }
  ws_server *server = ws_event_create_server (port);
  if (!server) return -1;
  server->events.onopen = onopen;
  server->events.onclose = onclose;
  server->events.onmessage = ondata;
  server->events.onperodic = onperodic;
  ws_event_loop (server);
  ws_event_dispose (server);
  return 0;
}
