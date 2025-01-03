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
  handle_text(cli, (char *)resp, strlen(resp));
}

int main (int argc, char **argv)
{
  const char *port = "8088";
  if (argc > 1) {
    port = argv[1];
  }
  ws_server *server = create_server (port);
  if (!server) return -1;
  server->onopen = onopen;
  server->onclose = onclose;
  server->onmessage = ondata;
  event_loop (server);
  event_loop_dispose (server);
  return 0;
}
