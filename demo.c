#include <stdio.h>
#include "ws.h"

static void onopen(ws_client *cli) {
  printf("Connected via id #%ld\n", cli->id);
}

static void onclose(ws_client *cli) {
  printf("#%ld id is disconnected\n", cli->id);
}

static void ondata(ws_client *cli, int op, const char *data, size_t len) {
  if (op != WS_FR_OP_TEXT) return;
  if (len < BUFFER_SIZE) {
    printf("#%ld -> data: %s\n", cli->id, data);
  } else {
    printf("#%ld -> %ld bytes\n", cli->id, len);
  }
}

int main() {
  ws_client *cli = ws_event_create_client(NULL);
  if (!cli) return -1;

  cli->events.onopen = onopen;
  cli->events.onclose = onclose;
  cli->events.onmessage = ondata;

  ws_client_connect(cli, "ws://127.0.0.1:9876", NULL);

  ws_event_listen(cli, 0);
  ws_event_dispose(cli);
  return 0;
}
