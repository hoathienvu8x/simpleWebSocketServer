#include "ws.h"

int main (int argc, char **argv)
{
  const char *port = "8088";
  if (argc > 1) {
    port = argv[1];
  }
  ws_server *server = create_server (port);
  event_loop (server);
  return 1;
}
