#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

#define true 1
#define false 0
#define MAX_EVENTS 64
#define MAX_CONNECTIONS 64
#define MAX_BUF 512 
#define TIMEOUT 100
#define LOG( msg ){ printf("LOG:\n%s\n", msg); }
//#define DBG 1
#define N_METHODS 5
#define ARRLEN( arr ) ( sizeof( arr ) / sizeof( arr[0] ) )
#define ASSERT( a, b )\
if( a == 0 )\
{\
  printf("[ERROR]: %s\n", b );\
  exit(1);\
}

struct route_t;
struct sv_data_t;
struct cl_data_t;

typedef unsigned char bool;
typedef unsigned char uc8;
typedef unsigned int ui32;
typedef char *( *route_proc )( struct cl_data_t *cl_data );

struct sv_data_t
{
  int fd;
  int epfd;
  struct epoll_event event;
  struct epoll_event *events;
  struct route_t *routes;
  ui32 routes_len;
};

struct cl_data_t
{
  int fd;
  char *ip;
  char in[MAX_BUF];
  char out[MAX_BUF];
};

struct route_t
{
  char *method;
  char *url;
  route_proc proc;
};

static bool g_running = true;
static char *g_methods[] =
{
  "GET",
  "PUT",
  "POST",
  "PATCH",
  "DELETE"
};

void
on_signal( int sig )
{
  g_running = false;
  LOG("RIP");
}

void signal_init()
{
  signal(SIGINT,on_signal);
  signal(SIGKILL,on_signal);
  signal(SIGQUIT,on_signal);
  signal(SIGTERM,on_signal);
  signal(SIGHUP,on_signal);
}

struct sv_data_t
sv_init( int sv_fd, struct route_t *routes, ui32 routes_len )
{
  struct sv_data_t d = {0};
  d.fd               = sv_fd;
  d.routes           = routes;
  d.routes_len       = routes_len;
  d.epfd             = epoll_create1( 0 );
  d.event.data.fd    = sv_fd;
  d.event.events     = EPOLLIN|EPOLLET; 
  int status         = epoll_ctl( d.epfd, EPOLL_CTL_ADD, sv_fd, &d.event );
  d.events           = calloc( MAX_EVENTS, sizeof( struct epoll_event ) );
  return( d );
}

struct cl_data_t*
cl_init( int fd, struct sockaddr_in *addr )
{
  struct cl_data_t *d = malloc( sizeof( struct cl_data_t ) );
  d->fd   = fd;
  d->ip   = inet_ntoa( addr->sin_addr );
  memset( d->in, 0, MAX_BUF );
  memset( d->out, 0, MAX_BUF );
  return d;
}

struct addrinfo
sk_init_hints( void )
{
  struct addrinfo hints;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family       = AF_INET;
  hints.ai_socktype     = SOCK_STREAM;
  hints.ai_flags        = AI_PASSIVE;
  return( hints );
}

void
sk_init_opts( int sv_fd )
{
  int status = fcntl( sv_fd, F_SETFL, O_NONBLOCK ); /* Non-Blocking */
  int n = 1;
  ASSERT( status == 0, "Non-Blocking Failed" );
  status = setsockopt( sv_fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof( n ) );
  ASSERT( status == 0, "Reuse Address Failed" );    
  setsockopt( sv_fd, IPPROTO_TCP, TCP_NODELAY, &n, sizeof( n ) );
  ASSERT( status == 0, "TCP No Delay Failed" );
  setsockopt( sv_fd, IPPROTO_TCP, TCP_QUICKACK, &n, sizeof( n ));
  ASSERT( status == 0, "TCP QuickACK Failed" );
}

int
sk_create_bind( char *port )
{
  struct addrinfo hints = sk_init_hints();
  struct addrinfo *res  = NULL;
  int status = getaddrinfo( NULL, port, &hints, &res );
  ASSERT( status == 0, "Create Socket Failed" );
  int sv_fd  = socket( res->ai_family, res->ai_socktype, res->ai_protocol );
  sk_init_opts( sv_fd );
  status = bind( sv_fd, res->ai_addr, res->ai_addrlen );
  ASSERT( status == 0, "Bind Failed" );
  status = listen( sv_fd, MAX_CONNECTIONS );
  ASSERT( status == 0, "Listen Failed" );
  return(sv_fd);
}

void
ep_on_connect( struct sv_data_t *sv )
{
  struct sockaddr_in in;
  socklen_t len = sizeof( in );
  struct epoll_event e;
  int cl_fd  = accept( sv->fd, (struct sockaddr*) &in, &len );
  ASSERT( cl_fd  != -1, "Failed To Accept Socket" );
  e.data.ptr = cl_init( cl_fd, &in );
  e.events   = EPOLLIN;
  int status = fcntl( cl_fd, F_SETFL, O_NONBLOCK );
  ASSERT( status == 0, "Non-Blocking Failed" );
  epoll_ctl( sv->epfd, EPOLL_CTL_ADD, cl_fd, &e );
}

void
ep_on_disconnect( struct sv_data_t *sv, struct cl_data_t *cl )
{
  struct epoll_event e;
  e.events   = EPOLLOUT;
  e.data.ptr = cl;
  epoll_ctl( sv->epfd, EPOLL_CTL_DEL, cl->fd, &e );
  shutdown( cl->fd, SHUT_RDWR );
  close( cl->fd );
  free( cl );
}

void
ep_on_error( struct sv_data_t *sv, struct cl_data_t *cl )
{
}

void
ep_on_send( struct sv_data_t *sv, struct cl_data_t *cl )
{
  int bytes = 0, pos = 0, len = strlen( cl->out );
  for( ; bytes != len; pos += bytes, len -= bytes )
    bytes = send( cl->fd, cl->out+pos, len, MSG_NOSIGNAL );
  #ifdef DBG
  printf("%s | RESPONSE | \"%s\" | \n",cl->ip, cl->out);
  #endif
  ep_on_disconnect( sv, cl );
}

char
*sk_get_method( char *in )
{
  char *method = NULL;
  for( int i=0; i < N_METHODS; i++)
  {
    char *method = g_methods[i];
    if( strstr( in, method ) ) return method;
  }
  return(NULL);
}

char*
sk_get_url( char *in )
{
  char *start = strstr( in, "/" );
  if( !start ) return NULL;
  char *end = strstr( in, "HTTP/" );
  if( !end ) return NULL;
  ui32 len = end-start-1;
  char *route = malloc( len );
  strncpy( route, start, len ); 
  return(route); 
}

struct route_t*
sk_find_route( struct sv_data_t *sv, struct cl_data_t *cl )
{
  char *method = sk_get_method( cl->in );
  char *url    = sk_get_url( cl->in );
  for( int i=0; i < sv->routes_len ; i++ )
  {
    struct route_t *sv_route = &sv->routes[i]; 
    int method_match = strcmp( method, sv_route->method );
    int url_match    = strcmp( url, sv_route->url );
    if( method_match == 0 && url_match == 0 )
    {
      return sv_route;
    }
  }
  free(url);
  return NULL;
}

void
ep_on_recv( struct sv_data_t *sv, struct cl_data_t *cl )
{
  int bytes = 0, pos = 0;
  for( ; bytes != -1; pos += bytes )
    bytes = recv( cl->fd, cl->in + pos, MAX_BUF, MSG_DONTWAIT );
  struct route_t *route = sk_find_route( sv, cl );
  if( route )
  {
    char *result = route->proc( cl );
    strcpy( cl->out, result ); 
  }
  struct epoll_event e;
  e.events   = EPOLLOUT;
  e.data.ptr = cl;
  epoll_ctl( sv->epfd, EPOLL_CTL_MOD, cl->fd, &e );
}

void
sk_run( struct sv_data_t *sv )
{
  for(;g_running;)
  {
    int fds = epoll_wait( sv->epfd, sv->events, MAX_EVENTS, TIMEOUT );
    for( int i=0; i < fds; i++ )
    {
      ui32 ev   = sv->events[ i ].events;
      int cl_fd = sv->events[ i ].data.fd;
      struct cl_data_t *cl = sv->events[ i ].data.ptr;
      if( sv->fd == cl_fd && (ev & EPOLLIN) ) ep_on_connect( sv );
      else if( (ev & EPOLLERR) || (ev & EPOLLRDHUP) ) ep_on_error( sv, cl );
      else if( (ev & EPOLLOUT) ) ep_on_send( sv, cl );
      else if( (ev & EPOLLIN) ) ep_on_recv( sv, cl );
    }
  }
  free( sv->events );
  close( sv->epfd );    
}

void
sk_init( char *port, struct route_t *routes, ui32 routes_len )
{
  signal_init();
  int sv_fd = sk_create_bind( port );
  struct sv_data_t sv_data = sv_init( sv_fd, routes, routes_len );
  sk_run( &sv_data );
}
/************************************************************** 
Tests
***************************************************************/
char
*hello( struct cl_data_t *cl )
{ 
  return("world");
}

char
*lol( struct cl_data_t *cl )
{
  return("kek");
}
/* TODO: Make routes a map for O(1),
 * implement using red-black trees.
 */
static struct route_t test_routes[] = 
{
  { "GET", "/hello", hello },
  { "GET", "/lol", lol }
};

int
main( int argc, char **argv )
{
  sk_init( "8008", test_routes, 2 );
  return(0);
}
