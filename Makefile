CC = gcc
CFLAGS = -Og -g
LDFLAGS = -I. -ldl -lpthread -lm
ifeq ($(build),release)
	CFLAGS = -O3
	LDFLAGS += -DNDEBUG=1
endif
CFLAGS += -Wall -pedantic -fPIC
RM = rm -rf
SOURCES = $(filter-out 66916835.c, $(wildcard *.c))
OBJECTS = $(addprefix objects/,$(SOURCES:.c=.o))

all: objects $(SOURCES)

objects:
	mkdir -p objects

epoll: objects/66916835.o
	$(CC) objects/66916835.o -o $@ $(LDFLAGS)

objects/%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	$(RM) objects/*.o $(EXECUTABLE)
