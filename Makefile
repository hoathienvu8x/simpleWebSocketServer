CC = gcc
LDFLAGS = -I. -ldl -lpthread -lm
ifeq ($(build),release)
	CFLAGS = -O3
	LDFLAGS += -DNDEBUG=1
else
	CFLAGS = -Og -g
endif
CFLAGS += -std=gnu99 -Wall -Wextra -Werror -pedantic
RM = rm -rf

OBJECTS = ws.o
OBJECTS := $(addprefix objects/,$(OBJECTS))
EXECUTABLE = demo

all: objects $(EXECUTABLE)

objects:
	@echo "Create 'objects' folder ..."
	@mkdir -p objects

$(EXECUTABLE): objects/demo.o $(OBJECTS)
ifeq ($(build),release)
	@echo "Build release '$@' executable ..."
else
	@echo "Build '$@' executable ..."
endif
	@$(CC) objects/demo.o $(OBJECTS) -o $@ $(LDFLAGS)
	@$(RM) objects/demo.o

objects/%.o: %.c
	@echo "Build '$@' object ..."
	@$(CC) -c $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	@echo "Cleanup ..."
	@$(RM) $(OBJECTS) $(EXECUTABLE)
