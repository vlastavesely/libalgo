CC = gcc
RM = rm -f
CFLAGS = -Ofast -Wall
LIBS =

LIB     = libsec.so
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:%.c=%.o)
CFLAGS  = -Wall -Ofast -fPIC
LIBS    =

TEST_PROG    = tests/test
TEST_SOURCES = $(wildcard tests/*.c)
TEST_OBJECTS = $(TEST_SOURCES:%.c=%.o)
TEST_CFLAGS  = $(CFLAGS) $(shell pkg-config --cflags check)
TEST_LIBS    = $(LIBS) $(shell pkg-config --libs check)

all:

.PHONY: all test clean

all: $(LIB)

include $(wildcard *.d tests/*.d)

$(LIB): $(OBJECTS)
	$(CC) -MMD -MP -shared $^ -o $@ $(CFLAGS) $(LIBS)

%.o: %.c
	$(CC) -MMD -MP -c $< -o $@ $(CFLAGS) $(LIBS)

test: $(TEST_PROG)
	LD_LIBRARY_PATH=$$(pwd) $(TEST_PROG)

$(TEST_PROG): $(TEST_OBJECTS) $(LIB)
	$(CC) -MMD -MP $(TEST_OBJECTS) -o $@ $(TEST_CFLAGS) $(TEST_LIBS) -L. -lsec

tests/%.o: tests/%.c
	$(CC) -MMD -MP -c $< -o $@ $(TEST_CFLAGS) $(TEST_LIBS)

clean:
	$(RM) $(PROG) $(TEST_PROG) *.a *.o */*.o */*.d *.d
