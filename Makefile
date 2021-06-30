BUILDDIR := build
BINDIR := $(BUILDDIR)/bin
TARGET := $(BINDIR)/heapchecker
OBJECTS := $(patsubst %.c,$(BUILDDIR)/%.o,$(wildcard *.c))
TEST_OBJECTS := hashmap.o
TEST_OBJECTS := $(patsubst %.o,$(BUILDDIR)/%.o,$(TEST_OBJECTS))

CFLAGS :=
LDFLAGS :=

$(BUILDDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJECTS) | $(BINDIR)
	echo $(OBJECTS)
	echo $(BUILDDIR)
	$(CC) $(CFLAGS) -o $(BINDIR)/heapchecker $(OBJECTS) $(LDFLAGS)

.DEFAULT_GOAL := all
all: CFLAGS += -O3
all: $(TARGET)

debug: CFLAGS += -g -O0
debug: $(TARGET)

tests: CFLAGS += -g -O0 -I.
tests: $(TARGET) run_tests

run_tests:
	$(CC) $(CFLAGS) -o tests/test_main $(TEST_OBJECTS) tests/test_main.c -lcmocka
	tests/test_main

$(OBJECTS): | $(BUILDDIR)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

.PHONY: clean
clean:
	rm -rf build debug
