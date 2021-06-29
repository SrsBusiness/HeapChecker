BUILDDIR := build
BINDIR := build/bin
OBJECTS := $(patsubst %.c,$(BUILDDIR)/%.o,$(wildcard *.c))

$(BUILDDIR)/%.o: %.c
	cc -c -o $@ $<

all: $(OBJECTS) | $(BINDIR)
	echo $(OBJECTS)
	cc -o $(BINDIR)/heapchecker $(OBJECTS)

$(OBJECTS): | $(BUILDDIR)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)


