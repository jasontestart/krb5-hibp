TARGET = hibp-checker
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
LDFLAGS += -L/usr/local/lib -lhibp -lconfuse
CFLAGS  += -I/usr/local/include
TARGET = hibp-checker

$(TARGET): hibp-checker.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

all: $(TARGET)

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)

