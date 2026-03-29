TARGET = krb5-hibp.so
KRB5_CFLAGS = $(shell krb5-config --cflags)
KRB5_LIBS   = $(shell krb5-config --libs)

CFLAGS  += -fPIC -I/usr/local/include $(KRB5_CFLAGS)
LDFLAGS += -shared -L/usr/local/lib -lhibp $(KRB5_LIBS)

$(TARGET): krb5-hibp.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

all: $(TARGET)

KRB5_PLUGIN_DIR ?= /usr/lib/`uname -m`-linux-gnu/krb5/plugins/pwqual

install: all
	install -d $(DESTDIR)$(KRB5_PLUGIN_DIR)
	install -m 0644 $(TARGET) $(DESTDIR)$(KRB5_PLUGIN_DIR)/

uninstall:
	rm -f $(DESTDIR)$(KRB5_PLUGIN_DIR)/$(TARGET)

clean:
	rm -f $(TARGET)
