CC      = gcc
CFLAGS  = -Wall -O2

FILTER_SRC  = vpfilter.c
FILTER_BIN  = vpfilter
FILTER_DEST = /usr/lib/cups/filter/vpfilter

.PHONY: all install uninstall clean

all: $(FILTER_BIN)

$(FILTER_BIN): $(FILTER_SRC)
	$(CC) $(CFLAGS) -o $@ $<

install: $(FILTER_BIN)
	@echo "[*] Installing vpfilter..."
	cp $(FILTER_BIN) $(FILTER_DEST)
	chown root:root $(FILTER_DEST)
	chmod 755 $(FILTER_DEST)
	@echo "[*] Restarting CUPS..."
	systemctl restart cups
	@echo "[✓] Done. Filter installed at $(FILTER_DEST)"

uninstall:
	rm -f $(FILTER_DEST)
	systemctl restart cups
	@echo "[✓] Uninstalled"

clean:
	rm -f $(FILTER_BIN)
