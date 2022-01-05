OPENRESTY_PREFIX ?= /usr/local/openresty
INSTALL ?= install

.PHONY: install

install:
	$(INSTALL) -d $(OPENRESTY_PREFIX)/lualib/resty/apisix/
	$(INSTALL) -m 664 lib/resty/apisix/*.lua $(OPENRESTY_PREFIX)/lualib/resty/apisix/
	$(INSTALL) -d $(OPENRESTY_PREFIX)/lualib/resty/apisix/stream
	$(INSTALL) -m 664 lib/resty/apisix/stream/*.lua $(OPENRESTY_PREFIX)/lualib/resty/apisix/stream
