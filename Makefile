# Makefile for pam_password_fingerprint PAM module

# Automatically detect the PAM security directory
ifeq ($(shell [ -d /lib/x86_64-linux-gnu/security ] && echo yes),yes)
    PAM_DIR ?= /lib/x86_64-linux-gnu/security
else ifeq ($(shell [ -d /usr/lib/security ] && echo yes),yes)
    PAM_DIR ?= /usr/lib/security
else
    PAM_DIR ?= /lib/security
endif

DESTDIR ?=

.PHONY: all build clean install uninstall test

all: build

build:
	cargo build --release

clean:
	cargo clean

install: build
	install -d $(DESTDIR)$(PAM_DIR)
	install -m 755 target/release/libpam_password_fingerprint.so $(DESTDIR)$(PAM_DIR)/pam_password_fingerprint.so
	@echo "PAM module installed to $(DESTDIR)$(PAM_DIR)/pam_password_fingerprint.so"

uninstall:
	rm -f $(DESTDIR)$(PAM_DIR)/pam_password_fingerprint.so
	@echo "PAM module removed from $(DESTDIR)$(PAM_DIR)/pam_password_fingerprint.so"
