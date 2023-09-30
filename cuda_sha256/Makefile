CFLAGS := -O2 -Wall -Wextra -Wvla -Wsign-conversion -pedantic -std=c99
APPNAME := sha256

ifeq ($(OS),Windows_NT)
	RM := del /Q
	CC := gcc
	EXT := .exe
endif

APP := $(APPNAME)$(EXT)
APP_OSSL := $(APPNAME)_ossl$(EXT)

all: $(APP)

$(APP): sha256.c pbkdf2_sha256.h
	$(CC) $(CFLAGS) -o $@ $<

$(APP_OSSL): sha256.c pbkdf2_sha256.h
	$(CC) $(CFLAGS) -DHAS_OSSL -o $@ $< -lcrypto

clean:
	$(RM) $(APP) $(APP_OSSL)
