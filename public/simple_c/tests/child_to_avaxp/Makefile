CFLAGS := -O2 -Wall -Wextra -Wvla -Wsign-conversion -pedantic -std=c99
APPNAME := child_to_avaxp

ifeq ($(OS),Windows_NT)
	RM := del /Q
	CC := gcc
	EXT := .exe
endif

APP := $(APPNAME)$(EXT)
APP_OSSL := $(APPNAME)_ossl$(EXT)

all: $(APP)

$(APP): child_to_avaxp.c pbkdf2_sha512.h
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

$(APP_OSSL): child_to_avaxp.c pbkdf2_sha512.h
	$(CC) $(CFLAGS) -DHAS_OSSL -o $@ $< -lcrypto

clean:
	$(RM) $(APP) $(APP_OSSL)
