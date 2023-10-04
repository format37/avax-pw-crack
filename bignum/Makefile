CFLAGS := -O2 -Wall -Wextra -Wvla -Wsign-conversion -pedantic -std=c99

APPNAME := program

ifeq ($(OS),Windows_NT)
  RM := del /Q  
  CC := gcc
  EXT := .exe  
endif

APP := $(APPNAME)$(EXT)

APP_OSSL := $(APPNAME)_ossl$(EXT)

all: $(APP) 

$(APP): program.c cgbn.h
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

$(APP_OSSL): program.c cgbn.h
	$(CC) $(CFLAGS) -DHAS_OSSL -o $@ $< -lcrypto

clean:
	$(RM) $(APP) $(APP_OSSL)