# Makefile for the C/SDL2 Network Monitor
#
# On Debian/Ubuntu, install dependencies with:
# sudo apt-get install libsdl2-dev libsdl2-ttf-dev libsdl2-mixer-dev
#
# To compile, run: make
# To run, execute: ./network_monitor_sdl

CC = gcc
# Use the 'sdl2-config' utility to get the correct compiler and linker flags.
# This makes the Makefile more portable.
CFLAGS = -Wall -Wextra -std=c99 -O2 $(shell sdl2-config --cflags)
# FIX: Added -lm to link the math library for the sin() function.
LDFLAGS = $(shell sdl2-config --libs) -lSDL2_ttf -lSDL2_mixer -lpthread -lm
TARGET = network_monitor_sdl

SRCS = main.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

