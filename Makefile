CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L

SRC     = src/collector.c
TARGET  = collector

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

# 'make test' builds the binary first, then runs the full pytest suite.
test: $(TARGET)
	python3 -m pytest tests/ -v

clean:
	rm -f $(TARGET)
