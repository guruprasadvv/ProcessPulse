CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L

SRC     = src/collector.c src/procfs.c src/jsonl.c
HDR     = src/procfs.h src/jsonl.h
TARGET  = collector

BUILD   = build
HELPER  = $(BUILD)/sysc_helper
CTEST   = $(BUILD)/test_procfs

PYTHON  ?= python3

.PHONY: all test test-c test-py test-privileged helpers check clean

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC)

$(BUILD):
	mkdir -p $(BUILD)

# Static so it runs unchanged inside a busybox container (DIT-1).
$(HELPER): tests/helpers/sysc_helper.c | $(BUILD)
	$(CC) $(CFLAGS) -O1 -static -o $@ $<

helpers: $(HELPER)

$(CTEST): tests/c/test_procfs.c src/procfs.c src/jsonl.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) -g -fsanitize=address,undefined -o $@ tests/c/test_procfs.c src/procfs.c src/jsonl.c

test-c: $(CTEST)
	./$(CTEST)

# 'make test' builds everything, runs the C unit tests, then the unprivileged
# pytest suite. Privileged eBPF/Docker tests: run 'make test-privileged' as root.
test: $(TARGET) $(HELPER) test-c
	$(PYTHON) -m pytest tests/ -v -m "not privileged"

test-py: $(TARGET) $(HELPER)
	$(PYTHON) -m pytest tests/ -v -m "not privileged"

test-privileged: $(TARGET) $(HELPER)
	$(PYTHON) -m pytest tests/ -v -m "privileged"

# Extra static analysis; not part of the default build.
check:
	$(CC) $(CFLAGS) -Wformat=2 -Wconversion -Wshadow -Wcast-qual -O2 -fsyntax-only $(SRC)
	$(CC) $(CFLAGS) -fanalyzer -O1 -fsyntax-only $(SRC)

clean:
	rm -f $(TARGET)
	rm -rf $(BUILD)
