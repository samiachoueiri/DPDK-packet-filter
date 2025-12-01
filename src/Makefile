# Makefile for DPDK-based fw_demo
# Assumes project headers live in ./include
# Usage:
#   make                       # builds fw_demo in build/
#   make run EAL_ARGS="..."    # runs via sudo (prompts if EAL_ARGS not set)
#   make clean
PROJECT_INC ?= ../include

# Source files
SRCS := main.c fw_ctx.c fw_inspect.c fw_packet.c fw_stats.c port_config.c

# Build directory
BUILD_DIR := build

# Target executable name
TARGET := fw_demo

# Object files (in build directory)
OBJS := $(addprefix $(BUILD_DIR)/, $(SRCS:.c=.o))

# Project include directory (default 'include' next to the .c files)
PROJECT_INC ?= /home/ubuntu/cyber_project/test/include

# Compiler and flags
CC := gcc
CFLAGS := -std=gnu11 -O2 -g -Wall -Wextra -fno-common 
# In your Makefile, add these compiler flags
CFLAGS += -march=native -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2
# Always add project include dir
PROJECT_INCLUDES := -I$(PROJECT_INC)

# Try pkg-config for libdpdk
PKGFLAGS := $(shell pkg-config --cflags --libs libdpdk 2>/dev/null || true)

ifeq ($(strip $(PKGFLAGS)),)
$(info pkg-config libdpdk not found; falling back to manual include/lib vars)
ifdef DPDK_INC
DPDK_INCLUDES := -I$(DPDK_INC)
else
DPDK_INCLUDES :=
endif
ifdef DPDK_LIB
LIBPATH := -L$(DPDK_LIB)
else
LIBPATH :=
endif

# Fallback DPDK libs (adjust if your DPDK packaging differs)
LDLIBS := -lrte_eal -lrte_mempool -lrte_ring -lrte_mbuf -lrte_ethdev -ldl -pthread -lm -lrt
INCLUDES := $(PROJECT_INCLUDES) $(DPDK_INCLUDES)
else
# pkg-config provides DPDK flags; still add project includes
INCLUDES := $(PROJECT_INCLUDES)
LIBPATH :=
LDLIBS := $(PKGFLAGS)
endif

LDFLAGS := $(LIBPATH)

.PHONY: all precheck clean run dirs

# Pre-check: ensure include directory exists and contains headers
all: dirs precheck $(BUILD_DIR)/$(TARGET)

# Create build directory
dirs:
	@mkdir -p $(BUILD_DIR)

precheck:
	@if [ ! -d "$(PROJECT_INC)" ]; then \
	  echo "ERROR: project include dir '$(PROJECT_INC)' not found."; \
	  exit 1; \
	fi
	@if ! ls $(PROJECT_INC)/*.h >/dev/null 2>&1; then \
	  echo "ERROR: no headers (*.h) found in '$(PROJECT_INC)'."; \
	  exit 1; \
	fi

# Link the executable
$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

# Compile .c files to .o files in build directory
# Pattern rule for building object files
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(RM) -r $(BUILD_DIR)

# convenience run target (requires EAL args)
run: $(BUILD_DIR)/$(TARGET)
	@echo "Running with sudo; ensure NICs bound and hugepages set up."
	@if [ -z "$(EAL_ARGS)" ]; then \
	  echo "ERROR: provide EAL_ARGS, e.g.: make run EAL_ARGS=\"-l 0-3 -n 4\" APP_ARGS=\"-- --block-port 80\""; exit 1; \
	fi
	sudo ./$(BUILD_DIR)/$(TARGET) $(EAL_ARGS) -- $(APP_ARGS)