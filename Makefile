CC = gcc
CFLAGS_COMMON = -std=c11 -D_POSIX_C_SOURCE=200809L
CFLAGS_DEBUG = -g -Wall -Wextra -fsanitize=address -DDEBUG
CFLAGS_RELEASE = -O3 -DNDEBUG
LDFLAGS_DEBUG = -fsanitize=address -pthread
LDFLAGS_RELEASE = -pthread

CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_DEBUG)
LDFLAGS = $(LDFLAGS_DEBUG)

# Directories
SRC_DIR = src
OBJ_DIR = obj
LIB_DIR = $(SRC_DIR)/lib
PARSERS_DIR = $(SRC_DIR)/parsers
SOCKS5_DIR = $(SRC_DIR)/socks5

# Include paths
INCLUDES = -I$(SRC_DIR) -I$(LIB_DIR) -I$(PARSERS_DIR) -I$(SOCKS5_DIR)

# Source files
SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/args.c \
       $(LIB_DIR)/buffer.c \
       $(LIB_DIR)/netutils.c \
       $(LIB_DIR)/selector.c \
       $(LIB_DIR)/stm.c \
       $(PARSERS_DIR)/parser.c \
       $(PARSERS_DIR)/parser_utils.c \
       $(PARSERS_DIR)/hello_parser.c \
       $(PARSERS_DIR)/request_parser.c \
       $(SOCKS5_DIR)/socks5nio.c

# Object files
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Target
TARGET = socks5d

.PHONY: all clean release

all: $(TARGET)

release: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_RELEASE)
release: LDFLAGS = $(LDFLAGS_RELEASE)
release: clean all

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -rf $(OBJ_DIR) $(TARGET)
