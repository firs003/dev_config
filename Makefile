CROSS_COMPILER_PRE=arm-linux-gnueabihf-
CC=gcc
CFLAGS=-Wall -Werror
LDFLAGS=-pthread

ARM_TARGET=dth_config_server
ARM_OBJS=dth_config_server.o
PC_TARGET=dth_config_client
PC_OBJS=dth_client.o
SHARE_DIR=../../share/
BIN_FILE=~/bin/dthc

arm:$(ARM_TARGET)
pc:$(PC_TARGET)
all:$(ARM_TARGET) $(PC_TARGET)

$(ARM_TARGET):$(ARM_OBJS)
	$(CROSS_COMPILER_PRE)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@cp $(ARM_TARGET) $(SHARE_DIR)
	@echo "cp $(ARM_TARGET) to share_dir"

dth_config_server.o:dth_config_server.c dth_config.h
	$(CROSS_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ -c $<

$(PC_TARGET):$(PC_OBJS)
	$(CC) $(CFLAGS) -o $@ $^
	@cp $(PC_TARGET) $(BIN_FILE)
	@echo "cp $(PC_TARGET) to bin_dir"

dth_client.o:dth_client.c dth_config.h

.PHONY:clean
clean:
	rm -rf $(ARM_TARGET) $(ARM_OBJS) $(PC_TARGET) $(PC_OBJS)