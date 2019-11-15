ARM_COMPILER_PRE=arm-linux-gnueabihf-
CC=gcc
CFLAGS=-Wall -Werror -I../util/inc
LDFLAGS=-L../util/out

ARM_TARGET=dth_config_server
ARM_OBJS=dth_config_server_arm.o
PC_TARGET=dth_config_client
PC_OBJS=dth_client.o
SHARE_DIR=../../share/
BIN_FILE=~/bin/dthc

arm:$(ARM_TARGET)
pc:$(PC_TARGET)
all:$(ARM_TARGET) $(PC_TARGET)

$(ARM_TARGET):$(ARM_OBJS)
	$(ARM_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ $^ -pthread $(LDFLAGS) -lutil_arm
	@cp $(ARM_TARGET) $(SHARE_DIR)
	@echo "cp $(ARM_TARGET) to share_dir"

$(ARM_OBJS):dth_config_server.c dth_config.h
	$(ARM_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ -c $<

$(PC_TARGET):$(PC_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lutil_x86
	@cp $(PC_TARGET) $(BIN_FILE)
	@echo "cp $(PC_TARGET) to bin_dir"

dth_client.o:dth_client.c dth_config.h

.PHONY:clean
clean:
	rm -rf $(ARM_TARGET) $(ARM_OBJS) $(PC_TARGET) $(PC_OBJS)
