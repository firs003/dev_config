ARM_COMPILER_PRE=arm-linux-gnueabihf-
MIPS_COMPILER_PRE=mipsel-openwrt-linux-
CC=gcc
CFLAGS=-Wall -Werror -I../util/inc
LDFLAGS=-L../util/out
STRIP=strip

ARM_TARGET=dth_config_server.arm
ARM_OBJS=dth_config_server_arm.o
MIPS_TARGET=dth_config_server.mips
MIPS_OBJS=dth_config_server_mips.o
PC_TARGET=dth_config_client
PC_OBJS=dth_client.o
SHARE_DIR=../../share/
BIN_FILE=~/bin/dthc

all:$(ARM_TARGET) $(MIPS_TARGET) $(PC_TARGET)
arm:$(ARM_TARGET)
mips:$(MIPS_TARGET)
pc:$(PC_TARGET)

$(ARM_TARGET):$(ARM_OBJS)
	$(ARM_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ $^ -pthread $(LDFLAGS) -lutil_arm
	$(ARM_COMPILER_PRE)$(STRIP) $@
	@cp $(ARM_TARGET) $(SHARE_DIR)
	@echo "cp $(ARM_TARGET) to share_dir"

$(ARM_OBJS):dth_config_server.c dth_config.h
	$(ARM_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ -c $<

$(MIPS_TARGET):$(MIPS_OBJS)
	$(MIPS_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ $^ -pthread $(LDFLAGS) -lutil_mips
	$(MIPS_COMPILER_PRE)$(STRIP) $@
	@cp $(MIPS_TARGET) $(SHARE_DIR)
	@echo "cp $(MIPS_TARGET) to share_dir"

$(MIPS_OBJS):dth_config_server.c dth_config.h
	$(MIPS_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ -c $<

$(PC_TARGET):$(PC_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lutil_x86
	@cp $(PC_TARGET) $(BIN_FILE)
	@echo "cp $(PC_TARGET) to bin_dir"

dth_client.o:dth_client.c dth_config.h

.PHONY:clean
clean:
	rm -rf $(ARM_TARGET) $(ARM_OBJS) $(PC_TARGET) $(PC_OBJS)
