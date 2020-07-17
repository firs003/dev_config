ARM_COMPILER_PRE=arm-linux-gnueabihf-
# ARM_COMPILER_PRE=arm-linux-gnueabi-
MIPS_COMPILER_PRE=mipsel-openwrt-linux-
X86_COMPILER_PRE=
CC=gcc
CFLAGS=-Wall -I./inc
LDFLAGS=-L.
STRIP=strip

ARM_TARGET=dth_config_server.arm
ARM_OBJS=dth_config_server_arm.o
ARM_CLIENT=dth_client.arm
ARM_CLIENT_OBJS=dth_client_arm.o
MIPS_TARGET=dth_config_server.mips
MIPS_OBJS=dth_config_server_mips.o
PC_TARGET=dth_config_client
PC_OBJS=dth_client.o

SHARE_DIR=../../share/
BIN_FILE=~/bin/dthc

all:pc arm mips
arm:$(ARM_TARGET) $(ARM_CLIENT)
mips:$(MIPS_TARGET)
pc:$(PC_TARGET)

$(ARM_TARGET):$(ARM_OBJS)
	$(ARM_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ $^ -pthread $(LDFLAGS) -lutil_arm
	$(ARM_COMPILER_PRE)$(STRIP) $@
	@cp $@ $(SHARE_DIR)/dth_config_server
	@echo "cp $@ to share_dir"

$(ARM_OBJS):dth_config_server.c inc/dth_config.h
	$(ARM_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ -c $<

$(ARM_CLIENT):$(ARM_CLIENT_OBJS)
	$(ARM_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lutil_arm
	$(ARM_COMPILER_PRE)$(STRIP) $@
	@cp $@ $(SHARE_DIR)
	@echo "cp $@ to share_dir"

$(ARM_CLIENT_OBJS):dth_client.c inc/dth_config.h
	$(ARM_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ -c $<

$(MIPS_TARGET):$(MIPS_OBJS)
	$(MIPS_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ $^ -pthread $(LDFLAGS) -lutil_mips
	$(MIPS_COMPILER_PRE)$(STRIP) $@
	@cp $@ $(SHARE_DIR)
	@echo "cp $@ to share_dir"

$(MIPS_OBJS):dth_config_server.c inc/dth_config.h
	$(MIPS_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ -c $<

$(PC_TARGET):$(PC_OBJS)
	$(X86_COMPILER_PRE)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lutil_x86
	@cp $@ $(BIN_FILE)
	@echo "cp $@ to bin_dir"

dth_client.o:dth_client.c inc/dth_config.h

.PHONY:clean
clean:
	rm -rf $(ARM_TARGET) $(ARM_OBJS) $(ARM_CLIENT) $(ARM_CLIENT_OBJS) $(MIPS_TARGET) $(MIPS_OBJS) $(PC_TARGET) $(PC_OBJS)
