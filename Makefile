TARGET_COMPILE ?= aarch64-none-elf-
KP_DIR         ?= ./KernelPatch
CC = $(TARGET_COMPILE)gcc
INCLUDE_DIRS := . include patch/include linux/include \
                linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir)) -I.
CFLAGS += -std=gnu11 -O2 -fno-builtin
SRCS += ./main.c
SRCS += ./trace.c
OBJS := $(SRCS:.c=.o)
all: kpm_trace_svc.kpm
kpm_trace_svc.kpm: ${OBJS}
	${CC} -r -o $@ $^
	find . -name "*.o" | xargs rm -f
%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<
.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
