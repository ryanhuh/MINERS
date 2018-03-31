
CC = gcc
LD = ld
CFLAGS = -O2 -Wall -Werror -fomit-frame-pointer -I/compat/jansson -I../../libblkmaker
LDFLAGS = -lpthread -lcurl -ljansson -lbase58 -lblkmaker-0.1 -L../../libblkmaker/lib -lblkmaker-0.1.8 
TARGET = Cpuminer
OBJS = $(patsubst %.c , %.o, $(wildcard *.c))


all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) --save-temps -o $@ $<

clean :
	rm -rf *.o $(TARGET)

echo :
	@echo $(OBJS)	
