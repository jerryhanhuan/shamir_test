OSSPEC = -m64
CC = gcc
INC = -I ./
DEFINES = $(OSSPEC) $(INC)
LIB = -lm

objs = shamir.o test.o
product = shamir_test

all:$(objs) $(product)

%.o:%.cpp
	$(CC) $(DEFINES) -c $<
%.o:%.c
	$(CC) $(DEFINES) -c $<

$(product):$(objs)
	$(CC) $(DEFINES) -o $(product) $(objs) $(LIB)

.PHONY:clean

clean:
	rm -rf *.o
	rm -rf $(product)





