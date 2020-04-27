SOURCES_D = nscand.cc
SOURCES_C =  nscanctl.c
OBJS = $(SOURCES_C:.c=.o) $(SOURCES_D:.cc=.o)
DAEMON = nscand
CLIENT = nscanctl
RM = rm -f

CFLAGS = -Wall -largp

all:
	$(CC) $(SOURCES_C) $(CFLAGS) -o $(CLIENT) 
	$(CC) $(SOURCES_D) $(CFLAGS) -o $(DAEMON)

clean:
	$(RM) $(CLIENT) *.o
	$(RM) $(DAEMON) *.o
