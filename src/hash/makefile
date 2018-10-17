all: objs\
        libhash\
        final

OSSPEC = -m64
CC = gcc
INC = -I ../../include
DEFINES = -O1 $(OSSPEC) $(INC)
OBJDIR = ../../obj/


objs:hashInterface.o

.SUFFIXES:.c.o
.c.o:
	$(CC) $(DEFINES) -c $*.c

.SUFFIXES:.cpp.o
.cpp.o:
	$(CC) $(DEFINES) -c $*.cpp

hashobj = hashInterface.o

libhash:$(hashobj)
	ar rv libhash.a $(hashobj)

final:$(null)
	mv *.o $(OBJDIR)
	mv libhash.a $(OBJDIR)






