all: objs\
        libutil\
        final

OSSPEC = -m64
CC = gcc
INC = -I ../../include
DEFINES = -O1 $(OSSPEC) $(INC)
OBJDIR = ../../obj/


objs:openssl_init.o str.o

.SUFFIXES:.c.o
.c.o:
	$(CC) $(DEFINES) -c $*.c

.SUFFIXES:.cpp.o
.cpp.o:
	$(CC) $(DEFINES) -c $*.cpp

utilobj = openssl_init.o str.o

libutil:$(utilobj)
	ar rv libutil.a $(utilobj)

final:$(null)
	mv *.o $(OBJDIR)
	mv libutil.a $(OBJDIR)






