OSSPEC = -m64
CC = gcc
INC = -I ../../include
DEFINES = -O1 $(OSSPEC) $(INC)
OBJDIR = ../../obj/

objs = hashInterface.o sha3.o
libobj = libhash.a

all:$(objs) $(libobj) final

%.o:%.cpp
	$(CC) $(DEFINES) -c $<
%.o:%.c
	$(CC) $(DEFINES) -c $<

$(libobj):$(objs)
	ar rv $(libobj) $(objs)
	
final:$(null)
	mv $(objs) $(OBJDIR)
	mv $(libobj) $(OBJDIR)






