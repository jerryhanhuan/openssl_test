OSSPEC = -m64
CC = gcc
INC = -I ../../include
DEFINES = -O1 $(OSSPEC) $(INC)
OBJDIR = ../../obj/

objs = hashInterface.o
libobj = libhash.a

all:$(objs) $(libobj) final

%.o:%.cpp
	$(CC) $(DEFINES) -c $<
%.o:%.c
	$(CC) $(DEFINES) -c $<

$(libobj):
	ar rv $(libobj) $(objs)
	
final:$(null)
	mv *.o $(OBJDIR)
	mv $(libobj) $(OBJDIR)






