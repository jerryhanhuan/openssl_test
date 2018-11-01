OSSPEC = -m64
CC = gcc
INC = -I ./ -I ../../include
DEFINES = -O1 $(OSSPEC) $(INC)
OBJDIR = ../../obj/


objs = rsa.o rsaInterface.o
libobj = librsa.a

all:$(objs) $(libobj) final

%.o:%.c
	$(CC) $(DEFINES) -c $<
%.o:%.cpp
	$(CC) $(DEFINES) -c $<

$(libobj):$(objs)
	ar rv $(libobj) $(objs)

final:$(null)
	mv $(objs) $(OBJDIR)
	mv $(libobj) $(OBJDIR)