OSSPEC = -m64
CC = gcc
INC = -I ../../include -I ./
DEFINES = $(OSSPEC) $(INC)
OBJDIR = ../../obj/

objs = sm3.o smAPI.o

libobj = libsma.a


all:$(objs) $(libobj) final

%.o:%.cpp
		$(CC) $(DEFINES) -c $<

%.o:%.c
		$(CC) $(DEFINES) -c $<

$(libobj):
		ar rv $(libobj)	$(objs)

final:$(NULL)
		mv $(objs) $(OBJDIR)
		mv $(libobj) $(OBJDIR)





