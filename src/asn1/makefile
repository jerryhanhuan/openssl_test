OSSPEC = -m64
CC = gcc
INC = -I ./ -I ../../include
DEFINES = -O1 $(OSSPEC) $(INC)
OBJDIR = ../../obj/

objs = asn1.o Asn1Interface.o
libobj = libasn1.a

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
