
CC = gcc
CFLAGS = -O1 -m64
INC = -I ../include
DEFINES = $(CFLAGS) $(INC)
LIBDIR = ../lib/
OBJDIR = ../obj/

arlib = $(OBJDIR)libhash.a\
		$(OBJDIR)libsma.a\
                $(OBJDIR)libasn1.a\
                $(OBJDIR)librsa.a\
				$(OBJDIR)libdes.a\
                $(OBJDIR)libutil.a

LIB =  $(arlib) -L $(LIBDIR) -lcrypto

test1_obj = test.o
test1 = test

all:$(test1) final

%.o:%.cpp
	$(CC) $(DEFINES) -c $<
%.o:%.c
	$(CC) $(DEFINES) -c $<

$(test1):$(test1_obj)
	$(CC) $(DEFINES) -o $(test1) $(test1_obj)  $(LIB)

final:$(null)
	rm -rf *.o








