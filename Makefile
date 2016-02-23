VERSION=1.0.1

compileparam = -O2 -g -pipe -Wall -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wparentheses -Wformat -Winline -Wreturn-type -fPIC -Wmissing-prototypes -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -maccumulate-outgoing-args -Wno-sign-compare -fno-asynchronous-unwind-tables -fomit-frame-pointer -Werror -D_FILE_OFFSET_BITS=64


all: library demo_program

install:
	cp netsum /usr/bin

library:
	cd ./lib && $(CC) -c -I ../include $(compileparam) *.c
	cd ./lib/protocols && $(CC) -c -I .. -I ../../include $(compileparam) *.c

	ar rcs ./libOpenDPI.a ./lib/*.o ./lib/protocols/*.o

demo_program: netsum.c library
	$(CC) $(compileparam) -I include netsum.c libOpenDPI.a -lpcap -o netsum -lncurses

clean:
	rm -rf *.a netsum libOpenDPI.a
	cd ./lib && rm -rf *.o
	cd ./lib/protocols && rm -rf *.o

dist:
	tar zcvf netsum-$(VERSION).tar.gz --transform 's,^,netsum-$(VERSION)/,' --exclude *.tar.gz *
