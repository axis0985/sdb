all: main.c cli.o sdb.o elftool.o
	$(CC)  main.c cli.o sdb.o elftool.o -o sdb -lelf  -lcapstone

cli.o: cli.c cli.h
	$(CC) cli.c -c

sdb.o: sdb.c sdb.h
	$(CC) sdb.c -c

elftool.o: elftool.c elftool.h
	%(CC) elftool.c -c

.PHONY: clean
clean: 
	rm -f *.o
	rm -f sdb