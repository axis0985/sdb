all: main.c cli.o sdb.o
	$(CC)  main.c cli.o sdb.o -o sdb -lelf 

cli.o: cli.c cli.h
	$(CC) cli.c -c

sdb.o: sdb.c sdb.h
	$(CC) sdb.c -c

.PHONY: clean
clean: 
	rm -f *.o
	rm -f sdb