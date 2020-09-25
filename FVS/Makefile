INCDIR   := inc 
SRCDIR   := src

CC=gcc

HEADER = -I./inc -I./inc/miracl
CFLAGS= -march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv
SOURCE =  ./src/FVS_BLS12381.c 

ALL:
	
	$(CC) $(CFLAGS) -c ./src/FVS_BLS12381.c $(HEADER)	
	$(CC) $(CFLAGS) *.o FVStest.c core.a -o FVStest $(HEADER)
	rm *.o
	
	
clean:
	rm main
