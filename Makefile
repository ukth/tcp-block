all: tcp-block

tcp-block: main.cpp main.h
	gcc -o tcp-block main.cpp -lpcap -std=c++0x

clean:
	rm -f tcp-block *.o

