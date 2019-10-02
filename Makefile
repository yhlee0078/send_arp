all : send_arp

send_arp: main.o
	g++ -w -o send_arp main.o -lpcap
main.o:
	g++ -w -c -o main.o main.cpp
clean:
	rm -f send_arp
	rm -f *.o

