all : send_arp

send_arp: main.o printarr.o protocol_check.o swap_endian.o 
	g++ -g -o send_arp main.o printarr.o protocol_check.o swap_endian.o -lpcap

swap_endian.o:
	g++ -g -c -o swap_endian.o swap_endian.cpp

protocol_check.o:
	g++ -g -c -o protocol_check.o protocol_check.cpp

printarr.o:
	g++ -g -c -o printarr.o printarr.cpp

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f send_arp
	rm -f *.o

