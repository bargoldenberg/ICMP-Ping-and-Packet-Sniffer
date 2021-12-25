all:  MyPing Sniffer
MyPing: MyPing.c
	gcc MyPing.c -o MyPing
Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer -lpcap
.PHONY: clean#.PHONY means that clean is not a file.
clean:
	rm -f MyPing Sniffer