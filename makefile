LDLIBS=-lpcap

all: airodump

mac.o : mac.h mac.cpp

main.o : mac.h main.cpp

airodump: mac.o main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o