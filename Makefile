#
#  Simple portscanner
#  Copyright (C) 2014  Aliaksandr Krukau
#
CC=g++
CPFLAGS=-g -Wall
LDFLAGS= -lpcap


SRC=portScanner.cpp 
OBJ=$(SRC:.cpp=.o)
BIN=portScanner

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

%.o:%.cpp
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf *.o $(BIN)
