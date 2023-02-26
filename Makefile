CC=g++
CFLAGS=-Wall -c

INC_DIR=./inc
SRC_DIR=./src
BLD_DIR=./build

EXE=PE-Extract

all: $(BLD_DIR)/main.o $(BLD_DIR)/HeaderExtract.o $(BLD_DIR)/BinManip.o
	$(CC) $^ -o $(BLD_DIR)/$(EXE)


$(BLD_DIR)/main.o: $(SRC_DIR)/main.cpp
	$(CC) $(CFLAGS) $< -o $@ -I$(INC_DIR)

$(BLD_DIR)/HeaderExtract.o: $(SRC_DIR)/HeaderExtract.cpp $(INC_DIR)/HeaderExtract.hpp $(INC_DIR)/BinManip.hpp
	$(CC) $(CFLAGS) $< -o $@ -I$(INC_DIR)

$(BLD_DIR)/BinManip.o: $(SRC_DIR)/BinManip.cpp $(INC_DIR)/BinManip.hpp
	$(CC) $(CFLAGS) $< -o $@ -I$(INC_DIR)


.PHONY: run
run:
	$(BLD_DIR)/$(EXE)

.PHONY: clean
clean:
	rm -rf $(BLD_DIR)/*.o
	rm -rf $(BLD_DIR)/$(EXE)
	rm -rf $(INC_DIR)/*.gch
