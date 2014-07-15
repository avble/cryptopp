CC=gcc 
#CC=arm-unknown-linux-gnu-gcc 

CXX=g++ 
CXX=arm-unknown-linux-gnu-g++ 

LIBS=../../libcryptopp.a -lpthread -lrt

INCLUDE=-I../../

CFLAGS=-g $(INCLUDE) 
CXXFLAGS=-g $(INCLUDE) 


OBJS =  Driver.o
OBJS +=  TimeCounter.o

all: $(OBJS)
	$(CXX) -o crypto_cbc_test $(OBJS) $(LIBS)

clean:
	rm -rf $(OBJS) 
