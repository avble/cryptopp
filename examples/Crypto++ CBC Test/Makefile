CC=gcc 
#CC=arm-unknown-linux-gnu-gcc 

CXX=g++ 
#CXX=arm-unknown-linux-gnu-g++ 

LIBS=../../libcryptopp.a -lpthread

INCLUDE=-I../../

CFLAGS=-g $(INCLUDE) 
CXXFLAGS=-g $(INCLUDE) 

# for lighttpd configure 
CFLAGS += -DHAVE_SYSLOG_H


OBJS =  Driver.o

all: $(OBJS)
	$(CXX) -o crypto_cbc_test $(OBJS) $(LIBS)

clean:
	rm -rf $(OBJS) 
