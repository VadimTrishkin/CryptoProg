CXX = g++
CXXFLAGS = -Wall -std=c++17 -I/usr/include/cryptopp
LDFLAGS = -lcryptopp

TARGET = hasher
SOURCES = hasher.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

