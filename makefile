# Makefile لبناء UniversalHook.dylib
CC = clang++
TARGET = UniversalHook.dylib
SOURCES = UniversalHook.mm
FRAMEWORKS = -framework Foundation -framework CoreFoundation -framework AppKit
INCLUDES = -I./Dobby/include -I./fishhook
LIB_PATHS = -L./Dobby/build
LIBS = -ldobby

CFLAGS = -dynamiclib -std=c++17 -O2 -Wall $(INCLUDES)
LDFLAGS = $(LIB_PATHS) $(LIBS) $(FRAMEWORKS)

all: $(TARGET)

$(TARGET): $(SOURCES) libdobby.a fishhook.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libdobby.a:
	@if [ ! -f "Dobby/build/libdobby.a" ]; then \
		echo "🔨 Building Dobby..."; \
		cd Dobby && mkdir -p build && cd build && \
		cmake .. -DDOBBY_GENERATE_SHARED=OFF -DCMAKE_BUILD_TYPE=Release && \
		make -j$$(sysctl -n hw.ncpu); \
	else \
		echo "✅ Dobby already built."; \
	fi

fishhook.h:
	@if [ ! -d "fishhook" ]; then \
		echo "📥 Cloning fishhook..."; \
		git clone https://github.com/facebook/fishhook.git; \
	fi
	@cp fishhook/fishhook.h .

clean:
	rm -f $(TARGET) fishhook.h
	rm -rf Dobby/build

.PHONY: all clean
