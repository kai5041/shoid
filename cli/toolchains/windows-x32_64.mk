CXX := x86_64-w64-mingw32-g++
CXX_FLAGS := -std=c++17 -Wall -Wextra -Wpedantic -I./libs/sdl3/include/ -g
LD_FLAGS := -static -static-libgcc -static-libstdc++ -lpthread \
            -lwinmm -lole32 -loleaut32 -luuid \
            -luser32 -lgdi32 -limm32 -lcomdlg32 -lsetupapi -lversion