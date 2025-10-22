PROJECT_NAME := shoid
SRC_DIR := src
INCLUDE_DIR := include
BUILD_DIR := build

SRC := $(shell find $(SRC_DIR) -type f -name '*.cpp')
INCLUDE := $(shell find $(INCLUDE_DIR) -type f -name '*.hpp')

CXX ?= g++
CXX_FLAGS := -std=c++20 -Wall -fPIC -I$(INCLUDE_DIR)
LD_FLAGS := -lpthread -lcrypto

LINUX_BUILD_DIR := $(BUILD_DIR)/linux
WIN_BUILD_DIR   := $(BUILD_DIR)/win

LINUX_OBJ := $(patsubst $(SRC_DIR)/%.cpp,$(LINUX_BUILD_DIR)/%.o,$(SRC))
WIN_OBJ   := $(patsubst $(SRC_DIR)/%.cpp,$(WIN_BUILD_DIR)/%.o,$(SRC))

# Linux build
# ----------------------------------------
$(LINUX_BUILD_DIR)/$(PROJECT_NAME): $(LINUX_OBJ) | $(LINUX_BUILD_DIR) $(INCLUDE)
	$(CXX) -o $@ $^ $(LD_FLAGS)

$(LINUX_BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(INCLUDE) $(LINUX_BUILD_DIR)
	@ mkdir -p $(dir $@)
	$(CXX) $(CXX_FLAGS) -c $< -o $@

$(LINUX_BUILD_DIR):
	mkdir -p $@

linux: $(LINUX_BUILD_DIR)/$(PROJECT_NAME)
	@echo "Linux build complete: $<"

# Windows build
# ----------------------------------------
$(WIN_BUILD_DIR)/$(PROJECT_NAME).exe: $(WIN_OBJ) | $(WIN_BUILD_DIR) $(INCLUDE)
	x86_64-w64-mingw32-g++ -o $@ $^ -static -static-libgcc -static-libstdc++ -lpthread

$(WIN_BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(INCLUDE) $(WIN_BUILD_DIR)
	@ mkdir -p $(dir $@)
	x86_64-w64-mingw32-g++ $(CXX_FLAGS) -c $< -o $@

$(WIN_BUILD_DIR):
	mkdir -p $@

win: $(WIN_BUILD_DIR)/$(PROJECT_NAME).exe
	@echo "Windows build complete: $<"

# Phony
# ----------------------------------------
clean:
	rm -rf $(BUILD_DIR)

install_linux:
	cp $(LINUX_BUILD_DIR)/$(PROJECT_NAME) /usr/local/bin/$(PROJECT_NAME)

.PHONY: linux win clean install_linux
