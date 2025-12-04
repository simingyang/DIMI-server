# 支付模块 Makefile
CXX = g++
CXXFLAGS = -std=c++14 -Wall -Wextra -O2
TARGET = payment_example
SOURCES = payment_module.cpp example.cpp
OBJECTS = $(SOURCES:.cpp=.o)
LIBS = -lcurl -lssl -lcrypto -ljsoncpp -ltinyxml2
INCLUDES = 

# 默认目标
all: $(TARGET)

# 链接目标
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LIBS)

# 编译源文件
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# 显式规则
payment_module.o: payment_module.cpp payment_module.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c payment_module.cpp -o payment_module.o

example.o: example.cpp payment_module.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c example.cpp -o example.o

# 清理
clean:
	rm -f $(OBJECTS) $(TARGET)

# 重新构建
rebuild: clean all

# 安装依赖（如果系统没有安装）
install-deps:
	sudo apt-get update
	sudo apt-get install -y libcurl4-openssl-dev libssl-dev libjsoncpp-dev

.PHONY: all clean rebuild install-deps