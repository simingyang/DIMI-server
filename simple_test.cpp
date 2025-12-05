#include "payment_module.h"
#include <iostream>
#include <cassert>
#include <memory>

int main() {
    std::cout << "Testing basic security features...\n";
    
    // 测试输入验证
    std::cout << "Testing input validation...\n";
    assert(PaymentInterface::validate_amount(100.50));
    assert(!PaymentInterface::validate_amount(-10.0));
    assert(PaymentInterface::validate_order_id("ORDER123456"));
    assert(!PaymentInterface::validate_order_id(""));  // 空字符串
    std::cout << "Input validation passed!\n";
    
    // 测试日志
    std::cout << "Testing logging...\n";
    auto logger = std::make_shared<ConsoleLogger>();
    logger->log(LogLevel::INFO, "Test log message");
    std::cout << "Logging passed!\n";
    
    // 测试密钥管理器基本功能
    std::cout << "Testing KeyManager singleton...\n";
    KeyManager& km = KeyManager::instance();
    std::cout << "KeyManager singleton acquired\n";
    
    std::cout << "Basic security tests passed!\n";
    
    return 0;
}