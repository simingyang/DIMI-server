#include "payment_module.h"
#include <iostream>
#include <cassert>
#include <memory>

void test_rsa_signature() {
    std::cout << "Testing RSA Signature functionality...\n";
    
    KeyManager& km = KeyManager::instance();
    
    // 生成密钥对
    std::string private_key, public_key;
    bool success = km.generate_rsa_keypair(private_key, public_key);
    assert(success);
    std::cout << "Generated RSA keypair successfully\n";
    
    // 加载生成的密钥
    km.load_private_key(private_key);
    km.load_public_key(public_key);
    
    // 测试签名和验证
    std::string data = "Hello, this is a test message for RSA signing!";
    std::string signature = km.rsa_sign(data);
    std::cout << "Generated signature: " << signature.substr(0, 20) << "...\n";
    
    bool is_valid = km.rsa_verify(data, signature);
    assert(is_valid);
    std::cout << "Signature verification passed\n";
    
    // 测试验证失败的情况
    std::string tampered_data = "Hello, this is a tampered test message!";
    bool is_invalid = !km.rsa_verify(tampered_data, signature);
    assert(is_invalid);
    std::cout << "Tampered data verification failed as expected\n";
    
    std::cout << "RSA Signature tests passed!\n\n";
}

void test_input_validation() {
    std::cout << "Testing input validation...\n";
    
    // 测试金额验证
    assert(PaymentInterface::validate_amount(100.50));
    assert(!PaymentInterface::validate_amount(-10.0));
    assert(!PaymentInterface::validate_amount(0));
    std::cout << "Amount validation passed\n";
    
    // 测试订单ID验证
    assert(PaymentInterface::validate_order_id("ORDER123456"));
    assert(PaymentInterface::validate_order_id("order_123-test"));
    assert(!PaymentInterface::validate_order_id(""));  // 空字符串
    assert(!PaymentInterface::validate_order_id(std::string(65, 'A')));  // 超长
    assert(!PaymentInterface::validate_order_id("ORDER<123>"));  // 包含危险字符
    std::cout << "Order ID validation passed\n";
    
    // 测试描述验证
    assert(PaymentInterface::validate_description("Valid description"));
    assert(!PaymentInterface::validate_description(""));  // 空字符串
    assert(!PaymentInterface::validate_description(std::string(129, 'A')));  // 超长
    assert(!PaymentInterface::validate_description("Description with <script> tag"));  // 包含危险字符
    std::cout << "Description validation passed\n";
    
    std::cout << "Input validation tests passed!\n\n";
}

void test_logging() {
    std::cout << "Testing logging functionality...\n";
    
    auto logger = std::make_shared<ConsoleLogger>();
    logger->log(LogLevel::INFO, "This is an info message");
    logger->log(LogLevel::ERROR, "This is an error message");
    logger->log(LogLevel::WARNING, "This is a warning message");
    logger->log(LogLevel::DEBUG, "This is a debug message");
    
    std::cout << "Logging tests passed!\n\n";
}

void test_payment_with_security() {
    std::cout << "Testing payment with security features...\n";
    
    // 创建支付服务并配置日志
    PaymentService service;
    auto logger = std::make_shared<ConsoleLogger>();
    service.set_logger(logger);
    
    // 测试支付请求结构体
    PaymentRequest request;
    request.order_id = "ORDER123456";
    request.amount = 99.99;
    request.description = "Test payment";
    request.user_id = "USER123";
    request.payment_type = PaymentType::WECHAT;
    
    // 测试输入验证
    assert(PaymentInterface::validate_order_id(request.order_id));
    assert(PaymentInterface::validate_amount(request.amount));
    assert(PaymentInterface::validate_description(request.description));
    assert(PaymentInterface::validate_user_id(request.user_id));
    
    std::cout << "Payment security tests passed!\n\n";
}

int main() {
    std::cout << "Running security tests for payment module...\n\n";
    
    test_rsa_signature();
    test_input_validation();
    test_logging();
    test_payment_with_security();
    
    std::cout << "All security tests passed successfully!\n";
    
    return 0;
}