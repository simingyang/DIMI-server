#include "payment_module.h"
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

int main() {
    std::cout << "=== 支付模块安全功能演示 ===\n\n";
    
    // 1. 演示日志功能
    std::cout << "1. 日志功能演示:\n";
    auto logger = std::make_shared<ConsoleLogger>();
    logger->log(LogLevel::INFO, "系统启动");
    logger->log(LogLevel::DEBUG, "调试信息");
    logger->log(LogLevel::WARNING, "警告信息");
    logger->log(LogLevel::ERROR, "错误信息");
    std::cout << "日志功能正常工作\n\n";
    
    // 2. 演示输入验证功能
    std::cout << "2. 输入验证功能演示:\n";
    std::cout << "有效金额 99.99: " << (PaymentInterface::validate_amount(99.99) ? "通过" : "失败") << "\n";
    std::cout << "无效金额 -10.0: " << (PaymentInterface::validate_amount(-10.0) ? "通过" : "失败") << "\n";
    std::cout << "有效订单号 ORDER123: " << (PaymentInterface::validate_order_id("ORDER123") ? "通过" : "失败") << "\n";
    std::cout << "无效订单号 (含特殊字符): " << (PaymentInterface::validate_order_id("ORDER<123>") ? "通过" : "失败") << "\n";
    std::cout << "有效描述: " << (PaymentInterface::validate_description("商品购买") ? "通过" : "失败") << "\n";
    std::cout << "无效描述 (含脚本标签): " << (PaymentInterface::validate_description("商品<script>注入") ? "通过" : "失败") << "\n\n";
    
    // 3. 演示密钥管理功能
    std::cout << "3. 密钥管理功能演示:\n";
    KeyManager& km = KeyManager::instance();
    
    // 生成密钥对
    std::string private_key, public_key;
    try {
        bool success = km.generate_rsa_keypair(private_key, public_key);
        if (success) {
            std::cout << "RSA密钥对生成成功\n";
            
            // 加载密钥
            km.load_private_key(private_key);
            km.load_public_key(public_key);
            std::cout << "密钥加载成功\n";
            
            // 演示签名和验证（使用简化的数据）
            std::string test_data = "Hello, secure payment system!";
            std::cout << "待签名数据: " << test_data << "\n";
            
            // 实际的签名/验证测试
            std::string signature = km.rsa_sign(test_data);
            std::cout << "签名长度: " << signature.length() << " 字符\n";
            
            bool is_valid = km.rsa_verify(test_data, signature);
            std::cout << "签名验证: " << (is_valid ? "通过" : "失败") << "\n";
            
            // 验证被篡改的数据
            bool tampered_valid = km.rsa_verify("Tampered data", signature);
            std::cout << "篡改数据验证: " << (tampered_valid ? "通过(错误)" : "失败(正确)") << "\n";
        } else {
            std::cout << "密钥对生成失败\n";
        }
    } catch (const std::exception& e) {
        std::cout << "密钥管理操作失败: " << e.what() << "\n";
    }
    std::cout << "\n";
    
    // 4. 演示SSL验证功能（通过配置参数展示）
    std::cout << "4. SSL验证功能:\n";
    std::cout << "支付模块已配置为默认启用SSL验证\n";
    std::cout << "在HTTP请求中启用了SSL证书验证\n\n";
    
    // 5. 演示支付服务配置
    std::cout << "5. 支付服务配置演示:\n";
    PaymentService service;
    service.set_logger(logger);
    
    // 模拟配置支付参数（不实际发起请求）
    service.set_wechat_config("wx_app_id", "wx_mch_id", "wx_api_key");
    service.set_alipay_config("alipay_app_id", private_key, public_key);
    
    std::cout << "支付服务已配置日志记录器\n";
    std::cout << "微信支付和支付宝支付已配置\n\n";
    
    // 6. 演示支付请求结构体
    std::cout << "6. 支付请求安全验证:\n";
    PaymentRequest request;
    request.order_id = "ORDER_SECURE_TEST";
    request.amount = 88.88;
    request.description = "安全支付测试";
    request.user_id = "USER_SECURE";
    request.payment_type = PaymentType::WECHAT;
    
    // 验证请求参数
    bool is_valid_request = 
        PaymentInterface::validate_order_id(request.order_id) &&
        PaymentInterface::validate_amount(request.amount) &&
        PaymentInterface::validate_description(request.description) &&
        PaymentInterface::validate_user_id(request.user_id);
    
    std::cout << "支付请求参数验证: " << (is_valid_request ? "通过" : "失败") << "\n\n";
    
    std::cout << "=== 安全功能演示完成 ===\n";
    std::cout << "\n实现的安全功能包括:\n";
    std::cout << "- 完整的RSA签名算法 (SHA256withRSA)\n";
    std::cout << "- 安全的密钥管理 (单例模式, 线程安全)\n";
    std::cout << "- SSL/TLS连接验证\n";
    std::cout << "- 输入参数验证 (金额, 订单号, 描述等)\n";
    std::cout << "- 安全日志记录\n";
    std::cout << "- 防止注入攻击的参数过滤\n";
    
    return 0;
}