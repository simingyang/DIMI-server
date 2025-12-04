#include "payment_module.h"
#include <iostream>

int main() {
    // 创建支付服务实例
    PaymentService payment_service;
    
    // 配置微信支付（使用测试参数）
    payment_service.set_wechat_config(
        "your_wechat_app_id", 
        "your_wechat_mch_id", 
        "your_wechat_api_key"
    );
    
    // 配置支付宝支付（使用测试参数）
    payment_service.set_alipay_config(
        "your_alipay_app_id",
        "your_alipay_private_key",
        "your_alipay_public_key"
    );
    
    // 示例1: 创建微信支付请求
    std::cout << "=== 微信支付示例 ===" << std::endl;
    PaymentRequest wechat_request;
    wechat_request.order_id = "ORDER_001";
    wechat_request.amount = 99.99;
    wechat_request.description = "测试商品";
    wechat_request.user_id = "USER_001";
    wechat_request.payment_type = PaymentType::WECHAT;
    
    PaymentResponse wechat_response = payment_service.process_payment(wechat_request);
    
    std::cout << "微信支付结果: ";
    switch(wechat_response.result) {
        case PaymentResult::SUCCESS:
            std::cout << "成功" << std::endl;
            std::cout << "交易ID: " << wechat_response.transaction_id << std::endl;
            std::cout << "支付URL: " << wechat_response.payment_url << std::endl;
            break;
        case PaymentResult::FAILED:
            std::cout << "失败 - " << wechat_response.message << std::endl;
            break;
        case PaymentResult::PENDING:
            std::cout << "待处理 - " << wechat_response.message << std::endl;
            break;
        case PaymentResult::CANCELLED:
            std::cout << "已取消 - " << wechat_response.message << std::endl;
            break;
    }
    
    std::cout << std::endl;
    
    // 示例2: 创建支付宝支付请求
    std::cout << "=== 支付宝支付示例 ===" << std::endl;
    PaymentRequest alipay_request;
    alipay_request.order_id = "ORDER_002";
    alipay_request.amount = 199.99;
    alipay_request.description = "测试商品2";
    alipay_request.user_id = "USER_002";
    alipay_request.payment_type = PaymentType::ALIPAY;
    
    PaymentResponse alipay_response = payment_service.process_payment(alipay_request);
    
    std::cout << "支付宝支付结果: ";
    switch(alipay_response.result) {
        case PaymentResult::SUCCESS:
            std::cout << "成功" << std::endl;
            std::cout << "支付URL: " << alipay_response.payment_url << std::endl;
            break;
        case PaymentResult::FAILED:
            std::cout << "失败 - " << alipay_response.message << std::endl;
            break;
        case PaymentResult::PENDING:
            std::cout << "待处理 - " << alipay_response.message << std::endl;
            break;
        case PaymentResult::CANCELLED:
            std::cout << "已取消 - " << alipay_response.message << std::endl;
            break;
    }
    
    std::cout << std::endl;
    
    // 示例3: 查询支付状态
    std::cout << "=== 查询支付状态示例 ===" << std::endl;
    if(!wechat_response.transaction_id.empty()) {
        PaymentResponse status_response = payment_service.query_payment_status(
            wechat_response.transaction_id, PaymentType::WECHAT);
        
        std::cout << "支付状态: ";
        switch(status_response.result) {
            case PaymentResult::SUCCESS:
                std::cout << "支付成功" << std::endl;
                break;
            case PaymentResult::FAILED:
                std::cout << "支付失败 - " << status_response.message << std::endl;
                break;
            case PaymentResult::PENDING:
                std::cout << "支付中 - " << status_response.message << std::endl;
                break;
            case PaymentResult::CANCELLED:
                std::cout << "已取消 - " << status_response.message << std::endl;
                break;
        }
    }
    
    // 示例4: 退款操作
    std::cout << "\n=== 退款操作示例 ===" << std::endl;
    if(!wechat_response.transaction_id.empty()) {
        PaymentResponse refund_response = payment_service.refund_payment(
            wechat_response.transaction_id, 99.99, PaymentType::WECHAT);
        
        std::cout << "退款结果: ";
        switch(refund_response.result) {
            case PaymentResult::SUCCESS:
                std::cout << "退款成功" << std::endl;
                break;
            case PaymentResult::FAILED:
                std::cout << "退款失败 - " << refund_response.message << std::endl;
                break;
            default:
                std::cout << "退款状态未知 - " << refund_response.message << std::endl;
                break;
        }
    }
    
    std::cout << "\n支付模块示例执行完成" << std::endl;
    
    return 0;
}