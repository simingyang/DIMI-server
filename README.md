# C++ 微信和支付宝支付模块

这是一个可移植的C++支付模块，支持微信支付和支付宝支付功能。该模块具有以下特点：

- 良好的可移植性，支持跨平台编译
- 统一的支付接口，易于扩展
- 支持支付、查询、退款等基本功能
- 面向对象设计，代码结构清晰

## 功能特性

- **微信支付支持**：统一下单、订单查询、申请退款
- **支付宝支付支持**：网页支付、订单查询、申请退款
- **统一接口**：抽象支付接口，便于扩展新的支付方式
- **错误处理**：完善的异常处理机制
- **配置灵活**：支持动态配置支付参数

## 依赖库

- libcurl：HTTP请求处理
- OpenSSL：加密算法支持
- jsoncpp：JSON解析
- tinyxml2：XML解析（需要额外安装）

## 安装依赖

```bash
make install-deps
```

注意：如果需要XML解析功能，还需要安装tinyxml2库：

```bash
sudo apt-get install -y libtinyxml2-dev
```

## 编译

```bash
make all
```

或者直接运行：

```bash
make
```

## 使用示例

### 基本用法

```cpp
#include "payment_module.h"
#include <iostream>

int main() {
    // 创建支付服务实例
    PaymentService payment_service;
    
    // 配置微信支付
    payment_service.set_wechat_config(
        "your_wechat_app_id", 
        "your_wechat_mch_id", 
        "your_wechat_api_key"
    );
    
    // 配置支付宝支付
    payment_service.set_alipay_config(
        "your_alipay_app_id",
        "your_alipay_private_key",
        "your_alipay_public_key"
    );
    
    // 创建支付请求
    PaymentRequest request;
    request.order_id = "ORDER_001";
    request.amount = 99.99;
    request.description = "测试商品";
    request.user_id = "USER_001";
    request.payment_type = PaymentType::WECHAT;  // 或 PaymentType::ALIPAY
    
    // 处理支付
    PaymentResponse response = payment_service.process_payment(request);
    
    if(response.result == PaymentResult::SUCCESS) {
        std::cout << "支付请求成功" << std::endl;
        std::cout << "支付URL: " << response.payment_url << std::endl;
    } else {
        std::cout << "支付请求失败: " << response.message << std::endl;
    }
    
    return 0;
}
```

### 查询支付状态

```cpp
PaymentResponse status_response = payment_service.query_payment_status(
    "transaction_id", PaymentType::WECHAT);
```

### 申请退款

```cpp
PaymentResponse refund_response = payment_service.refund_payment(
    "transaction_id", 99.99, PaymentType::WECHAT);
```

## 代码结构

- `payment_module.h`：头文件，包含接口定义
- `payment_module.cpp`：实现文件，包含具体实现
- `example.cpp`：使用示例
- `Makefile`：编译脚本

## 设计模式

- **抽象工厂模式**：用于创建不同类型的支付处理器
- **策略模式**：不同的支付方式实现统一接口
- **单一职责原则**：每个类只负责特定功能

## 安全注意事项

1. **密钥管理**：生产环境中不要硬编码API密钥
2. **SSL验证**：示例中为演示禁用了SSL验证，生产环境应启用
3. **输入验证**：在实际使用中应添加参数验证
4. **日志记录**：建议添加详细的日志记录功能

## 扩展性

该模块设计具有良好的扩展性，可以轻松添加新的支付方式：

1. 继承 `PaymentInterface` 接口
2. 实现相应的支付方法
3. 在 `PaymentFactory` 中添加创建逻辑

## 注意事项

1. 本代码为示例代码，实际部署前需要：
   - 完善错误处理
   - 添加安全验证
   - 实现完整的签名算法
   - 添加日志记录
   - 进行充分测试

2. 微信支付和支付宝支付的完整实现需要：
   - 正确的证书和密钥
   - 有效的商户账户
   - 合规的业务资质

## 许可证

本项目仅供学习参考使用。