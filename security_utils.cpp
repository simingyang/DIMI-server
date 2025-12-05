#include "security_utils.h"
#include <iostream>
#include <regex>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>

// 控制台日志实现
void ConsoleLogger::log(LogLevel level, const std::string& message) {
    std::string level_str;
    switch(level) {
        case LogLevel::DEBUG:   level_str = "[DEBUG]"; break;
        case LogLevel::INFO:    level_str = "[INFO ]"; break;
        case LogLevel::WARNING: level_str = "[WARN ]"; break;
        case LogLevel::ERROR:   level_str = "[ERROR]"; break;
    }
    
    std::cout << level_str << " " << message << std::endl;
}

// 输入验证实现
bool PaymentInterface::validate_amount(double amount) {
    return amount > 0 && amount <= 99999999; // 最大金额限制
}

bool PaymentInterface::validate_order_id(const std::string& order_id) {
    if(order_id.empty() || order_id.length() > 64) {
        return false;
    }
    
    // 订单ID只能包含字母、数字、下划线和连字符
    std::regex pattern("^[a-zA-Z0-9_-]+$");
    return std::regex_match(order_id, pattern);
}

bool PaymentInterface::validate_user_id(const std::string& user_id) {
    if(user_id.empty() || user_id.length() > 64) {
        return false;
    }
    
    // 用户ID只能包含字母、数字、下划线和连字符
    std::regex pattern("^[a-zA-Z0-9_-]+$");
    return std::regex_match(user_id, pattern);
}

bool PaymentInterface::validate_description(const std::string& description) {
    if(description.empty() || description.length() > 128) {
        return false;
    }
    
    // 检查是否包含危险字符
    std::regex dangerous_chars(R"([<>"'&])");
    return !std::regex_search(description, dangerous_chars);
}

// 密钥管理实现
KeyManager& KeyManager::instance() {
    static KeyManager instance;
    return instance;
}

bool KeyManager::load_private_key(const std::string& key_content) {
    std::lock_guard<std::mutex> lock(mutex_);
    private_key_ = key_content;
    return true;
}

bool KeyManager::load_public_key(const std::string& key_content) {
    std::lock_guard<std::mutex> lock(mutex_);
    public_key_ = key_content;
    return true;
}

bool KeyManager::load_private_key_from_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    std::string content;
    std::getline(file, content, '\0');  // 读取整个文件
    file.close();
    
    return load_private_key(content);
}

bool KeyManager::load_public_key_from_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    std::string content;
    std::getline(file, content, '\0');  // 读取整个文件
    file.close();
    
    return load_public_key(content);
}

std::string KeyManager::rsa_sign(const std::string& data, const std::string& algorithm) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if(private_key_.empty()) {
        throw std::runtime_error("Private key not loaded");
    }

    BIO* bio = BIO_new_mem_buf(private_key_.c_str(), -1);
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        throw std::runtime_error("Failed to load private key");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create signing context");
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize signing");
    }

    // 根据算法选择摘要类型
    const EVP_MD* md = NULL;
    if (algorithm == "RSA2" || algorithm == "SHA256") {
        md = EVP_sha256();
    } else {
        md = EVP_sha1();
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set signature algorithm");
    }

    // 获取签名长度
    size_t sig_len = 0;
    if (EVP_PKEY_sign(ctx, NULL, &sig_len, (unsigned char*)data.c_str(), data.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get signature length");
    }

    // 创建签名缓冲区
    unsigned char* sig = (unsigned char*)OPENSSL_malloc(sig_len);
    if (!sig) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to allocate signature buffer");
    }

    // 执行签名
    if (EVP_PKEY_sign(ctx, sig, &sig_len, (unsigned char*)data.c_str(), data.length()) <= 0) {
        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to sign data");
    }

    // 将签名转换为Base64
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, sig, sig_len);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string signature(bptr->data, bptr->length - 1); // 减1是为了去掉换行符
    
    // 清理资源
    BIO_free_all(b64);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return signature;
}

bool KeyManager::rsa_verify(const std::string& data, const std::string& signature, const std::string& algorithm) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if(public_key_.empty()) {
        throw std::runtime_error("Public key not loaded");
    }

    // 将Base64签名解码
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(bmem, signature.c_str(), signature.length());
    BIO_flush(bmem);

    int decoded_len = BIO_pending(bmem);
    char* decoded_sig = (char*)OPENSSL_malloc(decoded_len);
    int bytes_read = BIO_read(b64, decoded_sig, decoded_len);
    
    BIO_free_all(b64);

    if (bytes_read <= 0) {
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to decode signature");
    }

    // 加载公钥
    BIO* bio = BIO_new_mem_buf(public_key_.c_str(), -1);
    if (!bio) {
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to create BIO for public key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        // 尝试作为证书加载
        BIO_reset(bio);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    BIO_free(bio);

    if (!pkey) {
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to load public key");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        OPENSSL_free(decoded_sig);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create verification context");
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to initialize verification");
    }

    // 根据算法选择摘要类型
    const EVP_MD* md = NULL;
    if (algorithm == "RSA2" || algorithm == "SHA256") {
        md = EVP_sha256();
    } else {
        md = EVP_sha1();
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        OPENSSL_free(decoded_sig);
        throw std::runtime_error("Failed to set signature algorithm");
    }

    int result = EVP_PKEY_verify(ctx, (unsigned char*)decoded_sig, bytes_read, 
                                (unsigned char*)data.c_str(), data.length());

    OPENSSL_free(decoded_sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result == 1;
}

bool KeyManager::generate_rsa_keypair(std::string& private_key, std::string& public_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 创建RSA密钥对
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx) {
        throw std::runtime_error("Failed to create RSA context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set key size");
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate keypair");
    }

    EVP_PKEY_CTX_free(ctx);

    // 提取私钥
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write private key");
    }

    BUF_MEM* priv_buf;
    BIO_get_mem_ptr(priv_bio, &priv_buf);
    private_key.assign(priv_buf->data, priv_buf->length);
    BIO_free(priv_bio);

    // 提取公钥
    BIO* pub_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(pub_bio, pkey)) {
        BIO_free(pub_bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write public key");
    }

    BUF_MEM* pub_buf;
    BIO_get_mem_ptr(pub_bio, &pub_buf);
    public_key.assign(pub_buf->data, pub_buf->length);
    BIO_free(pub_bio);

    EVP_PKEY_free(pkey);
    
    return true;
}