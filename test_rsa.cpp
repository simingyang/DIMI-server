#include <iostream>
#include <string>
#include <memory>
#include <mutex>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

class SimpleKeyManager {
public:
    static SimpleKeyManager& instance() {
        static SimpleKeyManager instance;
        return instance;
    }
    
    bool generate_rsa_keypair(std::string& private_key, std::string& public_key) {
        // 创建RSA密钥对
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

        if (!ctx) {
            std::cout << "Failed to create RSA context\n";
            return false;
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cout << "Failed to initialize key generation\n";
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0) {  // 使用1024位以简化测试
            std::cout << "Failed to set key size\n";
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cout << "Failed to generate keypair\n";
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        EVP_PKEY_CTX_free(ctx);

        // 提取私钥
        BIO* priv_bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL);

        BUF_MEM* priv_buf;
        BIO_get_mem_ptr(priv_bio, &priv_buf);
        private_key.assign(priv_buf->data, priv_buf->length);
        BIO_free(priv_bio);

        // 提取公钥
        BIO* pub_bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(pub_bio, pkey);

        BUF_MEM* pub_buf;
        BIO_get_mem_ptr(pub_bio, &pub_buf);
        public_key.assign(pub_buf->data, pub_buf->length);
        BIO_free(pub_bio);

        EVP_PKEY_free(pkey);
        
        return true;
    }
    
    std::string rsa_sign(const std::string& data, const std::string& private_key_pem) {
        BIO* bio = BIO_new_mem_buf(private_key_pem.c_str(), -1);
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

        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
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
        
        std::string signature(bptr->data, bptr->length); // 不减1，保留换行符

        // 清理资源
        BIO_free_all(b64);
        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        return signature;
    }
    
    bool rsa_verify(const std::string& data, const std::string& signature, const std::string& public_key_pem) {
        BIO* bio = BIO_new_mem_buf(public_key_pem.c_str(), -1);
        if (!bio) {
            throw std::runtime_error("Failed to create BIO for public key");
        }

        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (!pkey) {
            throw std::runtime_error("Failed to load public key");
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create verification context");
        }

        if (EVP_PKEY_verify_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to initialize verification");
        }

        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to set signature algorithm");
        }

        // 将Base64签名解码
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new_mem_buf(signature.c_str(), -1);
        b64 = BIO_push(b64, bmem);
        
        char* decoded_sig = (char*)OPENSSL_malloc(4096); // 分配足够大的缓冲区
        int decoded_len = BIO_read(b64, decoded_sig, 4096);
        
        BIO_free_all(b64);

        if (decoded_len <= 0) {
            OPENSSL_free(decoded_sig);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to decode signature");
        }

        int result = EVP_PKEY_verify(ctx, (unsigned char*)decoded_sig, decoded_len, 
                                    (unsigned char*)data.c_str(), data.length());

        OPENSSL_free(decoded_sig);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        return result == 1;
    }
};

int main() {
    std::cout << "Testing RSA functionality...\n";
    
    SimpleKeyManager& km = SimpleKeyManager::instance();
    
    // 生成密钥对
    std::string private_key, public_key;
    if (km.generate_rsa_keypair(private_key, public_key)) {
        std::cout << "RSA keypair generated successfully\n";
        std::cout << "Private key length: " << private_key.length() << "\n";
        std::cout << "Public key length: " << public_key.length() << "\n";
        
        // 测试签名
        std::string data = "Hello, secure payment system!";
        try {
            std::string signature = km.rsa_sign(data, private_key);
            std::cout << "Signature generated successfully, length: " << signature.length() << "\n";
            
            // 测试验证
            bool is_valid = km.rsa_verify(data, signature, public_key);
            std::cout << "Signature verification: " << (is_valid ? "PASSED" : "FAILED") << "\n";
            
            // 测试验证被篡改的数据
            bool tampered_valid = km.rsa_verify("Tampered data", signature, public_key);
            std::cout << "Tampered data verification: " << (tampered_valid ? "PASSED (WRONG)" : "FAILED (CORRECT)") << "\n";
            
        } catch (const std::exception& e) {
            std::cout << "Error during signing/verification: " << e.what() << "\n";
        }
    } else {
        std::cout << "Failed to generate RSA keypair\n";
    }
    
    return 0;
}