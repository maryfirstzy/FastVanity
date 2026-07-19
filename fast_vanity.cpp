#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>
#include <cstring>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

const std::string BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const size_t RIPEMD160_DIGEST_LENGTH = 20;

// Base58 Decoder used once at startup to turn your text prefix into raw match bytes
bool decodeBase58Prefix(const std::string& str, std::vector<unsigned char>& out_bytes) {
    std::vector<unsigned char> tmp(str.length(), 0);
    for (size_t i = 0; i < str.length(); ++i) {
        size_t idx = BASE58_CHARS.find(str[i]);
        if (idx == std::string::npos) return false;
        tmp[i] = static_cast<unsigned char>(idx);
    }
    
    std::vector<unsigned char> result(32, 0);
    int result_len = 1;
    for (size_t i = 0; i < tmp.size(); ++i) {
        int carry = tmp[i];
        for (int j = 0; j < result_len; ++j) {
            carry += result[j] * 58;
            result[j] = carry & 0xFF;
            carry >>= 8;
        }
        while (carry > 0) {
            result[result_len] = carry & 0xFF;
            carry >>= 8;
            result_len++;
        }
    }
    
    out_bytes.clear();
    for (int i = result_len - 1; i >= 0; --i) {
        out_bytes.push_back(result[i]);
    }
    return true;
}

// Standard Base58 encoder called ONLY ONCE when a valid match is found
std::string encodeBase58(const unsigned char* input, size_t len) {
    std::vector<int> digits(40, 0);
    int digits_len = 1;
    for (size_t i = 0; i < len; ++i) {
        int carry = input[i];
        for (int j = 0; j < digits_len; ++j) {
            carry += digits[j] << 8;
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits[digits_len] = carry % 58;
            carry /= 58;
            digits_len++;
        }
    }
    std::string result = "";
    for (size_t i = 0; i < len && input[i] == 0; ++i) result += '1';
    for (int i = digits_len - 1; i >= 0; --i) result += BASE58_CHARS[digits[i]];
    return result;
}

std::string finalizeAddress(const unsigned char* ripemd_payload) {
    unsigned char ripemd_res[RIPEMD160_DIGEST_LENGTH + 5];
    ripemd_res[0] = 0x00; // Network byte
    std::memcpy(ripemd_res + 1, ripemd_payload, RIPEMD160_DIGEST_LENGTH);
    
    unsigned char checksum_sha1[SHA256_DIGEST_LENGTH];
    unsigned char checksum_sha2[SHA256_DIGEST_LENGTH];
    SHA256(ripemd_res, RIPEMD160_DIGEST_LENGTH + 1, checksum_sha1);
    SHA256(checksum_sha1, SHA256_DIGEST_LENGTH, checksum_sha2);
    
    std::memcpy(ripemd_res + RIPEMD160_DIGEST_LENGTH + 1, checksum_sha2, 4);
    return encodeBase58(ripemd_res, RIPEMD160_DIGEST_LENGTH + 5);
}

std::atomic<bool> found(false);
std::atomic<uint64_t> total_attempts(0);
std::vector<unsigned char> target_bytes;
size_t prefix_byte_len = 0;

void highSpeedSearchWorker(int thread_id) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    std::random_device rd;
    std::mt19937_64 rng(rd() ^ thread_id);
    
    unsigned char priv_key[32];          // Fixed array size definition
    unsigned char serialized_pub[33];    // Fixed array size definition
    unsigned char sha256_res[SHA256_DIGEST_LENGTH];
    unsigned char ripemd_res[RIPEMD160_DIGEST_LENGTH];
    
    uint64_t local_attempts = 0;

    while (!found) {
        for (int i = 0; i < 32; i += 8) {
            uint64_t r = rng();
            std::memcpy(priv_key + i, &r, 8);
        }

        for (uint16_t counter = 0; counter < 65535 && !found; ++counter) {
            std::memcpy(priv_key + 30, &counter, 2);

            if (!secp256k1_ec_seckey_verify(ctx, priv_key)) continue;

            secp256k1_pubkey pubkey;
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key)) continue;

            size_t serialized_len = 33;
            secp256k1_ec_pubkey_serialize(ctx, serialized_pub, &serialized_len, &pubkey, SECP256K1_EC_COMPRESSED);

            SHA256(serialized_pub, 33, sha256_res);

            unsigned int ripemd_len = 0;
            EVP_DigestInit_ex(mdctx, EVP_ripemd160(), nullptr);
            EVP_DigestUpdate(mdctx, sha256_res, SHA256_DIGEST_LENGTH);
            EVP_DigestFinal_ex(mdctx, ripemd_res, &ripemd_len);

            local_attempts++;
            if (local_attempts % 20000 == 0) {
                total_attempts += 20000;
                local_attempts = 0;
            }

            if (std::memcmp(ripemd_res, target_bytes.data(), prefix_byte_len) == 0) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    total_attempts += local_attempts;
                    std::string final_address = finalizeAddress(ripemd_res);
                    
                    std::cout << "\n🎉 SUCCESS! Match Found by Performance Worker " << thread_id << "\n";
                    std::cout << "Address:     " << final_address << "\n";
                    std::cout << "Private Key (Hex): ";
                    for(int i = 0; i < 32; ++i) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)priv_key[i];
                    }
                    std::cout << std::dec << "\n";
                }
                break;
            }
        }
    }
    EVP_MD_CTX_free(mdctx);
    secp256k1_context_destroy(ctx);
}

int main() {
    std::string target_prefix = "BTC"; // Edit your target token pattern here
    
    if (!decodeBase58Prefix(target_prefix, target_bytes)) {
        std::cerr << "❌ Error: Target prefix contains invalid Base58 characters!\n";
        return 1;
    }
    prefix_byte_len = target_bytes.size();
    unsigned int threads = std::thread::hardware_concurrency();
    
    std::cout << "🚀 Starting Streamlined Hashing Engine...\n";
    std::cout << "🎯 Target Prefix: 1" << target_prefix << "\n";
    std::cout << "🧵 Spawning " << threads << " optimized threads...\n\n";

    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<std::thread> worker_threads;

    for (unsigned int i = 0; i < threads; ++i) {
        worker_threads.push_back(std::thread(highSpeedSearchWorker, i)); // Fixed missing argument
    }

    while (!found) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto now = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = now - start_time;
        
        uint64_t current_count = total_attempts.load();
        double speed = current_count / elapsed.count();
        
        std::cout << "\r⚡ Engine Speed: " << std::fixed << std::setprecision(2) 
                  << (speed / 1000.0) << " kkeys/s | Total checked: " << current_count 
                  << " | Time: " << (int)elapsed.count() << "s" << std::flush;
    }

    for (auto& t : worker_threads) {
        if (t.joinable()) t.join();
    }
    return 0;
}
