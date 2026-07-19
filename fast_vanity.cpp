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

const char BASE58_CHARS[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const size_t RIPEMD160_DIGEST_LENGTH = 20;

// High-speed, allocation-free Base58 encoder
void encodeBase58(const unsigned char* input, size_t len, char* output) {
    int digits[40] = {0};
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

    int out_idx = 0;
    for (size_t i = 0; i < len && input[i] == 0; ++i) {
        output[out_idx++] = '1';
    }
    for (int i = digits_len - 1; i >= 0; --i) {
        output[out_idx++] = BASE58_CHARS[digits[i]];
    }
    output[out_idx] = '\0';
}

// Inline generation pipeline to minimize CPU overhead
void pubKeyToAddress(secp256k1_context* ctx, EVP_MD_CTX* mdctx, const secp256k1_pubkey& pubkey, char* out_address) {
    unsigned char serialized_pub[33];
    size_t serialized_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized_pub, &serialized_len, &pubkey, SECP256K1_EC_COMPRESSED);

    unsigned char sha256_res[SHA256_DIGEST_LENGTH];
    SHA256(serialized_pub, 33, sha256_res);

    unsigned char ripemd_res[RIPEMD160_DIGEST_LENGTH + 5];
    ripemd_res[0] = 0x00; // Network byte

    unsigned int ripemd_len = 0;
    EVP_DigestInit_ex(mdctx, EVP_ripemd160(), nullptr);
    EVP_DigestUpdate(mdctx, sha256_res, SHA256_DIGEST_LENGTH);
    EVP_DigestFinal_ex(mdctx, ripemd_res + 1, &ripemd_len);

    unsigned char checksum_sha1[SHA256_DIGEST_LENGTH];
    unsigned char checksum_sha2[SHA256_DIGEST_LENGTH];
    SHA256(ripemd_res, RIPEMD160_DIGEST_LENGTH + 1, checksum_sha1);
    SHA256(checksum_sha1, SHA256_DIGEST_LENGTH, checksum_sha2);

    std::memcpy(ripemd_res + RIPEMD160_DIGEST_LENGTH + 1, checksum_sha2, 4);

    encodeBase58(ripemd_res, RIPEMD160_DIGEST_LENGTH + 5, out_address);
}

std::atomic<bool> found(false);
std::atomic<uint64_t> total_attempts(0);

void highSpeedSearchWorker(std::string prefix, int thread_id) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    std::random_device rd;
    std::mt19937_64 rng(rd() ^ thread_id);
    
    unsigned char priv_key[32];
    char address_buffer[50];
    uint64_t local_attempts = 0;

    size_t prefix_len = prefix.length();

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

            // Generate address directly into a pre-allocated stack buffer
            pubKeyToAddress(ctx, mdctx, pubkey, address_buffer);

            local_attempts++;
            if (local_attempts % 10000 == 0) {
                total_attempts += 10000;
                local_attempts = 0;
            }

            // Direct character checking on the array to avoid string object overhead
            if (std::strncmp(address_buffer + 1, prefix.c_str(), prefix_len) == 0) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    total_attempts += local_attempts;
                    
                    std::cout << "\n🎉 SUCCESS! Match Found by Performance Worker " << thread_id << "\n";
                    std::cout << "Address:     " << address_buffer << "\n";
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
    std::string target_prefix = "RoseCross"; // Targets addresses starting with 1BTC
    unsigned int threads = std::thread::hardware_concurrency();
    
    std::cout << "🚀 Starting Corrected Hashing Engine...\n";
    std::cout << "🎯 Target Prefix: 1" << target_prefix << "\n";
    std::cout << "🧵 Spawning " << threads << " optimized threads...\n\n";

    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<std::thread> worker_threads;

    for (unsigned int i = 0; i < threads; ++i) {
        worker_threads.push_back(std::thread(highSpeedSearchWorker, target_prefix, i));
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
