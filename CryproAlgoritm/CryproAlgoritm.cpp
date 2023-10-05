#include <iostream>
#include <string>
#include <vector>
#include <bitset>
#include <sstream>
#include <iomanip>
#include <Windows.h>
#include <chrono>

// Набір символів (матриця)
const std::string input_data = "0110110000101001101010000110011100010000101000010000100001010101110101000001001001010101111000011000101000111001011011110011011110101101001001001100000110011000101010011000110001001100101001010001110011010111111001110111000010001001001011111010101000101110100111110100011010011000000100100001100010100001101101100000101001011101110001011000110100011000100001100011110101000110111001100110111101000011000111101110000000011111101000100110100000100111011111111100100011011101110010110001010101101001101100100101010010001010000110101100000010111000100001110000000011111000101101011110000010000111010111000001010100001001011110000000011110000000101101110100011101001011000010101100111001100110010001001010011001011001111110110001110110101101101111000011100001110001000010011011010010101100001000011001010111010110011010110101100101001011111111110101110101001110101000001010100111011111100011000011011000011001011100010011001000010100101011000011011111001101001100110110101101010011010101000010110111011101110101011010110000011110#1010100101001011001011000000001010000101111111101100011111110100010000111011111101001100100110001110111000100010011100101110011001000100001001100000001011001011010101001010010101101101010000111011010000011101111010010111010001101010101101101011000101101000001111110000110010010111011101100101010110011101000010111111111111111111011010010011011011100100110011101100101010011110101101001110100000001110101010001000000000110101110011101110010100101110100010011000000101010111011100100010101111001000010010110011101111111001101000100100001100011110010001010000101001000010100101111100100011101000101101101110001001000000000111111011011001011111100110100000111110001000001111110100100011001111101001100100001100100100000111001111110101001000001001110000001100111110110001110111001100011110110111100010000010010011101011011100101000011001011110001111100111110111000010000000010010101001010010110101011001000101111111000101111011110001010011000000000000100010011011100000101111011110110000010101011000001110100011000011100100011000#1110111000110001110000111001001001111110110101011100010101011101010101100001100011011010100100101110100101001000101111110010100101001110011101000100011000100010000001101010010000000101101110101001101001001000010100101010010100110000111111001011001011011111001111111100110011111101111100011110001010001100111001001111011111110100110110000011010001111010011100010011001000010111001010011011000000111000101100000110000001101011110010000010011101111000010000000100001000000110010010010001101100000010001100101101001101011111001010011010010100010011100101001110011001000111100001011110001011110100001111111110110011111111010111010010011001010100010110100001001110000011100100010110100000100011010010001101110110111100011111110000000011000001001111010000011010101110110111010100110001111100010110111000010101100010100111101001010101001010011011000100011000001000000001000010000101011110000110110101010000110101100111111000011010001001011100011101100100010010111100100101000010110001010001011011010100110011101101001000001000011101#0000100001110000011001001101010110110011100100000011110100010011011000110011010010101001011110000110100001000101101010100010111101110010101010000101111111111101001011110110001100011110110100100001101000000000011101000100001101001111000011101000100100101111101110111001000111101000000111101100000010100000011010111010111000110010000100001011010101101011101011101111001000111100110000000110110001110001010101100011101010100111010011000110011000000101011011010111110110000101010001001000101111100011010010010100111111010000010001100101111101011110010000011000100100110101010011010111111010000001000010001111100100100011011001001111101110011110101011000111000010010101111110001101001000011100001111110000110101100101001100111011100110001000101101100101000111010110110011011111000011000100011000110101101110001111010001010000100001101101000011100101101011001101100100010110001111111011011010001000111010111001111101100011011110110101100000000101101110011101110110101100000100001010011011110101001010110100101111100100010101010001";

// Функція для обчислення SHA-224 хешу
std::string sha224(const std::string& input) {
    // Ініціалізація констант
    std::vector<uint32_t> h(8);
    h[0] = 0xc1059ed8;
    h[1] = 0x367cd507;
    h[2] = 0x3070dd17;
    h[3] = 0xf70e5939;
    h[4] = 0xffc00b31;
    h[5] = 0x68581511;
    h[6] = 0x64f98fa7;
    h[7] = 0xbefa4fa4;

    // Функція SIGMA
    auto sigma0 = [](uint32_t x) -> uint32_t {
        return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
    };
    auto sigma1 = [](uint32_t x) -> uint32_t {
        return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
    };

    // Перетворення вхідних даних в бінарний формат
    std::vector<uint8_t> binary_input;
    for (char c : input) {
        binary_input.push_back(static_cast<uint8_t>(c));
    }

    // Доповнення даних до кратного 512 біт
    size_t initial_length = binary_input.size();
    binary_input.push_back(0x80);
    while ((binary_input.size() * 8) % 512 != 448) {
        binary_input.push_back(0x00);
    }

    // Додавання довжини даних у бітовому представленні
    uint64_t bit_length = initial_length * 8;
    binary_input.insert(binary_input.end(), reinterpret_cast<uint8_t*>(&bit_length), reinterpret_cast<uint8_t*>(&bit_length) + 8);

    // Обчислення хешу
    for (size_t i = 0; i < binary_input.size(); i += 64) {
        std::vector<uint32_t> w(64);
        for (size_t j = 0; j < 16; ++j) {
            w[j] = (binary_input[i + j * 4] << 24) |
                (binary_input[i + j * 4 + 1] << 16) |
                (binary_input[i + j * 4 + 2] << 8) |
                (binary_input[i + j * 4 + 3]);
        }

        for (size_t j = 16; j < 64; ++j) {
            w[j] = sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) + w[j - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t index = h[7];

        for (size_t j = 0; j < 64; ++j) {
            uint32_t t1 = index + (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
            t1 += (g & (e ^ f)) ^ f ^ g;
            t1 += 0x428a2f98 + w[j];

            uint32_t t2 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
            t2 += ((a & (b | c)) | (b & c));

            index = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += index;
    }

    // Перетворення результату у шістнадцятковий формат
    std::stringstream result;
    for (const uint32_t& val : h) {
        result << std::hex << std::setfill('0') << std::setw(8) << val;
    }

    return result.str();
}

// Функція для брутфорсу
void bruteForceSHA224() {
    for (int i = 0; i < 256; ++i) {
        std::string candidate;
        for (int j = 0; j < 8; ++j) {
            if (i & (1 << j)) {
                candidate += static_cast<char>(i);
            }
        }

        std::string hash_result = sha224(candidate);
        std::cout << "SHA-224 hash for candidate: " << candidate << " - " << hash_result << std::endl;
    }
}

int main() {
    // Початок обчислення часу
    auto start_time = std::chrono::high_resolution_clock::now();

    SetConsoleOutputCP(1251);

    std::cout << "Брутсорф, що порівнює хеш-значення SHA-224 для різних кандидатів із заданим значенням хеша SHA-224:";
    bruteForceSHA224();

    // Ваша строка для обчислення хешу
    std::string input_string = " <<\nОтриманий SHA-224 хеш";

    // Кінець обчислення часу
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::string hash_result = sha224(input_string);
    std::cout << input_string << " : " << hash_result << " (Time: " << duration.count() << " ms)" << std::endl;

    return 0;
}

/*#include <iostream>
#include <string>
#include <cstdint>
#include <iomanip>
#include <Windows.h>
#include <sstream>
#include <chrono>

// Логічні функції SHA-224
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define R(x, n) ((x) >> (n))

// Перетворення інпуту у блоки 64 байти
void PreprocessInput(const std::string& input, uint32_t* blocks) {
    // Доповнення вхідних даних
    size_t initialLength = input.length();
    size_t paddedLength = ((initialLength + 8) / 64 + 1) * 64;
    uint8_t* paddedInput = new uint8_t[paddedLength];
    for (size_t i = 0; i < initialLength; ++i) {
        paddedInput[i] = input[i];
    }
    paddedInput[initialLength] = 0x80;
    uint64_t bitLength = initialLength * 8;
    for (int i = 0; i < 8; ++i) {
        paddedInput[paddedLength - 8 + i] = static_cast<uint8_t>(bitLength >> (56 - 8 * i));
    }

    // Розбивка на блоки 64 байти
    for (size_t i = 0; i < paddedLength; i += 64) {
        for (int j = 0; j < 16; ++j) {
            blocks[i / 4 + j] = (static_cast<uint32_t>(paddedInput[i + j * 4]) << 24) |
                (static_cast<uint32_t>(paddedInput[i + j * 4 + 1]) << 16) |
                (static_cast<uint32_t>(paddedInput[i + j * 4 + 2]) << 8) |
                (static_cast<uint32_t>(paddedInput[i + j * 4 + 3]));
        }
    }

    delete[] paddedInput;
}

// Головна функція обчислення SHA-224
std::string sha224(const std::string& input) {
    // Ініціалізація констант
    uint32_t h[8] = { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };

    // Попередня обробка вхідних даних
    uint32_t* blocks = new uint32_t[16];
    PreprocessInput(input, blocks);

    // Головний цикл SHA-224
    for (size_t i = 0; i < (input.length() + 8) / 64; ++i) {
        uint32_t w[64] = { 0 };
        for (int t = 0; t < 16; ++t) {
            w[t] = blocks[i * 16 + t];
        }
        for (int t = 16; t < 64; ++t) {
            w[t] = S(w[t - 2], 17) ^ S(w[t - 2], 19) ^ R(w[t - 2], 10) + w[t - 7] +
                S(w[t - 15], 7) ^ S(w[t - 15], 18) ^ R(w[t - 15], 3) + w[t - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t index = h[7];

        for (int t = 0; t < 64; ++t) {
            uint32_t T1 = index + (S(e, 6) ^ S(e, 11) ^ S(e, 25)) + Ch(e, f, g) + h[t] + w[t];
            uint32_t T2 = (S(a, 2) ^ S(a, 13) ^ S(a, 22)) + (Maj(a, b, c));

            index = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += index;
    }

    // Форматування результату в шістнадцятковий вид
    std::stringstream result;
    for (int i = 0; i < 8; ++i) {
        result << std::hex << std::setfill('0') << std::setw(8) << h[i];
    }

    delete[] blocks;
    return result.str();
}

int main() {
    // Початок обчислення часу
    auto start_time = std::chrono::high_resolution_clock::now();

    SetConsoleOutputCP(1251);

    std::string targetDigest = "ebc2352de073b4a455c5ddfaaf653a8c4a442f91f5ad63c472240a3c9d95055a";
    int maxLength = 8;

    for (int length = 1; length <= maxLength; ++length) {
        std::string candidate(length, ' ');

        // Кінець обчислення часу
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        while (true) {
            std::string candidateDigest = sha224(candidate);
            if (candidateDigest == targetDigest) {
                std::cout << "Знайдено відповідний рядок: " << candidate << " (Time: " << duration.count() << " ms)" << std::endl;
                return 0;
            }
            bool carry = true;
            for (int i = length - 1; i >= 0; --i) {
                if (carry) {
                    ++candidate[i];
                    if (candidate[i] > 'z') {
                        candidate[i] = ' ';
                    }
                    else {
                        carry = false;
                    }
                }
            }
            if (carry) {
                break;
            }
        }
    }

    std::cout << "Рядок не знайдено." << std::endl;
    return 0;
}*/