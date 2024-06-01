#include "openfhe.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include <vector>
#include <iostream>
#include "Utils.h"

#include <fstream>
//#include <nlohmann/json.hpp>


using namespace lbcrypto;
using namespace std;
using namespace utils;


class CIFAR10CKKS {
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    PrivateKey<DCRTPoly> m_SecretKey;
    Ciphertext<DCRTPoly> m_InputC;
    Ciphertext<DCRTPoly> m_OutputC;
    string m_PubKeyLocation;
    string m_SecKeyLocation;
    string m_MultKeyLocation;
    string m_RotKeyLocation;
    string m_CCLocation;
    string m_InputLocation;
    string m_OutputLocation;

public:
    int num_slots = 65536;
    int depth = 21;

    CIFAR10CKKS(string ccLocation, string pubKeyLocation, string multKeyLocation, string rotKeyLocation,string inputLocation, string outputLocation);
    CIFAR10CKKS(string ccLocation, string pubKeyLocation, string secKeyLocation, string multKeyLocation, string rotKeyLocation,string inputLocation, string outputLocation, string mode);

	CIFAR10CKKS();

    void initCC(int test=0);

    void eval();

    void serializeOutput();

    void genCC();

    Plaintext encode(const vector<double> &vec, int level);

    Ciphertext<DCRTPoly> encrypt(const vector<double>& vec, int level = 0);

    vector<double> read_image(const char *filename);

    Ciphertext<DCRTPoly> conv3x16(const Ciphertext<DCRTPoly> &in, double scale);

    Ciphertext<DCRTPoly> conv2(const Ciphertext<DCRTPoly> &in, double scale);

    Ciphertext<DCRTPoly> conv3(const Ciphertext<DCRTPoly> &in, double scale);

    Ciphertext<DCRTPoly> fc(const Ciphertext<DCRTPoly> &in, double scale);

    Ciphertext<DCRTPoly> relu7(const Ciphertext<DCRTPoly> &in, double scale);

    Ciphertext<DCRTPoly> relu4(const Ciphertext<DCRTPoly> &in, double scale);

    Ciphertext<DCRTPoly> relu_square(const Ciphertext<DCRTPoly> &in);

    Ciphertext<DCRTPoly> model_conv3x16_relu7_conv16x16_relu7_conv16x16_relu7_fc(Ciphertext<DCRTPoly> &in);

    Ciphertext<DCRTPoly> model_conv3x16_relu7_fc(Ciphertext<DCRTPoly> &in);

    Ciphertext<DCRTPoly> model_conv3x16_square_fc(Ciphertext<DCRTPoly> &in);

    void store_res(Ciphertext<DCRTPoly> res, string filename);

    vector<double> decrypt_tovector(const Ciphertext<DCRTPoly> &c, int slots);

};