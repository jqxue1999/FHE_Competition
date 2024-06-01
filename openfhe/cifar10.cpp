#include "cifar10.h"

#define STB_IMAGE_IMPLEMENTATION

#include "stb_image.h"

CIFAR10CKKS::CIFAR10CKKS(
        string ccLocation, string pubKeyLocation, string secKeyLocation, string multKeyLocation, string rotKeyLocation,
        string inputLocation, string outputLocation, string mode
) : m_PubKeyLocation(pubKeyLocation), m_SecKeyLocation(secKeyLocation),
    m_MultKeyLocation(multKeyLocation), m_RotKeyLocation(rotKeyLocation),
    m_CCLocation(ccLocation), m_InputLocation(inputLocation), m_OutputLocation(outputLocation) {

    if (mode == "gen")
        genCC();
    else
        initCC(1);
};


CIFAR10CKKS::CIFAR10CKKS(
        string ccLocation, string pubKeyLocation, string multKeyLocation, string rotKeyLocation,
        string inputLocation, string outputLocation
) :
        m_PubKeyLocation(pubKeyLocation), m_MultKeyLocation(multKeyLocation), m_RotKeyLocation(rotKeyLocation),
        m_CCLocation(ccLocation), m_InputLocation(inputLocation), m_OutputLocation(outputLocation) {

    initCC();

};


void CIFAR10CKKS::initCC(int test) {
    if (!Serial::DeserializeFromFile(m_CCLocation, m_cc, SerType::BINARY)) {
        cerr << "Could not deserialize cryptocontext file" << endl;
        exit(1);
    }

    if (!Serial::DeserializeFromFile(m_PubKeyLocation, m_PublicKey, SerType::BINARY)) {
        cerr << "Could not deserialize public key file" << endl;
        exit(1);
    }

    if (test==1){
        if (!Serial::DeserializeFromFile(m_SecKeyLocation, m_SecretKey, SerType::BINARY)) {
            cerr << "Could not deserialize secret key file" << endl;
            exit(1);
        }
    }

    ifstream multKeyIStream(m_MultKeyLocation, ios::in | ios::binary);
    if (!multKeyIStream.is_open()) {
        exit(1);
    }
    if (!m_cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
        cerr << "Could not deserialize rot key file" << endl;
        exit(1);
    }

    ifstream rotKeyIStream(m_RotKeyLocation, ios::in | ios::binary);
    if (!rotKeyIStream.is_open()) {
        exit(1);
    }

    if (!m_cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
        cerr << "Could not deserialize eval rot key file" << endl;
        exit(1);
    }

    if (!Serial::DeserializeFromFile(m_InputLocation, m_InputC, SerType::BINARY)) {
        cerr << "Could not deserialize Input ciphertext" << endl;
        exit(1);
    }
    if (test == 1) {
        cout << "Step 1" << endl;
        vector<double> res_clean = decrypt_tovector(m_InputC, 4096);
        for (int i = 0; i < 10; i++)
            cout << res_clean[i] << " ";
        cout << endl;
    }

}

void CIFAR10CKKS::genCC() {
    // Set up the parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetRingDim(131072);
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetBatchSize(num_slots);

    // Generate the CryptoContext
    m_cc = GenCryptoContext(parameters);

    m_cc->Enable(PKE);
    m_cc->Enable(KEYSWITCH);
    m_cc->Enable(LEVELEDSHE);
    m_cc->Enable(ADVANCEDSHE);
    m_cc->Enable(FHE);

    KeyPair<DCRTPoly> key_pair = m_cc->KeyGen();
    m_SecretKey = key_pair.secretKey;
    m_PublicKey = key_pair.publicKey;

    vector<int32_t> rotations = {1, 2, 32, 33, 34, 64, 65, 66, 1024, 8192, 4096, 2048, 512, 256, 128, 16, 8, 4, -1, -2, -3, -4, -5, -6, -7, -8, -9, num_slots - 1024 * 16};
    m_cc->EvalRotateKeyGen(m_SecretKey, rotations);
    m_cc->EvalMultKeyGen(m_SecretKey);

    cout << "Now serializing keys ..." << endl;

    ofstream multKeyFile(m_MultKeyLocation, ios::out | ios::binary);
    if (multKeyFile.is_open()) {
        if (!m_cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
            cerr << "Error writing eval mult keys" << std::endl;
            exit(1);
        }
        cout << "Relinearization Keys have been serialized" << std::endl;
        multKeyFile.close();
    }
    else {
        cerr << "Error serializing EvalMult keys in " << m_MultKeyLocation << endl;
        exit(1);
    }

    if (!Serial::SerializeToFile(m_CCLocation, m_cc, SerType::BINARY)) {
        cerr << "Error writing serialization of the crypto context to crypto-context.txt" << endl;
    } else {
        cout << "Crypto Context have been serialized" << std::endl;
    }

    if (!Serial::SerializeToFile(m_PubKeyLocation, m_PublicKey, SerType::BINARY)) {
        cerr << "Error writing serialization of public key to " << m_PubKeyLocation << endl;
    } else {
        cout << "Public Key has been serialized" << std::endl;
    }

    if (!Serial::SerializeToFile("../keys/secret-key.txt", m_SecretKey, SerType::BINARY)) {
        cerr << "Error writing serialization of public key to secret-key.txt" << endl;
    } else {
        cout << "Secret Key has been serialized" << std::endl;
    }

    std::ofstream rotKeyOStream(m_RotKeyLocation, std::ios::out | std::ios::binary);
    if (rotKeyOStream.is_open()) {
        if (!m_cc->SerializeEvalAutomorphismKey(rotKeyOStream, SerType::BINARY)) {
            cerr << "Error writing eval automorphism keys" << std::endl;
            exit(1);
        }
        cout << "Rotation Keys have been serialized" << std::endl;
        rotKeyOStream.close();
    } else {
        cerr << "Error serializing EvalAutomorphism keys in " << m_RotKeyLocation << endl;
        exit(1);
    }

    string input_filename = "../inputs/test.png";
    vector<double> input_image = read_image(input_filename.c_str());

    m_InputC = encrypt(input_image, 0);

    if (!Serial::SerializeToFile(m_InputLocation, m_InputC, SerType::BINARY)) {
        cerr << "Error writing ciphertext 1" << endl;
    } else {
        cout << "Input ciphertext has been serialized" << endl;
    }

}

vector<double> CIFAR10CKKS::read_image(const char *filename) {
    int width = 32;
    int height = 32;
    int channels = 3;
    unsigned char *image_data = stbi_load(filename, &width, &height, &channels, 0);

    if (!image_data) {
        cerr << "Could not load the image in " << filename << endl;
        return {};
    }

    vector<double> imageVector;
    imageVector.reserve(width * height * channels);

    for (int i = 0; i < width * height; ++i) {
        //Channel R
        imageVector.push_back(static_cast<double>(image_data[3 * i]) / 255.0f);
    }
    for (int i = 0; i < width * height; ++i) {
        //Channel G
        imageVector.push_back(static_cast<double>(image_data[1 + 3 * i]) / 255.0f);
    }
    for (int i = 0; i < width * height; ++i) {
        //Channel B
        imageVector.push_back(static_cast<double>(image_data[2 + 3 * i]) / 255.0f);
    }

    stbi_image_free(image_data);

    ofstream outFile("input.txt");
    if (outFile.is_open()) {
        for (auto val: imageVector) {
            outFile << val << " ";
        }
        outFile.close();
    } else {
        std::cerr << "Unable to open file for writing." << std::endl;
    }

    return imageVector;
}


Plaintext CIFAR10CKKS::encode(const vector<double> &vec, int level) {
    size_t encoded_size = vec.size();

    Plaintext p = m_cc->MakeCKKSPackedPlaintext(vec, 1, level);
    p->SetLength(encoded_size);

    return p;
}


Ciphertext<DCRTPoly> CIFAR10CKKS::encrypt(const vector<double> &vec, int level) {
    Plaintext p = encode(vec, level);
    return m_cc->Encrypt(p, m_PublicKey);
}


vector<double> CIFAR10CKKS::decrypt_tovector(const Ciphertext<DCRTPoly> &c, int slots) {
    if (slots == 0) {
        slots = num_slots;
    }

    Plaintext p;
    m_cc->Decrypt(m_SecretKey, c, &p);
    p->SetLength(slots);
    vector<double> vec = p->GetRealPackedValue();
    return vec;
}

void CIFAR10CKKS::store_res(Ciphertext<DCRTPoly> res, string filename){
    vector<double> res_clean = decrypt_tovector(res, 16384);
    ofstream outFile(filename);
    if (outFile.is_open()) {
        for (auto val: res_clean)
            outFile << val << " ";
        outFile.close();
    } else
        std::cerr << "Unable to open file for writing." << std::endl;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::model_conv3x16_square_fc(Ciphertext<DCRTPoly> &in) {
    Ciphertext<DCRTPoly> res1 = conv3x16(in, 1);
    res1 = relu_square(res1);
    Ciphertext<DCRTPoly> res = fc(res1, 1);

    return res;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::model_conv3x16_relu7_fc(Ciphertext<DCRTPoly> &in) {
    Ciphertext<DCRTPoly> res1 = conv3x16(in, 1);
    res1 = relu7(res1, 1.0 / 14.0);
    Ciphertext<DCRTPoly> res = fc(res1, 1);

    return res;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::model_conv3x16_relu7_conv16x16_relu7_conv16x16_relu7_fc(Ciphertext<DCRTPoly> &in) {
    cout << "-------------------- Conv1  --------------------" << endl;

    Ciphertext<DCRTPoly> res1 = conv3x16(in, 1);
    store_res(res1, "../temp/conv1_res.txt");
    cout << "[Before Boot] Conv1 result level: " << res1->GetLevel() << endl;
    cout << "[Before Boot] Remaining level of Conv1 result: " << depth - res1->GetLevel() << endl;

    res1 = relu7(res1, 1.0 / 5.0);
    store_res(res1, "../temp/relu1_res.txt");
    cout << "[Before Boot] ReLU1 result level: " << res1->GetLevel() << endl;
    cout << "[Before Boot] Remaining level of ReLU1 result: " << depth - res1->GetLevel() << endl;

    cout << "-------------------- Conv2  --------------------" << endl;

    Ciphertext<DCRTPoly> res2 = conv16x16_1(res1, 1);
    store_res(res2, "../temp/conv2_res.txt");
    cout << "[Before Boot] Conv2 result level: " << res2->GetLevel() << endl;
    cout << "[Before Boot] Remaining level of Conv2 result: " << depth - res2->GetLevel() << endl;

    res2 = relu7(res2, 1.0/23.0);
    store_res(res2, "../temp/relu2_res.txt");
    cout << "[Before Boot] ReLU2 result level: " << res2->GetLevel() << endl;
    cout << "[Before Boot] Remaining level of ReLU2 result: " << depth - res2->GetLevel() << endl;

    cout << "[After Boot] ReLU2 result level: " << res2->GetLevel() << endl;
    cout << "[After Boot] Remaining level of ReLU2 result: " << depth - res2->GetLevel() << endl;

    cout << "-------------------- Conv3  --------------------" << endl;

    Ciphertext<DCRTPoly> res3 = conv16x16_2(res2, 1);
    store_res(res3, "../temp/conv3_res.txt");
    cout << "[Before Boot] Conv3 result level: " << res3->GetLevel() << endl;
    cout << "[Before Boot] Remaining level of Conv3 result: " << depth - res3->GetLevel() << endl;

    res3 = relu7(res3, 1.0 / 58.0);
    store_res(res3, "../temp/relu3_res.txt");
    cout << "[Before Boot] ReLU3 result level: " << res3->GetLevel() << endl;
    cout << "[Before Boot] Remaining level of ReLU3 result: " << depth - res3->GetLevel() << endl;

    res3 = m_cc->EvalBootstrap(res3);
    cout << "[After Boot] ReLU3 result level: " << res3->GetLevel() << endl;
    cout << "[After Boot] Remaining level of ReLU3 result: " << depth - res3->GetLevel() << endl;

    cout << "-------------------- FC  --------------------" << endl;

    Ciphertext<DCRTPoly> res = fc(res3, 1);
    store_res(res, "../temp/fc_res.txt");
    cout << "FC result level: " << res->GetLevel() << endl;

    return res;
}

void CIFAR10CKKS::eval(){
    Ciphertext<DCRTPoly> in = m_InputC;

    m_OutputC = model_conv3x16_square_fc(in);
}


void CIFAR10CKKS::serializeOutput() {
    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY)) {
        cerr << " Error writing ciphertext 1" << endl;
    }
}


Ciphertext<DCRTPoly> CIFAR10CKKS::conv3x16(const Ciphertext<DCRTPoly> &in, double scale) {
    vector<Ciphertext<DCRTPoly>> c_rotations;

    c_rotations.push_back(in);
    c_rotations.push_back(m_cc->EvalRotate(in, 1));
    c_rotations.push_back(m_cc->EvalRotate(in, 2));
    c_rotations.push_back(m_cc->EvalRotate(in, 32));
    c_rotations.push_back(m_cc->EvalRotate(in, 33));
    c_rotations.push_back(m_cc->EvalRotate(in, 34));
    c_rotations.push_back(m_cc->EvalRotate(in, 64));
    c_rotations.push_back(m_cc->EvalRotate(in, 65));
    c_rotations.push_back(m_cc->EvalRotate(in, 66));

    Ciphertext<DCRTPoly> finalsum;

    for (int c = 0; c < 16; c++) {
        vector<Ciphertext<DCRTPoly>> k_rows;
        for (int k = 0; k < 9; k++) {
            vector<double> weights = read_values_from_file(m_WeightsDir + "/conv1-ch" + to_string(c) + "-k" + to_string(k) + ".bin", scale);
            Plaintext encoded = encode(weights, in->GetLevel());
            k_rows.push_back(m_cc->EvalMult(c_rotations[k], encoded));
        }

        Ciphertext<DCRTPoly> sum = m_cc->EvalAddMany(k_rows);
        Ciphertext<DCRTPoly> res = sum->Clone();
        Ciphertext<DCRTPoly> sum_shift = m_cc->EvalRotate(sum, 1024);

        res = m_cc->EvalAdd(res, sum_shift);
        res = m_cc->EvalAdd(res, m_cc->EvalRotate(sum_shift, 1024));

        Plaintext bias=  encode(read_values_from_file(m_WeightsDir + "/conv1-ch" + to_string(c) + "-bias.bin", scale), res->GetLevel());
        res = m_cc->EvalAdd(res, bias);

        Plaintext mask = encode(read_values_from_file(m_WeightsDir + "/conv1-mask.bin", scale), res->GetLevel());
        res = m_cc->EvalMult(res, mask);

        if (c == 0) {
            finalsum = res->Clone();
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        } else {
            finalsum = m_cc->EvalAdd(finalsum, res);
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        }

    }

    finalsum = m_cc->EvalRotate(finalsum, num_slots - 1024 * 16);

    return finalsum;
}


Ciphertext<DCRTPoly> CIFAR10CKKS::conv16x16_1(const Ciphertext<DCRTPoly> &in, double scale) {
    vector<Ciphertext<DCRTPoly>> c_rotations;

    c_rotations.push_back(in);
    c_rotations.push_back(m_cc->EvalRotate(in, 1));
    c_rotations.push_back(m_cc->EvalRotate(in, 2));
    c_rotations.push_back(m_cc->EvalRotate(in, 32));
    c_rotations.push_back(m_cc->EvalRotate(in, 33));
    c_rotations.push_back(m_cc->EvalRotate(in, 34));
    c_rotations.push_back(m_cc->EvalRotate(in, 64));
    c_rotations.push_back(m_cc->EvalRotate(in, 65));
    c_rotations.push_back(m_cc->EvalRotate(in, 66));

    Ciphertext<DCRTPoly> finalsum;

    for (int c = 0; c < 16; c++) {
        vector<Ciphertext<DCRTPoly>> k_rows;

        for (int k = 0; k < 9; k++) {
            vector<double> weights = read_values_from_file(m_WeightsDir + "/conv2-ch" + to_string(c) + "-k" + to_string(k) + ".bin", scale);
            Plaintext encoded = encode(weights, in->GetLevel());
            k_rows.push_back(m_cc->EvalMult(c_rotations[k], encoded));
        }
        Ciphertext<DCRTPoly> sum = m_cc->EvalAddMany(k_rows);
        Ciphertext<DCRTPoly> res = sum->Clone();

        Plaintext bias = encode(read_values_from_file(m_WeightsDir + "/conv2-ch" + to_string(c) + "-bias.bin", scale), res->GetLevel());
        for (int i = 0; i < 16; i++) {
            if (i == 0) {
                res = m_cc->EvalAdd(res, bias);
                continue;
            }
            Ciphertext<DCRTPoly> sum_shift = m_cc->EvalRotate(sum, 1024);
            res = m_cc->EvalAdd(res, sum_shift);
            sum = sum_shift;
        }

        Plaintext mask = encode(read_values_from_file(m_WeightsDir + "/conv2-mask.bin", scale), res->GetLevel());
        res = m_cc->EvalMult(res, mask);

        if (c == 0) {
            finalsum = res->Clone();
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        } else {
            finalsum = m_cc->EvalAdd(finalsum, res);
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        }
    }

    return finalsum;
}


Ciphertext<DCRTPoly> CIFAR10CKKS::conv16x16_2(const Ciphertext<DCRTPoly> &in, double scale) {
    vector<Ciphertext<DCRTPoly>> c_rotations;

    c_rotations.push_back(in);
    c_rotations.push_back(m_cc->EvalRotate(in, 1));
    c_rotations.push_back(m_cc->EvalRotate(in, 2));
    c_rotations.push_back(m_cc->EvalRotate(in, 32));
    c_rotations.push_back(m_cc->EvalRotate(in, 33));
    c_rotations.push_back(m_cc->EvalRotate(in, 34));
    c_rotations.push_back(m_cc->EvalRotate(in, 64));
    c_rotations.push_back(m_cc->EvalRotate(in, 65));
    c_rotations.push_back(m_cc->EvalRotate(in, 66));

    Ciphertext<DCRTPoly> finalsum;

    for (int c = 0; c < 16; c++) {
        vector<Ciphertext<DCRTPoly>> k_rows;

        for (int k = 0; k < 9; k++) {
            vector<double> weights = read_values_from_file(m_WeightsDir + "/conv3-ch" + to_string(c) + "-k" + to_string(k) + ".bin", scale);
            Plaintext encoded = encode(weights, in->GetLevel());
            k_rows.push_back(m_cc->EvalMult(c_rotations[k], encoded));
        }
        Ciphertext<DCRTPoly> sum = m_cc->EvalAddMany(k_rows);
        Ciphertext<DCRTPoly> res = sum->Clone();

        Plaintext bias = encode(read_values_from_file(m_WeightsDir + "/conv3-ch" + to_string(c) + "-bias.bin", scale), res->GetLevel());
        for (int i = 0; i < 16; i++) {
            if (i == 0) {
                res = m_cc->EvalAdd(res, bias);
                continue;
            }
            Ciphertext<DCRTPoly> sum_shift = m_cc->EvalRotate(sum, 1024);
            res = m_cc->EvalAdd(res, sum_shift);
            sum = sum_shift;
        }

        Plaintext mask = encode(read_values_from_file(m_WeightsDir + "/conv3-mask.bin", scale), res->GetLevel());
        res = m_cc->EvalMult(res, mask);

        if (c == 0) {
            finalsum = res->Clone();
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        } else {
            finalsum = m_cc->EvalAdd(finalsum, res);
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        }
    }

    return finalsum;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::fc(const Ciphertext<DCRTPoly> &in, double scale) {
    Ciphertext<DCRTPoly> finalsum;
    vector<int> rolls = {8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1};

    for (int i = 0; i < 10; i++) {
        vector<double> weights = read_values_from_file(m_WeightsDir + "/fc-c" + to_string(i) + ".bin", scale);
        Plaintext encoded = encode(weights, in->GetLevel());

        Ciphertext<DCRTPoly> current = m_cc->EvalMult(in, encoded);

        for (int r: rolls)
            current = m_cc->EvalAdd(m_cc->EvalRotate(current, r), current);

        Plaintext mask = encode(read_values_from_file(m_WeightsDir + "/fc-mask.bin", scale), current->GetLevel());
        if (i == 0)
            finalsum = m_cc->EvalMult(current, mask);
        else
            finalsum = m_cc->EvalAdd(finalsum, m_cc->EvalRotate(m_cc->EvalMult(current, mask), -i));

    }

    Plaintext bias = encode(read_values_from_file(m_WeightsDir + "/fc-bias.bin", scale), finalsum->GetLevel());
    finalsum = m_cc->EvalAdd(finalsum, bias);

    return finalsum;
}


Ciphertext<DCRTPoly> CIFAR10CKKS::relu7(const Ciphertext<DCRTPoly> &in, double scale) {
    vector<double> temp;

    Ciphertext<DCRTPoly> in_scale = m_cc->EvalMult(in, scale);
    cout << "Level of in_scale: " << in_scale->GetLevel() << endl;

    vector<double> coeff_1 = {0.0, 7.30445164958251, 0.0, -34.6825871108659, 0.0, 59.8596518298826, 0.0, -31.8755225906466};

    vector<Ciphertext<DCRTPoly>> t(1024);

    t[1] = in_scale;
    cout << "Level of t[1]: " << t[1]->GetLevel() << endl;
    t[2] = m_cc->EvalMult(t[1], t[1]);
    cout << "Level of t[2]: " << t[2]->GetLevel() << endl;
    t[3] = m_cc->EvalMult(t[1], t[2]);
    cout << "Level of t[3]: " << t[3]->GetLevel() << endl;
    t[4] = m_cc->EvalMult(t[2], t[2]);
    cout << "Level of t[4]: " << t[4]->GetLevel() << endl;
    t[5] = m_cc->EvalMult(t[2], t[3]);
    cout << "Level of t[5]: " << t[5]->GetLevel() << endl;
    t[6] = m_cc->EvalMult(t[3], t[3]);
    cout << "Level of t[6]: " << t[6]->GetLevel() << endl;
    t[7] = m_cc->EvalMult(t[3], t[4]);
    cout << "Level of t[7]: " << t[7]->GetLevel() << endl;

    Ciphertext<DCRTPoly> f1 = m_cc->EvalAdd(m_cc->EvalMult(t[1], coeff_1[1]), m_cc->EvalMult(t[3], coeff_1[3]));
    f1 = m_cc->EvalAdd(f1, m_cc->EvalMult(t[5], coeff_1[5]));
    f1 = m_cc->EvalAdd(f1, m_cc->EvalMult(t[7], coeff_1[7]));
    cout << "Level of f1: " << f1->GetLevel() << endl;

    if (depth - f1->GetLevel() - 1 <= 5)
        f1 = m_cc->EvalBootstrap(f1);

    vector<double> coeff_2 = {0.0, 2.40085652217597, 0.0, -2.63125454261783, 0.0, 1.54912674773593, 0.0, -0.331172956504304};

    t[1] = f1;
    cout << "Level of t[1]: " << t[1]->GetLevel() << endl;
    t[2] = m_cc->EvalMult(t[1], t[1]);
    cout << "Level of t[2]: " << t[2]->GetLevel() << endl;
    t[3] = m_cc->EvalMult(t[1], t[2]);
    cout << "Level of t[3]: " << t[3]->GetLevel() << endl;
    t[4] = m_cc->EvalMult(t[2], t[2]);
    cout << "Level of t[4]: " << t[4]->GetLevel() << endl;
    t[5] = m_cc->EvalMult(t[2], t[3]);
    cout << "Level of t[5]: " << t[5]->GetLevel() << endl;
    t[6] = m_cc->EvalMult(t[3], t[3]);
    cout << "Level of t[6]: " << t[6]->GetLevel() << endl;
    t[7] = m_cc->EvalMult(t[2], t[5]);
    cout << "Level of t[7]: " << t[7]->GetLevel() << endl;

    Ciphertext<DCRTPoly> f2 = m_cc->EvalAdd(m_cc->EvalMult(t[1], coeff_2[1]), m_cc->EvalMult(t[3], coeff_2[3]));
    f2 = m_cc->EvalAdd(f2, m_cc->EvalMult(t[5], coeff_2[5]));
    f2 = m_cc->EvalAdd(f2, m_cc->EvalMult(t[7], coeff_2[7]));
    cout << "Level of f2: " << f2->GetLevel() << endl;

    Ciphertext<DCRTPoly> out = m_cc->EvalMult(in, f2);
    cout << "Level of out: " << out->GetLevel() << endl;
    out = m_cc->EvalAdd(out, in);
    cout << "Level of out: " << out->GetLevel() << endl;
    out = m_cc->EvalMult(out, 0.5);
    cout << "Level of out: " << out->GetLevel() << endl;

    if (depth - out->GetLevel() - 1 <= 5)
        out = m_cc->EvalBootstrap(out);

    return out;
}


Ciphertext<DCRTPoly> CIFAR10CKKS::relu4(const Ciphertext<DCRTPoly> &in, double scale) {
    vector<double> temp;

    Ciphertext<DCRTPoly> in_scale = m_cc->EvalMult(in, scale);
    cout << "Level of in_scale: " << in_scale->GetLevel() << endl;

    vector<double> coeff_1 = {0.0, 3.255859375, 0.0, -5.96484375, 0.0, 3.70703125};

    vector<Ciphertext<DCRTPoly>> t(1024);

    t[1] = in_scale;
    cout << "Level of t[1]: " << t[1]->GetLevel() << endl;
    t[2] = m_cc->EvalMult(t[1], t[1]);
    cout << "Level of t[2]: " << t[2]->GetLevel() << endl;
    t[3] = m_cc->EvalMult(t[1], t[2]);
    cout << "Level of t[3]: " << t[3]->GetLevel() << endl;
    t[5] = m_cc->EvalMult(t[2], t[3]);
    cout << "Level of t[5]: " << t[5]->GetLevel() << endl;

    Ciphertext<DCRTPoly> f1 = m_cc->EvalAdd(m_cc->EvalMult(t[1], coeff_1[1]), m_cc->EvalMult(t[3], coeff_1[3]));
    f1 = m_cc->EvalAdd(f1, m_cc->EvalMult(t[5], coeff_1[5]));
    cout << "Level of f1: " << f1->GetLevel() << endl;


    vector<double> coeff_2 = {0.0, 1.5, 0.0, -0.5};

    t[1] = f1;
    cout << "Level of t[1]: " << t[1]->GetLevel() << endl;
    t[2] = m_cc->EvalMult(t[1], t[1]);
    cout << "Level of t[2]: " << t[2]->GetLevel() << endl;
    t[3] = m_cc->EvalMult(t[1], t[2]);
    cout << "Level of t[3]: " << t[3]->GetLevel() << endl;


    Ciphertext<DCRTPoly> f2 = m_cc->EvalAdd(m_cc->EvalMult(t[1], coeff_2[1]), m_cc->EvalMult(t[3], coeff_2[3]));
    cout << "Level of f2: " << f2->GetLevel() << endl;

    vector<double> coeff_3 = {0.0, 1.5, 0.0, -0.5};

    t[1] = f2;
    cout << "Level of t[1]: " << t[1]->GetLevel() << endl;
    t[2] = m_cc->EvalMult(t[1], t[1]);
    cout << "Level of t[2]: " << t[2]->GetLevel() << endl;
    t[3] = m_cc->EvalMult(t[1], t[2]);
    cout << "Level of t[3]: " << t[3]->GetLevel() << endl;

    Ciphertext<DCRTPoly> f3 = m_cc->EvalAdd(m_cc->EvalMult(t[1], coeff_2[1]), m_cc->EvalMult(t[3], coeff_2[3]));
    cout << "Level of f3: " << f3->GetLevel() << endl;

    Ciphertext<DCRTPoly> out = m_cc->EvalMult(in, f3);
    cout << "Level of out: " << out->GetLevel() << endl;
    out = m_cc->EvalAdd(out, in);
    cout << "Level of out: " << out->GetLevel() << endl;
    out = m_cc->EvalMult(out, 0.5);
    cout << "Level of out: " << out->GetLevel() << endl;

    return out;
}


Ciphertext<DCRTPoly> CIFAR10CKKS::relu_square(const Ciphertext<DCRTPoly> &in) {
    return m_cc->EvalMult(in, in);
}