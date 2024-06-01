#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // 初始化加密参数
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetScalingModSize(60);
    parameters.SetScalingFactorBits(50);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(8192);
    parameters.SetMultiplicativeDepth(32);

    // 创建加密上下文
    auto cc = GenCryptoContext(parameters);
    cc->Enable(ENCRYPTION);
    cc->Enable(SHE);

    // 密钥生成
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // 加密一个示例数据
    std::vector<double> vec = {1.23, 4.56, 7.89};
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(vec);
    auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // 执行一些操作
    auto ciphertextMult = cc->EvalMult(ciphertext, ciphertext);

    // 获取当前噪声预算
    auto noiseBudget = ciphertextMult->GetNoiseScaleDeg();
    std::cout << "Current noise budget: " << noiseBudget << std::endl;

    return 0;
}
