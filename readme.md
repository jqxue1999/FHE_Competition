
```
cd openfhe

mkdir keys temp data

mkdir build & cd build

cmake ..
make
./app --key_pub ../keys/public-key.txt --key_mult ../keys/mult-key.txt --key_rot ../keys/rot-key.txt --input ../inputs/input.txt --output ../inputs/output.txt --mode gen --cc crypto-context.txt
```