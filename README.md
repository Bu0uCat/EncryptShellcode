# EncryptShellcode
这是一个对shellcode进行加密的程序，支持的加密方式有AES256、RC4以及XOR。<br>
This is a program for encrypting shellcode, and it supports three encryption methods: AES256, RC4 and XOR.


# 声明
这只是一个简单的对shellcode加密的程序，方便在制作免杀的时候找各种工具进行转换。本程序简单整合了AES256、RC4、XOR三种加密方式对shellcode进行加密。<br>
This is merely a simple program for encrypting shellcode, which facilitates the use of various tools to convert it when creating anti-detection versions. This program simply integrates three encryption methods: AES256, RC4, and XOR, to encrypt the shellcode.

# AES256
本项目使用的AES加密使用的项目为https://github.com/kokke/tiny-AES-c<t>模式为CBC模式，如需使用其他模式可以对代码进行修改，同时添加了padding操作,填充方式为PKCS#7。<br>
The AES encryption used in this project uses https://github.com/kokke/tiny-AES-c. The mode is CBC mode. If you need to use other modes, you can modify the code. At the same time, a padding operation is added, and the padding method is PKCS#7.

# Encrypt
Usage: EncryptShllcode.exe payload.bin [Option] (AES、RC4、XOR)

EncryptShllcode.exe  calc.bin AES 
<img width="1837" height="1115" alt="图片" src="https://github.com/user-attachments/assets/86908d2b-536e-40dc-8aea-b03f11880f27" />

EncryptShllcode.exe  calc.bin XOR
<img width="1924" height="955" alt="图片" src="https://github.com/user-attachments/assets/ed5512b1-5f44-4291-89ca-a104ba29549f" />

EncryptShllcode.exe  calc.bin RC4
<img width="1793" height="1021" alt="图片" src="https://github.com/user-attachments/assets/6874f1b6-cb04-49b6-8963-52230bc6c3ae" />

# Decrypt
如果熟悉加解密的话可以自己写程序进行解密，从而调用shellcode，或者使用我提供的Decrypt文件夹下的代码进行修改后调用。<br>
If you are familiar with encryption and decryption, you can write your own program to decrypt and call the shellcode, or use the code in the Decrypt folder I provided and modify it before calling it.<br>

![PixPin_2025-08-27_14-47-53](https://github.com/user-attachments/assets/f17484b3-4145-44ba-a8d1-5586fb259f89)

![RC4](https://github.com/user-attachments/assets/80be9d96-b1ca-4dd8-be53-6db3e262a452)

![PixPin_2025-08-27_14-48-42](https://github.com/user-attachments/assets/fdb4cda2-85cc-4d9c-980e-d18644929c1a)
