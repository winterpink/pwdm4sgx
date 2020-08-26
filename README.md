# pwdm4sgx
A more Efficient and Safe password manager with Scrypt on Linux powered by Intel SGX.

## 演示

请下载查看源码中的`pre.mp4`

## 使用文档

1. 首先需要安装SGXSDK，运行版本需要指定2.9.1版本，然后安装JHI工具集合。

2. 需要为每个安全飞地生成签名

```bash
$ openssl genrsa -out Enclave/Enclave_private.pem -3 3072
```

3. 需要使用scrypt加密算法生成派生密钥.txt文件

4. 生成之后需要在每个`Encalve.cpp`文件中加密部分指定该密钥

5. 将编译文件`makefile`编译模式改为`SIM`模拟运行

6. 将编译文件`makefile`中环境路径进行更改

7. 生效配置

```bash
$ source /opt/intel/sgxsdk/environment
```

8. 输入`make`指令编译程序

9. 输入`./app`运行程序

10. 输入`help`获得可使用的命令

11. 输入`send ping`进行本地认证备份数据

12. 其他命令请根据提示使用

## 注意

- 如果遇到`buff error`，说明你的CPU没有可用`buff`，不是程序问题
- 如果遇到内存溢出错误，请修改`enclave`最大内存分配空间

## 说明

该程序大部分库函数为官方开源的，且几乎所有编写格式需要根据开发文档指定格式开发，因此改动较大的部分只有安全飞地编码部分，其他部分调用的函数需要严格规定。

