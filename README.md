# ETH 靓号钱包地址生成器 💰

在 Web3 世界冲浪，谁不想要一个靓号呢？ETH 靓号钱包地址生成器是一个 Go 语言编写的工具，用于生成具有 **特定前缀**和 **后缀** 的以太坊钱包地址 🔑。

本项目所有运算均在本地完成，**不能也永远不会存储你生成的内容** 🚫，你可以根据计算机配置的高低自由决定增加线程以达到更快的生成速度 💨，或在计算机运行困难时适当减少线程 😴。

你可以通过命令行参数来控制前缀、后缀和线程数量 🛠️。

## 下载安装 

首先从本项目的 [Releases](https://github.com/cat7373/rare_eth/releases) 中找到符合自己平台的二进制文件下载，下载完成后重命名为 `rare_eth` 📥，如果程序没有可执行权限请手动加一下:

```bash
chmod +x rare_eth
```

## 使用方法

使用命令行运行可执行文件，可指定钱包地址的前缀、后缀和线程数量：

```bash
./rare_eth -p <prefix> -s <suffix> -t <threads> -l <logInterval>
```

参数说明：

- `-p` 或 `--prefix`：需要的钱包地址的前缀，不指定则为不限制。注意字母必须为 A-F 之间的字母，数字无要求 🆔。
- `-s` 或 `--suffix`：需要的钱包地址的后缀，不指定则为不限制。注意字母必须为 A-F 之间的字母，数字无要求 🆔。
- `-t` 或 `--threads`：线程数量，默认为 CPU 核心数⚙️。
- `-l` 或 `--logInterval`：日志输出间隔，默认为 60 秒。

找到满足条件的钱包地址后，程序会输出对应的钱包地址和私钥 🎉。

## 示例

生成一个以 `888` 为前缀，以 `888` 为后缀的 ETH 钱包靓号：

```bash
./rare_eth -p 888 -s 888 -l 10
```

👇 下图为程序运行后输出的结果：

![](https://github.com/user-attachments/assets/11f1fff0-5a26-45dc-9338-01dc333ac1a9)

我们得到了一个 888 开头 888 结尾的靓号 💯

> 你要求的前后缀越长，程序计算需要的时间就越长，如果你想要 8 个 8 这种靓号，推荐使用 tmux 或 screen 这种工具在服务器后台慢慢跑。
>
> 当然，就像上图一样，你运气好的话，可能很快就能生成到一个地址，运气不好的话，可能要多等一会。

## 兼容性

ETH 靓号生成器生成的 ETH 靓号地址均符合 ERC-20 标准，支持 Ethereum、BSC、HECO、Polygon、OKEx、Fantom、Optimism、Avalanche 等网络。
Keystore 文件与 MyEtherWallet、imToken、MetaMask、TokenPocket、Mist 及 geth 完全兼容。

## 贡献

欢迎提交 Issue 或 Pull Request 来完善本项目。在提交 Pull Request 之前，请确保你的代码符合 Go 语言的编码规范。

## 许可证

本项目采用 [MIT 许可证](LICENSE) 授权。
