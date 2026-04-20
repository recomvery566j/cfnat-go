源代码为股神频道的go源码。https://t.me/CF_NAT/39004
功能实现和代码与股神的cfnat一致，但是增加了udp支持
现在的cfnat，可以同时代理1234（默认端口）的tcp（h2）和udp（h3）
实测，h3的峰值速度不如h2，但是延时会比h2低很多（美西+cf香港），h3-182，h2-200.
我只用actions，编译出了64位的Linux版本和64位的电脑版本，其余版本没有编译也没有测试
电脑版本可以直接替换这个项目的同名文件https://github.com/cmliu/CFnat-Windows-GUI （win7未测试未专门编译，我win10可以替换）
可以去actions下载编译产物，也可fork后手动编译执行。
