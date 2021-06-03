# Process-Injection
>  目前网上进程注入的文章很多，但是代码质量参差不齐，很多还只有x86下的代码，同时对于进程注入的探讨大多停留在各种注入手法上，缺少系列的汇总性的研究文章，故想要在本项目中汇总所有可以接触到的进程注入的手法，自行研究复现总结成文章，同时会将调试好的可执行的代码贴出，完成对x86/x64版本的测试，以此来促进自己的学习，同时也欢迎师傅们提Issue，一起交流讨论~



## 开发环境

- 操作系统：Windows 10
- IDEA：Visual Studio 2019

**注：项目内所有代码均经过测试，确保x86/x64下均可用，并能实现注入效果, 使用时请修改Dll路径**



## 原理分析

详细的原理分析和代码的拆解分析，听说，学进程注入，代码和文章一起更配哟~欢迎催更hhhhh~

|        | 题目               | 手法                           | 链接                                              | 完成 |
| ------ | ------------------ | ------------------------------ | ------------------------------------------------- | ---- |
| 第一课 | 进程提权原理       | 获取SE_DEBUG权限               | https://mp.weixin.qq.com/s/NkJOfiRIBnqyzVh3_fE22Q | √    |
| 第二课 | 远程线程注入       | 最经典的进程注入手法           | https://mp.weixin.qq.com/s/7lHqfWrewgiVtTXGhVXfQA | √    |
| 第三课 | 远程线程注入进阶   | 利用未导出API躲避杀软          | https://mp.weixin.qq.com/s/0zBPrC42zB6fkDZAEn92ww | √    |
| 第四课 | 远程线程注入进阶二 | 用类似调试器的思想来注入       | https://mp.weixin.qq.com/s/O80hGlJWRMkH-r1SoWzE8A | √    |
| 第五课 | 创建进程挂起注入   | 以CREATE_SUSPENDED标志创建进程 | https://mp.weixin.qq.com/s/QifTJZGg4dtO9YtSv8a5Ug | √    |
| 第六课 | APC注入            | 用户态下APC注入方式            | 3天内更新                                         |      |
| 第七课 | APC注入进阶        | 内核态下APC注入方式            | 1周内更新                                         |      |
| ...    | ...                | ...                            | ...                                               |      |

至少是10节~会持续更新的



## issue

[我要提交建议或问题](https://github.com/Gality369/Process-Injection/issues)



## LICENSE

[GNU General Public License v3.0](https://github.com/Gality369/Process-Injection/blob/main/LICENSE)



## 关于其他

如果你觉得这个项目不错，请给我一个Star～

也宣传下团队~🎉**Wgpsec狼组安全团队**~致力于构建安全安全乌托邦 => https://www.wgpsec.org/

也欢迎关注公众号，一起来交流讨论学习q(≧▽≦q)~

