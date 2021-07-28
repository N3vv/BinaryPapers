## 二进制相关论文收集





### USENIX-2021 Sharing More and Checking Less:
 Leveraging Common Input Keywords to Detect Bugs in Embedded Systems

> https://www.usenix.org/system/files/sec21fall-chen-libo.pdf

- 针对固件中前端和后端server服务器交互，实现了一种静态污点分析工具，可以自动化识别前端和输入相关的关键字并在后端对应到其处理程序，以较低和开销（和当前此类最先进的工具karonte相比）进行污点分析，发现了33个bug，其中33个获得编号



### USENIX-2020 HALucinator: Firmware Re-hosting Through Abstraction Layer Emulation

> https://www.usenix.org/conference/usenixsecurity20/presentation/clements

- 分离固件中的硬件依赖，通过二进制分析在固件中定位库函数，然后在仿真器中提供通用实现
- 现有库匹配技术的扩展，这些技术用于识别二进制固件中的库函数、减少冲突以及推断额外的函数名



### USENIX-2020 PARTEMU: Enabling Dynamic Analysis of Real-World TrustZone Software Using Emulation

> https://www.usenix.org/conference/usenixsecurity20/presentation/harrison

- 模拟仿真硬件和软件组件

- qemu-pdanda 反馈驱动的模糊测试

- TrustZone

  

### USENIX-2020  P2IM: Scalable and Hardware-independent Firmware Testing via Automatic Peripheral Interface Modeling

> https://www.usenix.org/conference/usenixsecurity20/presentation/feng

- 嵌入式固件的动态测试或者模糊测试对硬件依赖比较高，规模化比较困难
- 提出一个软件框架，可以连续执行给定的固件二进制文件，引导现成的fuzzer输入
- 抽象外设，基于自动生成的模型动态的处理固件IO



### USENIX-2020 Everything Old is New Again: Binary Security of WebAssembly

> https://www.usenix.org/conference/usenixsecurity20/presentation/lehmann

- 分析了WebAssembly二进制文件中漏洞可利用的程度
- 常见的缓解措施使得许多经典的漏洞在本地二进制文件中不再可用，而在WebAssembly中完全暴露出来。
- 提供了一组攻击原语，使攻击者(i)能够写入任意内存，(ii)能够覆盖敏感数据，(iii)能够通过转移控制流或操纵主机环境来触发意外行为。我们提供了一组易受攻击的概念验证应用程序以及完整的端到端利用，涵盖了三个WebAssembly平台
- 讨论了潜在的保护机制



### USENIX-2020  Analysis of DTLS Implementations Using Protocol State Fuzzing

> https://www.usenix.org/conference/usenixsecurity20/presentation/fiterau-brostean

- 状态机-协议fuzz

  

### NDSS-2020 HYPER-CUBE: High-Dimensional Hypervisor Fuzzing

> https://www.ndss-symposium.org/ndss-paper/hyper-cube-high-dimensional-hypervisor-fuzzing/

- fuzz 虚拟机管理程序
- 34个cve
- 评估结果表明，下一代覆盖导向模糊器应该为长时间运行的目标(如管理程序)包含更高吞吐量的设计。



### NDSS-2019 REDQUEEN: Fuzzing with Input-to-State Correspondence

> https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/

- 能够为给定的二进制可执行文件自动解决magic字节和(嵌套的)校验和测试
- REDQUEEN是第一个发现所有目标中超过100%植入LAVA-M的bug的方法
- 发现了65个新的bug和16个cve
- 在输入和当前程序状态之间存在很强的输入到状态的对应关系。



### NDSS-2019 One Engine To Serve 'em All: Inferring Taint Rules Without Architectural Semantics

> https://www.ndss-symposium.org/ndss-paper/one-engine-to-serve-em-all-inferring-taint-rules-without-architectural-semantics/

- 动态二进制分析中的关键挑战之一是指定污染规则，这些规则捕获了体系结构上每条指令的污染信息传播方式。大多数现有解决方案使用演绎方法指定污染规则，在分析指令语义后手动总结规则
- 我们提出了一个污点传播的归纳方法，并开发了一个通用的污点跟踪引擎，它与架构无关，可以通过观察指令的执行行为，用最少的架构知识学习污染规则。



### NDSS-2019  Neural Machine Translation Inspired Binary Code Similarity Comparison beyond Function Pairs

> https://www.ndss-symposium.org/ndss-paper/neural-machine-translation-inspired-binary-code-similarity-comparison-beyond-function-pairs/

- 二进制代码相似性比对
- 机器学习
  - 给不同指令集架构的一对基本块，确定它们的语义是否相似
  - 给定感兴趣的一段代码，确定它是否包含在来自不同架构的另一段汇编代码中



### NDSS-2018 IOTFUZZER:Discovering Memory Corruptions in IoT Through App-based Fuzzing

> https://blog.csdn.net/qq_32505207/article/details/104389266



### S&P-2019 Iodine: Fast Dynamic Taint Tracking Using Rollback-free Optimistic Hybrid Analysis

> https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/19skfUgAmBi/pdf

- 动态污点分析、静态分析结合回滚

  

### S&P-2021 DICE: Automatic Emulation of DMA Input Channels for Dynamic Firmware Analysis

> https://arxiv.org/pdf/2007.01502v1.pdf

- DMA仿真

- 发现更多路径，发现5个新bug



### S&P-2021 SoK: All You Ever Wanted to Know About x86/x64 Binary Disassembly But Were Afraid to Ask

> https://arxiv.org/pdf/2007.14266v1.pdf

- 评估不同反汇编算法以及启发式规则对二进制代码反汇编的影响


### S&P-2020 Karonte: Detecting Insecure Multi-binary Interactions in Embedded Firmware

> https://github.com/ucsb-seclab/karonte

- 静态污点分析
- 多二进制文件分析
- 漏洞挖掘



### SoK: Using Dynamic Binary Instrumentation for Security (And How You May Get Caught Red Handed)

> https://www.diag.uniroma1.it/~delia/papers/asiaccs2019.pdf

- 动态二进制插装技术综述



### CCS-2019 Different is Good: Detecting the Use of Uninitialized Variables through Differential Replay

- 关键技术： 
  - 动态运行->静态分析
  - 差分重放 Panda 



### CCS 2020 FirmXRay: Detecting Bluetooth Link Layer Vulnerabilities From Bare-Metal Firmware

> http://web.cse.ohio-state.edu/~lin.3021/file/CCS20.pdf

- 蓝牙固件
- 静态分析
- 提出了一种提取蓝牙固件的方式，还可以通过函数签名识别数据结构



### RAID-2020 Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities

> https://arxiv.org/pdf/2002.10751.pdf

- fuzz UAF漏洞
- 针对UAF漏洞细节定制的fuzz（灰盒）



### ACSAC-2019 Function Boundary Detection in Stripped Binaries

> https://dl.acm.org/doi/pdf/10.1145/3359789.3359825

- 函数边界识别



### ACSAC-2019 HDMI-Walk: Attacking HDMI Distribution Networks via Consumer Electronic Control Protocol

> https://arxiv.org/abs/1910.02139

- 针对hdmi接口中ecc协议的攻击和研究
- 拓扑探测
- dos
- 窃取音频



### ACSAC-2019 SRFuzzer: an automatic fuzzing framework for physical SOHO router devices to discover multi-type vulnerabilities

> https://dl.acm.org/doi/pdf/10.1145/3359789.3359826

- 家用、办公路由
- 内存破坏漏洞、com命令注入漏洞、跨站脚本攻击(XSS)漏洞和信息泄露漏洞
- 直接测试物理设备，模拟电源开关重启卡死设备
- 设计了六种变异规则和三种监测机制。当模糊测试一个给定类型的漏洞时，选择适当的变异规则和监控机制
