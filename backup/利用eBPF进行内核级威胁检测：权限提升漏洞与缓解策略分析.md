

# **利用eBPF进行内核级威胁检测：权限提升漏洞与缓解策略分析**

**执行摘要**

eBPF（扩展伯克利数据包过滤器）技术代表了内核安全领域的一次范式转换，为操作系统提供了前所未有的可观测性和强制执行能力。然而，其强大的功能和日益增加的复杂性也引入了新的攻击向量和防御挑战。本报告旨在对使用eBPF检测内核权限提升漏洞进行全面而深入的研究，为技术决策者和安全工程师提供战略评估和实施规划的依据。

本报告首先阐述了eBPF的核心架构、安全机制及其生态系统，强调了其作为安全内核可编程平台的潜力。随后，报告深入剖析了内核权限提升攻击的解剖学，重点分析了释放后使用（Use-after-Free, UAF）、竞争条件（Time-of-Check to Time-of-Use, TOCTOU）以及凭证结构直接操纵等关键漏洞的利用链。

在此基础上，报告详细阐述了eBPF的多种检测方法论，包括如何利用kprobes、tracepoints和Linux安全模块（LSM）钩子来精确观测这些攻击手法的原子操作和行为模式。报告对当前主流的eBPF安全工具（如Cilium Tetragon、Aqua Tracee和Sysdig Falco）进行了深入的架构对比分析，评估了它们在性能、检测哲学和与云原生环境集成方面的差异。

此外，报告还从攻击者的视角审视了eBPF技术的双刃剑效应，分析了其被用于构建复杂根キット（rootkit）和逃避检测的潜力，并提出了相应的防御策略。最后，报告展望了eBPF与机器学习结合进行异常检测等前沿领域，并提出了一系列战略性建议，旨在帮助组织机构构建基于eBPF的、分层且稳健的内核安全防御体系。

---

## **第1节 eBPF框架：安全内核可编程性的新范式**

### **1.1 架构概述：从cBPF到eBPF**

eBPF的出现被广泛认为是操作系统领域的一场革命，其地位类似于JavaScript之于Web 1。要理解其深刻影响，必须追溯其技术演进的根源。eBPF的前身是经典伯克利数据包过滤器（cBPF），该技术诞生于20世纪90年代，主要用于高效地过滤网络数据包，例如在

tcpdump等工具中 2。然而，cBPF的功能相对单一，其虚拟机仅包含少数几个寄存器和有限的指令集。

随着云计算和大规模分布式系统的兴起，对内核进行动态、安全扩展的需求日益迫切。传统的内核扩展方式，如加载内核模块（LKM），虽然功能强大，但存在巨大的安全风险——一个有缺陷的模块就可能导致整个系统崩溃 3。而直接修改内核源码则因其复杂性和部署困难，在规模化环境中几乎不具备可行性 4。

eBPF正是在这一背景下应运而生，于Linux内核3.18版本（2014年）被引入，并在此后不断发展壮大 4。它将cBPF的概念从一个简单的过滤器扩展为一个通用的、位于内核中的高效虚拟机。这个虚拟机允许开发人员编写的、经过安全验证的沙盒程序在内核空间内运行，从而在不修改内核源码或加载内核模块的情况下，安全地扩展内核功能 1。

eBPF的核心价值在于其事件驱动模型。eBPF程序并非持续运行，而是在特定的内核事件（即钩子点）被触发时执行 1。这些钩子点遍布内核的关键路径，包括系统调用（syscalls）的入口和出口、内核函数（kprobes）和用户函数（uprobes）的调用、静态定义的跟踪点（tracepoints）、网络事件（XDP, TC）等 1。这种机制使得eBPF能够在系统最底层的执行路径上获得无与伦比的可见性和控制力，成为实现高性能网络、深度可观测性和细粒度安全策略的理想技术。

### **1.2 核心组件：eBPF虚拟机、JIT编译器与Maps**

eBPF的强大功能由几个核心组件协同实现，这些组件共同构成了一个既安全又高效的内核执行环境。

* **eBPF虚拟机 (VM)**：这是eBPF技术的核心，一个在内核内部实现的、基于寄存器的虚拟机。它拥有一个精简指令集（RISC-like），包含11个64位通用寄存器（R0-R10）、一个程序计数器和一个512字节的固定大小栈 7。R10是只读的栈指针，用于访问栈帧；R0则用于存放函数调用的返回值和程序的退出码。这种精简的设计使得eBPF指令易于分析和验证。  
* **即时编译器 (Just-In-Time, JIT)**：为了实现极致的性能，eBPF并不仅仅以解释模式运行字节码。当一个eBPF程序通过验证后，内核中的JIT编译器会将其通用的eBPF字节码动态地编译成目标CPU架构的原生机器码 1。这意味着eBPF程序的执行速度可以接近于原生编译的内核代码，这对于处理每秒数百万数据包的网络应用或进行全系统范围的性能追踪至关重要。  
* **eBPF Maps**：eBPF程序本身是无状态的，且其生命周期与触发事件绑定。为了在多次调用之间保存状态、聚合数据以及在内核态与用户态之间进行通信，eBPF引入了Maps机制 1。eBPF Maps是一种通用的键值对数据结构，存在于内核空间，但可以被用户态程序通过文件描述符访问 2。eBPF支持多种类型的Map，如哈希表（  
  BPF\_MAP\_TYPE\_HASH）、数组（BPF\_MAP\_TYPE\_ARRAY）、性能事件缓冲区（BPF\_MAP\_TYPE\_PERF\_EVENT\_ARRAY）和环形缓冲区（BPF\_MAP\_TYPE\_RINGBUF），以满足不同的数据存储和通信需求。

### **1.3 eBPF生态系统：编译器、库与加载器**

一个强大的技术离不开一个繁荣的生态系统。eBPF的发展得益于一系列成熟的开发工具和库，它们极大地降低了开发者的入门门槛。

* **编译工具链**：eBPF程序的开发流程通常始于编写高级语言代码。目前，主流的开发语言是C的一个受限子集，使用LLVM/Clang编译器套件将其编译成包含eBPF字节码的ELF（Executable and Linkable Format）目标文件 9。自GCC 10版本起，GCC也提供了对eBPF后端的支持 11。这个ELF文件不仅包含程序代码，还包含了Map的定义、重定位信息以及BTF元数据。  
* **用户态库与加载器**：用户态应用程序负责将编译好的eBPF程序加载到内核中。这个过程由专门的库来简化，如C/C++的libbpf、Go语言的libbpf-go和cilium/ebpf、以及Rust语言的aya 11。这些库封装了与内核  
  bpf(2)系统调用交互的复杂细节，包括解析ELF文件、创建Maps、根据重定位信息调整代码、以及将程序附加到指定的钩子点 7。  
* **CO-RE (一次编译，到处运行)**：在eBPF早期，一个主要痛点是可移植性问题。由于不同版本的Linux内核其数据结构（如task\_struct）的定义可能存在差异，为一个内核版本编译的eBPF程序往往无法在另一个版本上运行。CO-RE机制的出现解决了这一难题 8。它依赖于BPF类型格式（BPF Type Format, BTF），这是一种将内核和eBPF程序中类型信息的调试信息以紧凑格式编码的技术 4。当加载一个启用了CO-RE的eBPF程序时，加载器（如  
  libbpf）会利用内核提供的BTF信息，在加载时动态地调整程序中对结构体成员的访问偏移量 4。这使得单个编译的eBPF程序二进制文件能够在不同内核版本上正确运行，极大地提升了eBPF应用的可维护性和部署便利性。

eBPF的整体架构设计，从安全的沙盒环境、高性能的JIT编译器，到丰富的API（辅助函数和Maps），都与Web技术中JavaScript的成功要素惊人地相似。JavaScript需要安全地在浏览器中运行不受信任的代码，eBPF则需要安全地在内核中运行来自用户态的代码，两者都需要一个强大的沙盒机制。JavaScript通过JIT编译器实现了高性能，以支持复杂的Web应用；eBPF同样利用JIT来满足线速网络处理和全系统追踪的性能要求 1。JavaScript通过DOM API与浏览器环境交互，而eBPF则通过Maps和一系列内核定义的辅助函数（helper functions）与内核交互 1。这种架构上的趋同性预示着eBPF生态系统可能会经历与Web相似的演化路径：库和框架的爆发式增长、复杂性的提升，以及一场持续的安全攻防“军备竞赛”。新功能的加入在扩展能力的同时，也可能扩大攻击面，要求防御体系不断进化。eBPF最初作为一种简单、安全的内核扩展，正在演变为一个功能强大、但潜在风险也随之增加的内核内应用平台。

---

## **第2节 攻击者视角：内核权限提升的解剖学**

理解如何使用eBPF进行防御，首先必须深入理解攻击者试图实现的目标以及他们所利用的漏洞机制。内核权限提升（Local Privilege Escalation, LPE）并非单一动作，而是一个环环相扣的利用链，其最终目标通常是获得系统的最高控制权。

### **2.1 终极目标：操纵进程凭证（cred结构体）**

在Linux系统中，一个进程的权限由其凭证（credentials）决定。这些信息存储在内核数据结构task\_struct中，该结构是内核对进程的完整描述 13。其中，与权限直接相关的成员是

cred和real\_cred指针，它们指向一个struct cred结构。这个结构体包含了进程的所有安全上下文，如用户ID（UID）、组ID（GID）、补充组、以及更细粒度的能力（Capabilities）集 13。

绝大多数LPE攻击的最终目的，就是通过某种方式修改当前进程的cred结构，将其UID和GID都设置为0，即root用户的权限。为了合法地完成这一操作，内核提供了两个关键函数：prepare\_kernel\_cred()和commit\_creds() 14。

* prepare\_kernel\_cred(NULL)：当以NULL作为参数调用时，这个函数会分配并返回一个新的、拥有完整权限（即root权限）的cred结构。  
* commit\_creds()：这个函数接收一个cred结构作为参数，并将其应用到当前进程，从而完成权限的变更。

因此，攻击者的圣杯就是找到一种方法，在内核模式下执行commit\_creds(prepare\_kernel\_cred(NULL))这行代码。任何能够实现这一点的漏洞，都意味着完整的系统沦陷。

### **2.2 内存破坏原语：释放后使用（UAF）漏洞**

释放后使用（Use-after-Free, UAF）是一类非常危险的内存损坏漏洞。它发生在程序释放了一块内存后，却继续通过一个悬垂指针（dangling pointer）来使用这块已被释放的内存 15。由于内存分配器可能会将这块内存重新分配给其他对象，攻击者可以利用这一点来实现对内核内存的控制。

一个典型的内核UAF漏洞利用过程可以分解为以下几个步骤，以一个存在漏洞的内核模块vuln.ko为例进行说明 15：

1. **触发UAF条件**：攻击的第一步是创造一个悬垂指针。这通常需要利用漏洞代码中的逻辑缺陷。在vuln.ko的案例中，一个竞争条件漏洞允许两个线程同时打开设备文件，导致它们获得指向同一块内核内存（由kzalloc分配）的文件描述符。当其中一个线程关闭其文件描述符时，内核会调用kfree释放这块内存。然而，另一个线程的文件描述符依然指向这块已被释放的内存地址，这就形成了一个悬垂指针，即UAF条件 15。  
2. **堆喷射（Heap Spraying）**：在目标内存被释放后，它就成了一个“空位”，可以被内存分配器（如SLUB）重新利用。攻击者会立即进行“堆喷射”，即大量地、重复地请求分配特定大小和类型的内核对象（例如，通过反复打开/dev/ptmx来分配tty\_struct对象） 15。其目的是让其中一个新分配的、攻击者可控的对象“恰好”占据刚刚被释放的内存空位。  
3. **类型混淆与原语构建**：一旦堆喷射成功，悬垂指针现在就指向了一个类型不同但由攻击者部分控制的新对象（如tty\_struct）。攻击者此时通过悬垂指针（例如，通过对旧的文件描述符进行write操作）写入数据，实际上是在修改新对象的内存内容。这种将A类型的指针用于访问B类型对象的行为被称为“类型混淆”。攻击者可以精确计算偏移量，覆盖新对象中的关键数据，例如函数指针。通过覆盖函数指针，攻击者可以将程序的控制流劫持到一个他可以控制的地方，从而构建起更强大的利用原语，如任意地址读（Arbitrary Address Read, AAR）和任意地址写（Arbitrary Address Write, AAW） 15。  
4. **实现权限提升**：拥有了AAR/AAW原语后，攻击者就几乎拥有了对内核的完全控制。他们可以使用这些原语来实现最终目标。一种常见且相对稳定的技术是覆盖内核中的modprobe\_path变量，该变量定义了当内核需要加载模块时执行的程序路径。攻击者将其修改为指向一个自己控制的脚本（如/tmp/x），然后通过触发一个需要加载模块的操作（例如执行一个格式无法识别的文件），来以root权限执行自己的代码 15。另一种更直接的方式是构建一个返回导向编程（Return-Oriented Programming, ROP）链，直接在内核中调用  
   commit\_creds(prepare\_kernel\_cred(NULL))。

### **2.3 并发缺陷：利用竞争条件（TOCTOU）**

竞争条件（Race Condition）是另一类常见的内核漏洞，尤其是一种被称为“检查时-使用时”（Time-of-Check to Time-of-Use, TOCTOU）的子类型 19。这类漏洞的根源在于，一个程序在执行一个操作前检查某个条件（例如，文件权限），但在检查完成之后、实际使用资源之前，系统的状态被另一个并发的线程所改变，导致最初的检查失效 19。

在内核中，TOCTOU漏洞经常发生在内核代码需要多次从用户空间内存读取数据时 20。由于用户空间内存可以被用户进程随时修改，一个精心设计的攻击程序可以在一个CPU核心上运行内核代码，同时在另一个CPU核心上运行一个线程，专门用于在内核两次读取的间隙修改那块用户内存 15。

一个典型的TOCTOU攻击场景如下：一个内核驱动程序首先从用户空间读取一个长度值，以确定需要分配多大的内核缓冲区。然后，它再次从用户空间读取实际的数据，并使用memcpy将其复制到新分配的缓冲区中。攻击者可以利用竞争条件，在第一次读取时提供一个很小且合法的值（例如8字节），使内核分配一个很小的缓冲区。紧接着，在内核执行memcpy之前，攻击者线程迅速将用户空间中的长度值修改为一个非常大的值（例如1024字节）。当内核第二次读取长度并执行memcpy时，就会试图将1024字节的数据复制到一个只有8字节的缓冲区中，从而导致内核堆栈或堆的缓冲区溢出 20。

这种从低级漏洞（如竞争条件）到中级原语（如UAF或缓冲区溢出），再到高级原语（AAR/AAW），最终实现权限提升的利用链，揭示了内核攻击的层次化本质。这一本质对于设计防御策略具有深远的指导意义。一个稳健的eBPF防御体系不应仅仅满足于在终点线（如commit\_creds调用）设置监控。尽管这是有价值的最后一道防线，但一个更先进的系统应该致力于在利用链的更早阶段进行检测。例如，可以设计eBPF程序来识别异常的堆喷射行为（一个进程在短时间内大量分配同一种对象），或者通过监控RCU（Read-Copy-Update）宽限期等底层同步原语的活动来发现TOCTOU竞争的迹象 16。这种思路在检测逻辑内部构建了一个“纵深防御”模型，极大地增加了攻击者成功的难度。

---

## **第3节 eBPF验证器：安全的基石及其局限性**

eBPF之所以能够被接纳并集成到Linux内核这一核心组件中，其关键在于一套严格的安全保障机制，而这套机制的核心就是eBPF验证器（Verifier）。验证器是一个静态分析引擎，任何eBPF程序在被加载到内核并附加到钩子点之前，都必须通过它的审查 1。验证器的设计目标是“证明”程序是安全的，而不是检查程序“做什么” 1。

### **3.1 验证过程：控制流与内存访问的静态分析**

验证器在加载时对eBPF字节码执行一系列严格的检查，以确保其不会对内核造成危害。主要检查项包括：

1. **权限检查**：默认情况下，只有特权进程（root或拥有CAP\_BPF能力的进程）才能加载eBPF程序。如果系统开启了非特权eBPF（unprivileged\_bpf\_disabled=0），普通用户也可以加载eBPF程序，但其功能会受到极大限制，例如无法访问任意内核内存 1。  
2. **终止保证（无无限循环）**：验证器通过分析程序的控制流图（Control Flow Graph, CFG），构建一个有向无环图（Directed Acyclic Graph, DAG）来确保程序中不存在后向跳转（back-edge），从而从根本上禁止了无限循环 1。这保证了任何eBPF程序都能在有限的指令数内执行完毕，防止其永久占用CPU导致内核锁死。从Linux 5.3版本开始，eBPF支持有界循环（bounded loops），但前提是验证器必须能够静态地证明循环的退出条件必然会达成 1。  
3. **有效内存访问**：这是验证器最复杂也最关键的任务之一。它确保程序不会访问其权限范围之外的内存，也不会读取未初始化的变量 1。例如，对栈的访问必须在\`。

### **3.2 类型与状态追踪：确保指针和数据的完整性**

为了实现对内存访问的精确验证，验证器会模拟eBPF程序所有可能的执行路径。在这个过程中，它会细致地追踪每个指令执行后，11个寄存器和栈空间的状态变化 7。

* **寄存器状态 (bpf\_reg\_state)**：验证器为每个寄存器维护一个bpf\_reg\_state结构。该结构记录了寄存器的类型，例如是SCALAR\_VALUE（不能作为指针解引用的标量值），还是PTR\_TO\_MAP\_VALUE、PTR\_TO\_PACKET等指针类型 12。此外，它还追踪指针的固定偏移量以及一个可能的可变偏移量范围。  
* **防止内核指针泄露**：追踪指针类型是防止内核地址泄露给用户空间的关键。当eBPF程序对一个指针执行了某些算术运算（如乘法）后，验证器可能会将其类型“降级”为SCALAR\_VALUE。这样一来，即使该寄存器中仍然包含一个有效的内核地址，程序也无法再通过它来解引用内存，从而阻止了信息泄露 12。在更严格的“安全模式”（secure mode）下，验证器甚至会禁止对指针进行任何算术运算 12。

### **3.3 脆弱的信任：历史验证器绕过漏洞（CVE）分析**

尽管验证器是eBPF安全模型的核心，但它本身也是一个由超过一万行C代码构成的复杂软件 2，因此不可避免地成为了一个攻击面。历史证明，验证器中的漏洞是真实存在的，并且一旦被利用，后果可能是灾难性的，通常会导致权限提升 5。

许多验证器漏洞的根源在于其对寄存器值范围和状态进行推断的复杂逻辑中，尤其是在处理ALU（算术逻辑单元）操作和类型转换时 5。验证器并非形式化验证的产物，它本质上是实现了一个禁止行为的“黑名单”。这意味着，任何设计者未曾预料到的攻击路径，都可能成为一个绕过验证器的漏洞 8。

案例研究1：find\_equal\_scalars中的整数溢出 25

在2024年由NCC集团进行的一次安全审计中，发现了一个高危漏洞。该漏洞存在于验证器处理32位加法运算的逻辑中，一个精心构造的程序可以利用整数溢出，欺骗验证器，最终获得任意内核内存读写的能力。这个案例表明，即使是核心的算术操作清理（sanitization）逻辑，也可能存在细微而致命的缺陷。  
案例研究2：寄存器边界跟踪错误 (GHSA-hfqc-63c7-rj9f)  
Google的研究人员通过模糊测试发现了一个验证器在跟踪寄存器边界时的漏洞 27。攻击者可以通过一系列精巧的位运算和条件分支，使得验证器在静态分析时对某个寄存器的值范围的判断，与该寄存器在实际执行时的真实值产生偏差。这种“状态不一致”使得攻击者可以绕过安全检查，实现内核内存的读写。  
下表总结了一些值得注意的验证器漏洞，突显了其作为攻击面的持续风险。

**表1：部分eBPF验证器历史漏洞**

| CVE / ID | 漏洞类别 | 最终影响 | 来源 |
| :---- | :---- | :---- | :---- |
| CVE-2022-23222 | 不当输入验证 | 权限提升 | 26 |
| (NCC-E015561-JJX) | 32位加法处理不当 | 任意内核内存读写 | 25 |
| GHSA-hfqc-63c7-rj9f | 寄存器边界跟踪错误 | 任意内核内存读写 | 27 |
| CVE-2021-3490 | ALU范围跟踪不当 | 权限提升、信息泄露 | 5 |

这些漏洞揭示了一个根本性的矛盾：一方面，社区和行业希望eBPF拥有更强大的功能，如CO-RE、有界循环、更复杂的辅助函数等 1。另一方面，支持这些高级功能不可避免地导致验证器的逻辑变得愈发复杂 4。复杂性的增加是滋生软件缺陷的温床，尤其是在C语言这样对内存安全要求苛刻的环境中。安全审计和模糊测试虽然在不断发现并修复漏洞，但它们总是在追赶不断膨胀的复杂性 25。

因此，eBPF验证器正处在一个可能不可持续的发展轨迹上。它正在成为一个复杂性与整个eBPF生态系统的雄心同步增长的单点故障。这强烈地表明，未来的安全模型不能、也不应仅仅依赖验证器的完美无缺。纵深防御策略至关重要，这包括：严格控制能够加载eBPF程序的权限（CAP\_BPF）、对可疑的BPF活动进行监控，以及探索新的硬件辅助隔离技术。验证器是一个至关重要的*安全*工具，但将其视为一个绝对可靠的*安全边界*，是一个危险的假设 1。

---

## **第4节 检测机制：为安全可观测性插桩内核**

eBPF为内核防御提供了丰富的工具箱，其核心在于能够通过不同的钩子机制在内核的关键路径上进行插桩（instrumentation），从而实现对系统行为的深度观测乃至主动干预。选择合适的钩子是设计高效eBPF安全策略的第一步。

### **4.1 选择正确的钩子：Tracepoints、Kprobes与LSM的比较分析**

eBPF提供了多种类型的钩子，每种都有其独特的优势和适用场景。

* **Tracepoints（跟踪点）**：是由内核开发者预先在代码中定义好的静态钩子点 29。它们通常位于稳定且有明确语义的位置（如系统调用的入口/出口）。作为一种稳定的API，Tracepoint在不同内核版本之间保持良好的一致性，是构建可移植eBPF工具的首选 29。其主要缺点是数量和位置有限，如果开发者没有在某个关键函数中预置Tracepoint，就无法在此处挂载程序 29。此外，还有一种  
  raw\_tracepoint，它提供了对事件原始参数的访问，性能略高，但需要eBPF程序自行从寄存器中解析参数，增加了编程的复杂性 29。  
* **Kprobes（内核探针）**：是一种动态跟踪机制，允许将eBPF程序附加到内核中几乎任何一个未被内联的函数入口（kprobe）或出口（kretprobe） 31。这提供了极大的灵活性，使得开发者可以探测任意感兴趣的内核函数，弥补了Tracepoint覆盖范围不足的缺陷。然而，这种灵活性的代价是稳定性较差。Kprobe依赖于内核函数名或符号，这些在内核版本迭代中可能会发生变化，导致eBPF程序失效 30。  
* **LSM（Linux安全模块）钩子**：LSM是内核中一个为实现强制访问控制（Mandatory Access Control, MAC）而设计的框架，如SELinux和AppArmor都基于此构建 34。从Linux 5.7版本开始，eBPF程序可以直接附加到LSM钩子上，这一技术被称为BPF-LSM。LSM钩子位于内核执行安全敏感操作的关键决策点。与Tracepoint和Kprobe主要用于观测不同，BPF-LSM程序不仅可以观测事件，还可以通过返回一个错误码（如  
  \-EPERM）来主动**阻止**该操作的执行 34。这为实现主动、实时的安全策略提供了强有力的武器。

下表对这三种主要的钩子机制进行了比较，为安全架构师和工程师在设计eBPF安全方案时提供了决策依据。

**表2：eBPF钩子机制比较**

| 钩子类型 | 稳定性 | 性能开销 | 能力 | 典型用例 | 来源 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **Tracepoint** | 高（稳定API） | 低 | 仅可观测 | 监控稳定的内核事件（如系统调用） | 29 |
| **Kprobe** | 低（依赖内核实现） | 中（动态插桩） | 仅可观测 | 调试、追踪任意内核函数 | 31 |
| **BPF-LSM** | 高（稳定钩子点） | 低至中 | 可观测与强制执行 | 实现细粒度的安全策略和访问控制 | 34 |

### **4.2 实践应用：监控commit\_creds以发现非法权限变更**

监控commit\_creds函数的调用是检测权限提升攻击的一种直接且有效的策略。在正常系统中，只有少数特权进程（如sudo、su）会合法地调用此函数。任何来自非预期进程（如一个Web服务器进程）的commit\_creds调用都应被视为高度可疑的攻击信号 14。

使用Kprobe可以轻松实现对此类行为的监控 38。一个附加到

commit\_creds函数入口的eBPF程序可以执行以下逻辑：

1. 获取当前进程的PID和进程名（comm）。  
2. 将这些信息（PID、comm）以及时间戳等上下文数据写入一个eBPF Map（如perf\_event\_array或ringbuf）。  
3. 用户态的监控守护进程从Map中读取这些事件。  
4. 守护进程根据预设的策略（例如，白名单）对事件进行分析。如果发现调用commit\_creds的进程不在白名单内，立即生成高优先级安全警报。

### **4.3 检测复杂漏洞利用：识别UAF和TOCTOU模式**

更高级的防御策略旨在攻击者成功执行commit\_creds之前，就发现其利用链中的早期行为。

* **检测UAF利用模式**：直接检测UAF漏洞本身非常困难，但可以监控其利用过程中产生的行为指征。例如，堆喷射阶段通常表现为一个进程在短时间内大量、重复地创建同一种类型的对象（如vuln.ko案例中反复打开/dev/ptmx来创建tty\_struct） 15。eBPF程序可以监控相关的系统调用（如  
  open、ioctl），并在eBPF Map中统计每个进程的行为频率，一旦超过某个阈值，就触发警报。更前沿的研究如BUDAlloc，甚至利用eBPF构建定制化的内存分配器来直接检测UAF的发生 17。  
* **检测TOCTOU竞争**：使用Tracepoint或Kprobe在系统调用的入口和出口分别记录参数，理论上可以发现参数在两次读取间的变化。但这种方法本身也可能存在竞争。一个更稳健的方法是利用LSM钩子。LSM钩子通常在内核已经将所有参数从用户空间安全地复制到内核空间之后才被触发 40。例如，  
  security\_file\_open这个LSM钩子所看到的路径参数，是内核最终决定要打开的那个路径，而不是攻击者在TOCTOU窗口中可能已经切换掉的路径。这从根本上消除了检测过程中的竞争条件。

### **4.4 使用BPF-LSM进行策略强制：主动阻止恶意操作**

BPF-LSM的出现，标志着eBPF在安全领域的应用从被动的“检测-响应”模式，向主动的“预防-保护”模式的转变 35。

* **示例：阻止特定网络连接**：一个附加到lsm/socket\_connect钩子的eBPF程序可以检查目标IP地址。如果目标地址位于一个预定义的黑名单中，程序可以直接返回-EPERM，内核将中止这次连接尝试，从而实现了一个动态的、内核级的防火墙策略 34。  
* **示例：缓解容器逃逸**：创建新的用户命名空间（user namespace）是容器逃逸攻击中的常用手法，通常通过unshare或clone系统调用实现。内核在处理这类请求时，会调用prepare\_creds函数。一个附加到cred\_prepare LSM钩子的eBPF程序可以检查当前进程是否在容器内，以及它是否被授权创建新的用户命名空间。如果未经授权，程序可以返回错误码，从而阻止这次容器逃逸的尝试 42。

eBPF防御机制的发展呈现出一个清晰的“成熟度模型”。最初级的应用是使用Kprobe或Tracepoint对已知的恶意行为（如调用commit\_creds）进行事后观测和告警。这是纯粹的被动检测。一个更进阶的阶段是利用LSM钩子等机制，在利用链的更早阶段，基于更丰富的上下文进行检测，例如识别TOCTOU攻击模式。这是更智能、更具上下文的检测。而最高级的阶段，则是利用BPF-LSM的强制执行能力，直接在内核中阻止恶意操作的完成，实现主动防御。BPF-LSM的出现是这一领域最具战略意义的进展，它将eBPF从一个观测工具转变为一个能够与SELinux、AppArmor等传统MAC框架相竞争，甚至可能取而代之的策略执行引擎。它为实现高度可编程、细粒度的安全策略提供了一条全新的、可能更易于管理的路径，从根本上改变了Linux运行时安全的格局 35。

---

## **第5节 深度剖析：基于eBPF的安全工具**

随着eBPF技术的成熟，一系列开源和商业安全工具应运而生。它们利用eBPF提供的内核级可见性，为云原生和传统Linux环境提供运行时安全监控和保护。本节将深入分析三个代表性工具：Cilium Tetragon、Aqua Tracee和Sysdig Falco。

### **5.1 Cilium Tetragon：云原生运行时安全与强制执行**

* **架构**：Tetragon是Cilium项目的一部分，专为Kubernetes环境设计，并作为DaemonSet部署在集群的每个节点上 33。其架构包含一个在每个节点上运行的Tetragon Agent（引擎），负责加载eBPF探针和收集事件；以及一个Tetragon Operator，负责管理通过Kubernetes CRD（Custom Resource Definition）定义的  
  TracingPolicy 44。Tetragon的核心优势在于其深度K8s感知能力，它能够将底层内核事件与高层的Kubernetes身份（如Pod、Namespace、Service）相关联 45。  
* **数据收集与强制执行**：Tetragon利用eBPF在内核中以极低的开销监控系统调用、文件访问、网络活动和权限提升等事件 45。至关重要的是，Tetragon不仅限于观测，它还支持内核级的强制执行。通过  
  TracingPolicy，用户可以定义规则，在检测到恶意行为时，Tetragon的eBPF程序可以直接在内核中采取行动，例如向违规进程发送SIGKILL信号，或者覆盖系统调用的返回值来阻止操作，这使其能够有效防御TOCTOU等竞争条件攻击 45。  
* **设计哲学**：与提供大量预置规则的工具不同，Tetragon的设计哲学是提供一个高度灵活和可编程的框架。它本身不附带太多默认策略，而是鼓励用户根据自身应用的行为和安全需求，通过TracingPolicy CRD来定制观测和强制执行逻辑 33。收集到的事件可以通过JSON日志或gRPC流导出，以便与SIEM等外部系统集成 45。

### **5.2 Aqua Tracee：精细化的追踪与取证框架**

* **架构**：Tracee由两个核心组件构成：Tracee-eBPF和Tracee-Rules 48。  
  Tracee-eBPF是纯粹的事件收集器，负责通过eBPF程序从内核中捕获事件。这些原始事件通过性能事件缓冲区（perf buffer）或环形缓冲区（ring buffer）被发送到用户空间的tracee-ebpf守护进程。该进程会对事件进行解析和丰富（例如，添加容器信息），然后通过一个内部管道将处理后的事件流传递给Tracee-Rules引擎进行分析和检测 48。  
* **数据收集**：Tracee专注于提供尽可能详细和丰富的事件数据，使其成为一个强大的数字取证（forensics）和故障排查工具 49。它能够精确地追踪仅在特定容器内发生的事件，自动过滤掉来自宿主机或其他容器的无关噪声，这在多租户环境中尤为重要 50。  
* **规则引擎**：Tracee-Rules是Tracee的检测大脑。它支持使用多种语言编写检测规则（官方称为“签名”），包括性能优越的Golang、声明式的Rego（来自Open Policy Agent项目）以及尚在实验阶段的Go-CEL 48。这种灵活性允许安全团队根据具体场景和团队技能选择最合适的语言来定义可疑行为模式。

### **5.3 Sysdig Falco：成熟的、基于规则的威胁检测引擎**

* **架构**：Falco是CNCF（云原生计算基金会）的毕业项目，是云原生运行时安全领域的元老级工具。其最初依赖于一个定制的内核模块来捕获系统调用，但现在已经转向默认使用现代eBPF探针作为其主要的数据源 51。其架构包含一个内核驱动（eBPF探针或内核模块）和一个用户空间的Falco守护进程。驱动负责从内核捕获事件流，并通过一个环形缓冲区高效地传递给守护进程。守护进程则根据一套丰富的规则集对事件流进行实时评估，并在匹配到恶意行为时，通过一个名为Falcosidekick的组件将警报发送到超过50种不同的下游系统（如SIEM、Slack等） 52。  
* **数据收集**：Falco的现代eBPF探针现在已直接内嵌在Falco主程序二进制文件中，极大地简化了部署过程。falcoctl工具能够自动检测目标系统的内核能力，智能地选择最佳驱动（现代eBPF探针、传统eBPF探针或内核模块） 53。  
* **设计哲学**：Falco的核心优势在于其提供了一套非常全面且经过社区千锤百炼的默认规则集。这些规则覆盖了从容器内部异常行为、主机安全威胁到Kubernetes和云平台安全等多个层面 52。Falco的设计哲学是“开箱即用”，为用户提供立即的价值，其主要关注点是实时的威胁检测和告警。

### **5.4 生产环境中的性能与开销考量**

* **通用eBPF开销**：尽管eBPF因其高效而被誉为“低开销”，但任何形式的插桩都会引入性能成本 55。开销主要来源于两个方面：eBPF程序本身在内核中的执行时间，以及将数据从内核空间传输到用户空间的成本。  
* **工具特定开销**：不同的工具架构对性能的影响不同。像Tetragon这样在内核中进行预过滤和聚合的工具，可以显著减少需要发送到用户空间的数据量，从而降低整体开销 45。相比之下，将大量原始事件流发送到用户空间进行处理的工具，可能会在CPU和内存方面产生更高的负载。  
* **未追踪进程开销（Untraced Overhead）**：一个常被忽视的关键点是，即使某些进程并未被明确地追踪，它们也可能因为eBPF的全局插桩而遭受性能损失 58。当一个eBPF程序被附加到某个全局的内核钩子点（如一个系统调用Tracepoint）时，系统上所有触发该钩子点的进程都会导致该eBPF程序的执行，即使程序内部的逻辑会立即过滤掉不感兴趣的进程。这在高度共享的多租户系统上是一个需要仔细评估的因素。  
* **Uprobe开销**：用于追踪用户空间函数的Uprobe，通常比追踪内核函数的Kprobe或Tracepoint具有更大的性能开销，因为它们涉及到更复杂的上下文切换和地址空间处理 59。

eBPF安全工具的演进轨迹清晰地反映了行业安全理念的变迁。Falco代表了第一代工具，它拥有强大的、基于已知模式的检测引擎，并成功地将eBPF作为其更优的数据来源 51。Tracee则体现了对深度取证和数据粒度的极致追求，其架构清晰地分离了收集与检测 48。而Tetragon则代表了下一代的设计哲学，它从一开始就为eBPF和Kubernetes而生 45。其核心差异化优势在于深度K8s上下文感知和内核内强制执行能力 45。它不仅仅是“看到”了坏事，而是能在坏事发生时，在内核层面“阻止”它。从Falco到Tetragon的演进，是从“检测与响应”到“预防与保护”的明确转变，而驱动这一转变的核心技术正是eBPF，特别是BPF-LSM能力的成熟。运行时安全的未来，将不再仅仅是可观测性，而是可编程的、实时的、内核内的策略强制执行。

**表3：eBPF安全工具架构比较**

| 工具 | 主要架构 | 强制执行模型 | Kubernetes集成 | 策略/规则方法 | 来源 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **Cilium Tetragon** | K8s原生Operator/DaemonSet | 内核内强制（信号/系统调用覆盖） | 深度（工作负载身份感知） | 自定义TracingPolicy CRD | 44 |
| **Aqua Tracee** | 模块化收集器/规则引擎 | 无（仅检测/取证） | 上下文丰富（添加容器信息） | Go/Rego/CEL签名 | 48 |
| **Sysdig Falco** | 驱动/守护进程与Sidekick | 事后响应（通过外部集成） | 上下文丰富（添加容器信息） | 基于YAML的规则 | 9 |

---

## **第6节 攻击者视角：进攻性eBPF与规避技术**

eBPF的强大能力是一把双刃剑。防御者用来构建堡垒的工具，同样可以被攻击者用来打造攻城利器。理解进攻性eBPF（Offensive eBPF）的原理和技术，对于构建真正有效的防御体系至关重要 6。

### **6.1 eBPF作为根キット（Rootkit）平台：隐藏进程、文件与网络连接**

eBPF为现代根キット提供了一个近乎完美的平台，因为它能在内核层面实现经典的恶意软件功能，同时绕过许多传统的检测手段。

* **隐藏技术**：一个基于eBPF的根キット可以实现深度的自我隐藏。通过在getdents64系统调用的Tracepoint或Kprobe上挂载eBPF程序，根キット可以在该系统调用返回给用户空间（如ls、ps等命令）之前，遍历其返回的目录项列表，并从中移除任何与根キット自身相关的文件或目录名 6。同理，通过挂钩  
  kill系统调用，它可以拦截并丢弃所有试图终止根キット进程的信号。更高级的根キット甚至会挂钩bpf(2)系统调用本身，从而在bpftool等管理工具的查询结果中隐藏自己的eBPF程序和Maps，达到“隐形”的目的 61。  
* **持久化**：为了在系统重启后依然存活，eBPF根キット可以采用多种持久化策略。例如，它可以利用eBPF程序修改关键的系统配置文件（如/etc/passwd、sshd\_config或cron任务），然后利用上述的隐藏技术来掩盖这些修改 61。另一种更隐蔽的方法是使用Uprobe来为关键的用户空间守护进程（如  
  sshd）植入后门。例如，通过在sshd的密码验证函数上附加Uprobe，根キット可以在不修改sshd二进制文件的情况下，实现一个万能密码登录的功能 61。

### **6.2 隐蔽的命令与控制（C2）及数据窃取**

由于eBPF程序本身受到严格限制，无法主动发起网络连接，因此eBPF根キット的C2通信必须依赖于劫持现有的网络流量。

* **劫持网络流量**：根キット通常会利用XDP（eXpress Data Path）或TC（Traffic Control）钩子。这些钩子位于网络协议栈的极早期阶段，允许eBPF程序在内核主网络协议栈处理数据包之前就对其进行检查和修改 61。根キット可以监听所有入站或出站流量，寻找一个预定义的“魔法字节”或特定模式的C2信标。一旦匹配成功，它就可以将该数据包的内容解析为命令并执行，或者将窃取的数据打包成响应，修改数据包后发回，整个过程对操作系统和上层应用完全透明 61。  
* **数据窃取**：eBPF的Maps机制为数据窃取提供了便利的通道。一个eBPF程序（例如，附加到文件读写系统调用的Kprobe）可以捕获敏感信息（如从/etc/shadow读取的内容），并将其存入一个共享的eBPF Map中。然后，另一个附加到网络出口（如TC egress）的eBPF程序可以从这个Map中读取数据，并将其编码后插入到正常的出站网络流量中，实现隐蔽的数据外泄 61。

### **6.3 防御防御者：监控恶意的eBPF程序加载**

eBPF根キット的存在意味着，一个全面的防御策略必须将eBPF子系统本身也视为一个需要被严密监控和保护的关键资产。

* **关键防御措施**：  
  1. **限制非特权BPF**：在生产环境中，应始终将内核参数kernel.unprivileged\_bpf\_disabled设置为1 26。这可以阻止非特权用户加载eBPF程序，从而极大地缩小了攻击面，尤其是针对验证器漏洞的利用。  
  2. **监控bpf()系统调用**：讽刺但有效地，防御者可以使用一个可信的eBPF程序（或传统的auditd）来监控bpf(2)系统调用本身。任何BPF\_PROG\_LOAD操作都应被记录，包括加载程序的进程PID、可执行文件路径等。对非预期的进程（例如，除了系统管理工具和已知安全代理之外的任何进程）加载eBPF程序的行为，应触发高优先级警报。  
  3. **基于虚拟机管理程序的检测**：对于最高级别的威胁，即根キット已经成功在内核中隐藏自己的情况，带内（in-band）检测工具可能已经失效。此时，需要依赖带外（out-of-band）的检测手段。通过虚拟机管理程序（Hypervisor）获取整个虚拟机的内存快照，然后在另一个可信的环境中进行内存取证分析，可以发现那些对客户机操作系统（Guest OS）不可见的eBPF程序和数据结构 63。

eBPF的安全态势呈现出一种根本性的悖论：其力量即是其风险。因此，一个成熟的安全组织必须将eBPF子系统本身视为一个需要被监控和防御的关键资产，而不仅仅是获取防御工具的来源。这意味着，安全工具如Tetragon或Falco，除了要监控外部威胁外，还应内置规则来检测可疑的eBPF活动本身。例如，一个非系统服务进程加载了一个追踪程序，或者一个eBPF程序被附加到一个敏感的安全函数上，这些都应被视为潜在的威胁指标。这种“eBPF感知”的安全监控能力，将成为未来运行时安全解决方案的核心要求。

---

## **第7节 前沿领域与战略建议**

eBPF技术仍在飞速发展，其在安全领域的应用也在不断拓展到新的前沿。本节将探讨一些新兴的应用方向，并为组织机构在部署eBPF安全方案时提供战略性建议。

### **7.1 下一波浪潮：eBPF与机器学习结合进行异常检测**

传统的安全工具大多依赖于基于签名或规则的检测方法，这对于发现已知威胁非常有效，但对零日攻击和未知的恶意行为模式则力不从心。eBPF能够以极高的保真度捕获海量的底层系统事件（如每一次系统调用、每一个网络包），这为机器学习模型的应用提供了理想的数据源 64。

* **异常检测**：通过eBPF收集系统在正常运行状态下的行为数据（如系统调用序列、进程间通信模式、网络流量特征等），可以训练一个机器学习模型来学习这个“正常行为基线”。在部署后，模型可以实时分析由eBPF捕获的事件流。任何显著偏离这个基线的行为都可以被标记为异常，从而可能在攻击的早期阶段就发现威胁，即使该攻击手法是前所未见的 65。  
* **实现架构**：这种架构通常涉及两部分：在内核中，eBPF程序负责高效、无侵入地收集原始数据；在用户空间，一个守护进程将这些数据流送入一个机器学习推理引擎进行实时分析和判断 66。

### **7.2 新型防御应用：利用eBPF辅助的分配器缓解UAF**

除了检测，eBPF的强大能力也开始被用于主动缓解整个类别的漏洞。以UAF漏洞为例，一些前沿研究展示了eBPF如何从根本上改变内存管理的安全性。

* **主动缓解**：BUDAlloc项目是一个典型的例子 17。它提出了一种用户态内存分配器与内核协同设计的新思路。  
* **机制**：BUDAlloc利用eBPF来定制内核的缺页异常（page fault）处理程序。当一个对象被分配时，用户态分配器为其创建多个虚拟地址别名，并将这些映射关系通过eBPF共享给内核。当对象被释放时，其所有虚拟地址到物理地址的映射都会被解除。如果之后程序通过一个悬垂指针访问这块内存，将会触发一个缺页异常。此时，BUDAlloc定制的、由eBPF驱动的缺页处理程序会被调用。它会检查共享的元数据，发现该地址已无有效映射，从而实时地捕获这次UAF访问。这种方法展示了eBPF的终极潜力：不仅仅是观测内核，而是安全地修改和增强内核的核心功能，以根除漏洞。

### **7.3 实施与部署的战略建议**

对于希望利用eBPF提升其安全能力的组织，以下战略性建议可供参考：

* **采纳纵深防御姿态**：不应将所有希望寄托于单一工具或技术。应将基于eBPF的监控与传统的安全措施（如内核加固、最小权限原则、漏洞扫描、静态代码分析）相结合，构建多层次的防御体系。  
* **从可观测性开始，逐步成熟到强制执行**：部署eBPF安全方案应循序渐进。可以先从一个纯监控模式的工具（如Falco或Tracee）开始，收集数据，建立对系统正常行为的基线理解，并熟悉事件的类型和数量。在积累了足够的经验和信心后，再逐步引入具备强制执行能力的工具（如Tetragon），针对最关键的应用和最明确的恶意行为，创建高置信度的阻止策略。  
* **加固eBPF子系统本身**：  
  * **禁用非特权BPF**：在所有生产服务器上，通过sysctl将kernel.unprivileged\_bpf\_disabled设置为1。  
  * **严格限制能力**：在容器化环境中，使用Seccomp、AppArmor或SELinux等机制，严格限制容器的CAP\_BPF以及与之相关的CAP\_PERFMON、CAP\_SYS\_ADMIN等能力。权限应按需授予，而非默认开启。  
  * **审计BPF活动**：实施对bpf(2)系统调用的监控，审计所有eBPF程序的加载事件，并对来源可疑的加载行为进行告警。  
* **为正确的任务选择正确的工具**：  
  * 如果需求是快速部署、拥有大量开箱即用的成熟检测规则，适用于通用环境，**Falco**是一个可靠的起点。  
  * 如果核心需求是深度事件响应和数字取证，对数据粒度和丰富度有极高要求，**Tracee**是更合适的选择。  
  * 如果环境是Kubernetes原生，且最终目标是实现可编程的、主动的、与应用身份紧密集成的策略强制执行，那么**Tetragon**是当前技术方向上的领先者。

eBPF技术正经历从一个强大的“附加”观测工具，向成为内核核心安全架构不可或缺的一部分的转变。长远来看，其愿景不仅仅是让eBPF程序*监视*内核，而是让eBPF程序*成为*一个更安全、可动态加固的内核的一部分。这一趋势将对操作系统设计和系统安全的未来产生深远的影响。

#### **引用的著作**

1. What is eBPF? An Introduction and Deep Dive into the eBPF ..., 访问时间为 七月 1, 2025， [https://ebpf.io/what-is-ebpf/](https://ebpf.io/what-is-ebpf/)  
2. Programmability and Performance in the Linux Kernel by eBPF. \- DEV Community, 访问时间为 七月 1, 2025， [https://dev.to/krishnasvp/programmability-and-performance-in-the-linux-kernel-by-ebpf-10nl](https://dev.to/krishnasvp/programmability-and-performance-in-the-linux-kernel-by-ebpf-10nl)  
3. eBPF Tutorial by Example 0: Introduction to Core Concepts and Tools \- eunomia, 访问时间为 七月 1, 2025， [https://eunomia.dev/tutorials/0-introduce/](https://eunomia.dev/tutorials/0-introduce/)  
4. The eBPF Runtime in the Linux Kernel \- arXiv, 访问时间为 七月 1, 2025， [https://arxiv.org/html/2410.00026v2](https://arxiv.org/html/2410.00026v2)  
5. Understanding the Security of Linux eBPF Subsystem \- Systems Software Research Group, 访问时间为 七月 1, 2025， [https://www.ssrg.ece.vt.edu/papers/apsys23.pdf](https://www.ssrg.ece.vt.edu/papers/apsys23.pdf)  
6. What is eBPF? The Hacker's New Power Tool for Linux \- Cymulate, 访问时间为 七月 1, 2025， [https://cymulate.com/blog/ebpf\_hacking/](https://cymulate.com/blog/ebpf_hacking/)  
7. The art of writing eBPF programs: a primer. \- Sysdig, 访问时间为 七月 1, 2025， [https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/](https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/)  
8. Harnessing the eBPF Verifier \- The Trail of Bits Blog, 访问时间为 七月 1, 2025， [https://blog.trailofbits.com/2023/01/19/ebpf-verifier-harness/](https://blog.trailofbits.com/2023/01/19/ebpf-verifier-harness/)  
9. Sysdig and Falco now powered by eBPF. | Sysdig, 访问时间为 七月 1, 2025， [https://sysdig.com/blog/sysdig-and-falco-now-powered-by-ebpf/](https://sysdig.com/blog/sysdig-and-falco-now-powered-by-ebpf/)  
10. The beginning of my eBPF Journey — Kprobe Adventures with BCC | by Douglas Mendez, 访问时间为 七月 1, 2025， [https://douglasmakey.medium.com/the-beginning-of-my-ebpf-journey-kprobe-adventures-with-bcc-6aae3eb33a1e](https://douglasmakey.medium.com/the-beginning-of-my-ebpf-journey-kprobe-adventures-with-bcc-6aae3eb33a1e)  
11. eBPF Core Infrastructure Landscape, 访问时间为 七月 1, 2025， [https://ebpf.io/infrastructure/](https://ebpf.io/infrastructure/)  
12. eBPF verifier — The Linux Kernel documentation, 访问时间为 七月 1, 2025， [https://docs.kernel.org/bpf/verifier.html](https://docs.kernel.org/bpf/verifier.html)  
13. Privilege Escalation Procedure through commit\_creds() \- ResearchGate, 访问时间为 七月 1, 2025， [https://www.researchgate.net/figure/Privilege-Escalation-Procedure-through-commit-creds\_fig3\_329408891](https://www.researchgate.net/figure/Privilege-Escalation-Procedure-through-commit-creds_fig3_329408891)  
14. Implementing Container Privilege Escalation Detection using eBPF for C... Inhyeok Jang & Sungjin Kim \- YouTube, 访问时间为 七月 1, 2025， [https://www.youtube.com/watch?v=buZxMGKX9Xk](https://www.youtube.com/watch?v=buZxMGKX9Xk)  
15. Linux Kernel Exploitation: Exploiting race-condition \+ UAF ..., 访问时间为 七月 1, 2025， [https://santaclz.github.io/2024/01/29/Linux-Kernel-Exploitation-exploiting-race-condition-and-UAF.html](https://santaclz.github.io/2024/01/29/Linux-Kernel-Exploitation-exploiting-race-condition-and-UAF.html)  
16. Deep Dive into RCU Race Condition: Analysis of TCP-AO UAF (CVE-2024–27394) \- Theori, 访问时间为 七月 1, 2025， [https://theori.io/blog/deep-dive-into-rcu-race-condition-analysis-of-tcp-ao-uaf-cve-2024-27394](https://theori.io/blog/deep-dive-into-rcu-race-condition-analysis-of-tcp-ao-uaf-cve-2024-27394)  
17. BUDAlloc: Defeating Use-After-Free Bugs by Decoupling ... \- USENIX, 访问时间为 七月 1, 2025， [https://www.usenix.org/system/files/usenixsecurity24-ahn.pdf](https://www.usenix.org/system/files/usenixsecurity24-ahn.pdf)  
18. Playing for K(H)eaps: Understanding and Improving Linux Kernel Exploit Reliability \- USENIX, 访问时间为 七月 1, 2025， [https://www.usenix.org/system/files/sec22fall\_zeng.pdf](https://www.usenix.org/system/files/sec22fall_zeng.pdf)  
19. Study of Race Condition: A Privilege Escalation Vulnerability \- International Institute of Informatics and Cybernetics, 访问时间为 七月 1, 2025， [https://www.iiisci.org/journal/pdv/sci/pdfs/SA025BU17.pdf](https://www.iiisci.org/journal/pdv/sci/pdfs/SA025BU17.pdf)  
20. Identifying and Exploiting Windows Kernel Race Conditions via Memory Access Patterns \- Google Research, 访问时间为 七月 1, 2025， [https://research.google.com/pubs/archive/42189.pdf](https://research.google.com/pubs/archive/42189.pdf)  
21. Understanding the Meltdown vulnerability \- Information Security Stack Exchange, 访问时间为 七月 1, 2025， [https://security.stackexchange.com/questions/255225/understanding-the-meltdown-vulnerability](https://security.stackexchange.com/questions/255225/understanding-the-meltdown-vulnerability)  
22. Privilege Escalation in Linux via a Local Buffer Overflow | by Ravishanka Silva | Medium, 访问时间为 七月 1, 2025， [https://ravi5hanka.medium.com/privilege-escalation-in-linux-via-a-local-buffer-overflow-dcee4f9b4a49](https://ravi5hanka.medium.com/privilege-escalation-in-linux-via-a-local-buffer-overflow-dcee4f9b4a49)  
23. eBPF Verifier: Why It Matters for Reliable Observability \- groundcover, 访问时间为 七月 1, 2025， [https://www.groundcover.com/ebpf/ebpf-verifier](https://www.groundcover.com/ebpf/ebpf-verifier)  
24. How does an eBPF program cause a kernel panic? \- Information Security Stack Exchange, 访问时间为 七月 1, 2025， [https://security.stackexchange.com/questions/277892/how-does-an-ebpf-program-cause-a-kernel-panic](https://security.stackexchange.com/questions/277892/how-does-an-ebpf-program-cause-a-kernel-panic)  
25. eBPF Verifier Code Review \- Linux Foundation, 访问时间为 七月 1, 2025， [https://www.linuxfoundation.org/hubfs/eBPF/eBPF%20Verifier%20Security%20Audit.pdf?\_\_hstc=137369199.8da91b5f8b42a5531651a132262dd89d.1732320000083.1732320000084.1732320000085.1&\_\_hssc=137369199.1.1732320000086&\_\_hsfp=2637229211](https://www.linuxfoundation.org/hubfs/eBPF/eBPF%20Verifier%20Security%20Audit.pdf?__hstc=137369199.8da91b5f8b42a5531651a132262dd89d.1732320000083.1732320000084.1732320000085.1&__hssc=137369199.1.1732320000086&__hsfp=2637229211)  
26. Understanding the Security Aspects of Linux eBPF \- Pentera, 访问时间为 七月 1, 2025， [https://pentera.io/blog/the-good-bad-and-compromisable-aspects-of-linux-ebpf/](https://pentera.io/blog/the-good-bad-and-compromisable-aspects-of-linux-ebpf/)  
27. Linux Kernel: Vulnerability in the eBPF verifier register limit tracking ..., 访问时间为 七月 1, 2025， [https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f](https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f)  
28. Toss a Fault to BpfChecker: Revealing Implementation Flaws for eBPF runtimes with Differential Fuzzing \- Yajin Zhou, 访问时间为 七月 1, 2025， [http://www.malgenomeproject.org/papers/CCS2024\_BpfChecker.pdf](http://www.malgenomeproject.org/papers/CCS2024_BpfChecker.pdf)  
29. Tracepoints, Kprobes, or Fprobes: Which One Should You Choose ..., 访问时间为 七月 1, 2025， [https://cloudchirp.medium.com/tracepoints-kprobes-or-fprobes-which-one-should-you-choose-00d65918fbe2](https://cloudchirp.medium.com/tracepoints-kprobes-or-fprobes-which-one-should-you-choose-00d65918fbe2)  
30. Security Monitoring with eBPF \- Brendan Gregg, 访问时间为 七月 1, 2025， [https://www.brendangregg.com/Slides/BSidesSF2017\_BPF\_security\_monitoring.pdf](https://www.brendangregg.com/Slides/BSidesSF2017_BPF_security_monitoring.pdf)  
31. eBPF Tutorial by Example 2: Monitoring unlink System Calls with kprobe \- eunomia, 访问时间为 七月 1, 2025， [https://eunomia.dev/tutorials/2-kprobe-unlink/](https://eunomia.dev/tutorials/2-kprobe-unlink/)  
32. Tracing System Calls Using eBPF \- Part 2 \- Falco, 访问时间为 七月 1, 2025， [https://falco.org/blog/tracing-system-calls-using-ebpf-part-2/](https://falco.org/blog/tracing-system-calls-using-ebpf-part-2/)  
33. Quick Exploration of Tetragon — A Security Observability and Execution Tool Based on eBPF \- Addo Zhang, 访问时间为 七月 1, 2025， [https://addozhang.medium.com/quick-exploration-of-tetragon-a-security-observability-and-execution-tool-based-on-ebpf-b67ddc84886d](https://addozhang.medium.com/quick-exploration-of-tetragon-a-security-observability-and-execution-tool-based-on-ebpf-b67ddc84886d)  
34. eBPF Tutorial by Example 19: Security Detection and Defense using ..., 访问时间为 七月 1, 2025， [https://eunomia.dev/tutorials/19-lsm-connect/](https://eunomia.dev/tutorials/19-lsm-connect/)  
35. Secure the Linux Kernel with eBPF Linux Security Module \- Vandana Salve, Independent Consultant \- YouTube, 访问时间为 七月 1, 2025， [https://www.youtube.com/watch?v=\_tG1G6Oewc4](https://www.youtube.com/watch?v=_tG1G6Oewc4)  
36. Practical Guide to LSM BPF \- Head First eBPF, 访问时间为 七月 1, 2025， [https://www.ebpf.top/en/post/lsm\_bpf\_intro/](https://www.ebpf.top/en/post/lsm_bpf_intro/)  
37. Program Type 'BPF\_PROG\_TYPE\_LSM' \- eBPF Docs, 访问时间为 七月 1, 2025， [https://docs.ebpf.io/linux/program-type/BPF\_PROG\_TYPE\_LSM/](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/)  
38. Program Type 'BPF\_PROG\_TYPE\_KPROBE' \- eBPF Docs, 访问时间为 七月 1, 2025， [https://docs.ebpf.io/linux/program-type/BPF\_PROG\_TYPE\_KPROBE/](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)  
39. eBPF Developer Tutorial: Learning eBPF Step by Step with Examples \- GitHub, 访问时间为 七月 1, 2025， [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)  
40. Using LSM Hooks with Tracee to Overcome Gaps with Syscall Tracing \- Aqua Security, 访问时间为 七月 1, 2025， [https://www.aquasec.com/blog/linux-vulnerabilitie-tracee/](https://www.aquasec.com/blog/linux-vulnerabilitie-tracee/)  
41. Runtime Security And The Role Of EBPF/BPF-LSM \- AccuKnox, 访问时间为 七月 1, 2025， [https://accuknox.com/blog/runtime-security-ebpf-bpf-lsm](https://accuknox.com/blog/runtime-security-ebpf-bpf-lsm)  
42. Live-patching security vulnerabilities inside the Linux kernel with eBPF Linux Security Module \- The Cloudflare Blog, 访问时间为 七月 1, 2025， [https://blog.cloudflare.com/live-patch-security-vulnerabilities-with-ebpf-lsm/](https://blog.cloudflare.com/live-patch-security-vulnerabilities-with-ebpf-lsm/)  
43. Securing systems with eBPF Linux Security Module \- Frederick Lawler \- YouTube, 访问时间为 七月 1, 2025， [https://www.youtube.com/watch?v=XlqfTX9xV\_4](https://www.youtube.com/watch?v=XlqfTX9xV_4)  
44. Master Kubernetes Security with Tetragon \- Is It Observable, 访问时间为 七月 1, 2025， [https://isitobservable.io/observability/kubernetes/master-kubernetes-security-with-tetragon](https://isitobservable.io/observability/kubernetes/master-kubernetes-security-with-tetragon)  
45. Tetragon \- Isovalent Networking for Kubernetes documentation, 访问时间为 七月 1, 2025， [https://docs.isovalent.com/project/tetragon/index.html](https://docs.isovalent.com/project/tetragon/index.html)  
46. Cloud Native, eBPF-based Networking, Observability, and Security \- Cilium, 访问时间为 七月 1, 2025， [https://cilium.io/get-started/](https://cilium.io/get-started/)  
47. Tetragon \- eBPF-based Security Observability and Runtime Enforcement, 访问时间为 七月 1, 2025， [https://tetragon.io/](https://tetragon.io/)  
48. Overview \- Tracee \- Aqua Security, 访问时间为 七月 1, 2025， [https://aquasecurity.github.io/tracee/v0.9/](https://aquasecurity.github.io/tracee/v0.9/)  
49. Aqua Tracee: Real-Time Security with eBPF for Linux & Kubernetes \- Venturenox, 访问时间为 七月 1, 2025， [https://venturenox.com/blog/aqua-tracee-real-time-security-monitoring/](https://venturenox.com/blog/aqua-tracee-real-time-security-monitoring/)  
50. A Deep Dive into eBPF: The Technology that Powers Tracee \- Aqua Security, 访问时间为 七月 1, 2025， [https://www.aquasec.com/blog/https-www-aquasec-com-blog-intro-ebpf-tracing-containers/](https://www.aquasec.com/blog/https-www-aquasec-com-blog-intro-ebpf-tracing-containers/)  
51. Falco: A New Approach to Security and Visibility \- Intel, 访问时间为 七月 1, 2025， [https://www.intel.com/content/www/us/en/developer/articles/community/falco-a-new-approach-to-security-and-visibility.html](https://www.intel.com/content/www/us/en/developer/articles/community/falco-a-new-approach-to-security-and-visibility.html)  
52. Exploring eBPF: Empowering DevOps with Falco and KubeArmor | by RAP | Medium, 访问时间为 七月 1, 2025， [https://medium.com/@ridhoadya/exploring-ebpf-empowering-devops-with-falco-and-kubearmor-830669bc0fd5](https://medium.com/@ridhoadya/exploring-ebpf-empowering-devops-with-falco-and-kubearmor-830669bc0fd5)  
53. charts/charts/falco/README.md at master · falcosecurity/charts \- GitHub, 访问时间为 七月 1, 2025， [https://github.com/falcosecurity/charts/blob/master/charts/falco/README.md](https://github.com/falcosecurity/charts/blob/master/charts/falco/README.md)  
54. Choosing a Falco driver, 访问时间为 七月 1, 2025， [https://falco.org/blog/choosing-a-driver/](https://falco.org/blog/choosing-a-driver/)  
55. eBPF for Advanced Linux Performance Monitoring and Security \- TuxCare, 访问时间为 七月 1, 2025， [https://tuxcare.com/blog/ebpf-for-advanced-linux-performance-monitoring-and-security/](https://tuxcare.com/blog/ebpf-for-advanced-linux-performance-monitoring-and-security/)  
56. Demystifying eBPF Tracing: A Beginner's Guide to Performance Optimization, 访问时间为 七月 1, 2025， [https://www.groundcover.com/ebpf/ebpf-tracing](https://www.groundcover.com/ebpf/ebpf-tracing)  
57. Enhancing Cloud-Native Security with Tetragon \- CloudRaft, 访问时间为 七月 1, 2025， [https://www.cloudraft.io/blog/cloud-native-security-with-tetragon](https://www.cloudraft.io/blog/cloud-native-security-with-tetragon)  
58. Eliminating eBPF Tracing Overhead on Untraced Processes \- People \- Virginia Tech, 访问时间为 七月 1, 2025， [https://people.cs.vt.edu/djwillia/papers/ebpf24-mookernel.pdf](https://people.cs.vt.edu/djwillia/papers/ebpf24-mookernel.pdf)  
59. Measuring Function Latency with eBPF \- eunomia, 访问时间为 七月 1, 2025， [https://eunomia.dev/tutorials/33-funclatency/](https://eunomia.dev/tutorials/33-funclatency/)  
60. Measuring Function Latency with eBPF \- DEV Community, 访问时间为 七月 1, 2025， [https://dev.to/yunwei37/measuring-function-latency-with-ebpf-2ogk](https://dev.to/yunwei37/measuring-function-latency-with-ebpf-2ogk)  
61. With Friends like eBPF, who needs enemies ? \- Black Hat, 访问时间为 七月 1, 2025， [https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-With-Friends-Like-EBPF-Who-Needs-Enemies.pdf](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-With-Friends-Like-EBPF-Who-Needs-Enemies.pdf)  
62. Cross Container Attacks: The Bewildered eBPF on Clouds \- USENIX, 访问时间为 七月 1, 2025， [https://www.usenix.org/system/files/usenixsecurity23-he.pdf](https://www.usenix.org/system/files/usenixsecurity23-he.pdf)  
63. Detecting eBPF Rootkits Using Virtualization and Memory Forensics \- SciTePress, 访问时间为 七月 1, 2025， [https://www.scitepress.org/Papers/2024/124708/124708.pdf](https://www.scitepress.org/Papers/2024/124708/124708.pdf)  
64. eACGM: Non-instrumented Performance Tracing and Anomaly Detection towards Machine Learning Systems \- arXiv, 访问时间为 七月 1, 2025， [https://arxiv.org/html/2506.02007v1](https://arxiv.org/html/2506.02007v1)  
65. \[2503.04178\] Unsupervised anomaly detection on cybersecurity data streams: a case with BETH dataset \- arXiv, 访问时间为 七月 1, 2025， [https://arxiv.org/abs/2503.04178](https://arxiv.org/abs/2503.04178)  
66. High-performance Intrusion Detection Systemusing eBPF with Machine Learning algorithms, 访问时间为 七月 1, 2025， [https://www.researchgate.net/publication/372142095\_High-performance\_Intrusion\_Detection\_Systemusing\_eBPF\_with\_Machine\_Learning\_algorithms](https://www.researchgate.net/publication/372142095_High-performance_Intrusion_Detection_Systemusing_eBPF_with_Machine_Learning_algorithms)