![](./images/ecapture-logo-400x400.jpg)

[English](./README.md) | 中文介绍

[![GitHub stars](https://img.shields.io/github/stars/yinwuhui/emleak.svg?label=Stars&logo=github)](https://github.com/yinwuhui/emleak)
[![GitHub forks](https://img.shields.io/github/forks/yinwuhui/emleak)](https://github.com/yinwuhui/emleak)
[![Github Version](https://img.shields.io/github/v/release/yinwuhui/emleak?display_name=tag\&include_prereleases\&sort=semver)](https://github.com/yinwuhui/emleak)

[![Example](https://github.com/yinwuhui/emleak/blob/main/images/eBPF.svg)](https://github.com/yinwuhui/emleak/blob/main/images/eBPF.svg)

### emleak(): 动态的跟踪进程的内存泄漏情况，不影响内存的读写性能

> **Note:**
>
> 支持Linux系统内核x86\_64 4.18及以上版本
>
> 不支持Windows、macOS系统。

# emleak 工作原理

eBPF `Uprobe`/`Kprobe`实现用户空间/内核空间的接口捕获，无需改动原程序。

*   基于eBPF技术，跟踪标准库的malloc/free相关的接口，以及内核的缺页事件，从而获取进程的内存使用情况。
*   基于CO-RE BTF ，避免了运行需要依赖复杂编译环境与内核头文件 
*   通过跟踪exec相关的系统调用，可以在生产环境持续的捕获进程的内存信息。
*   通过Python pygal库将内存数据可视化为柱状图与折线图。

# emleak 系统架构

# 演示

## emleak 使用方法

## 直接运行

下载 [release](https://github.com/yinwuhui/emleak/releases) 的二进制包，可直接使用。

系统配置要求

*   系统linux kernel版本必须高于4.18。
*   开启BTF [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html) 支持。 (可选, 2022-04-17)

## 运行模式

实时查看内存增长情况：

```bash
sudo ./emleak top -k -i 1
```

只采集并导出数据，不显示实时报告：

```bash
sudo ./emleak record -k -i 1 --duration 60
```

`top` 模式显示当前未释放内存、对象数、分配/释放速率、周期增长量和 Top N 调用栈；`record` 模式写入可机器读取的快照、汇总和 FlameGraph folded-stack 数据。

## 命令参数

> **Note**
>
> 需要ROOT权限执行。
    
```
./emleak -h
usage: %s [OPTS]
   Trace outstanding memory allocations that weren't freed.
Supports allocations made with libc functions
Supports allocations made with you customization functions
OPTS:
    -p    the PID to trace
    -c    the program name to trace, must start memleak before program
    -i    interval in seconds to print outstanding allocations
    -k    trace kernel memory allocations globally
    --kernel-pages    additionally trace page allocator events
    --cgroup PATH     filter allocations by cgroup path
    --sample-rate N   sample roughly one allocation in N
    --min-size BYTES  trace allocations at least this size
    --max-size BYTES  trace allocations at most this size
    --older MS        report only allocations older than MS milliseconds
    --top N            limit top mode to N rows; default fills the terminal
	--show-stacks      show resolved stack details below the top table
    --duration SEC     stop record mode after SEC seconds

./emleak -p 12356
#指定进程pid跟踪，默认10s记录一次内存信息到文件.

./emleak -c myprogname
#跟踪进程名字为myprogname，默认10s记录一次内存信息到文件. 
#进程重启也会被再次跟踪，可以将emleak后台运行，持续追踪进程。
#运行多个同名进程，只会捕获第一个启动的进程。

./emleak -p 12356 -i 1
#设置自定义的记录周期

sudo ./emleak -k -i 5
#跟踪内核 kmalloc/slab 分配和释放，使用内核调用栈定位未释放对象。
#内核模式是全局跟踪，可能包含跟踪器自身及系统服务产生的分配。

sudo ./emleak -k --pid 1234 --sample-rate 10 --min-size 4096 --older 500
#只跟踪指定进程触发的内核分配，每10次采样一次，仅保留至少4KiB且持续超过500ms的对象。

sudo ./emleak -k --comm kworker/u8:1 --cgroup /sys/fs/cgroup/my-service
#按内核线程名和cgroup限制内核分配跟踪范围。

sudo ./emleak -k --kernel-pages -i 5
#额外跟踪页分配器事件；事件量较大，适合短时间定位物理页级问题。

```

### emleak输出
   emleak会在当前目录创建 pid + time 名字的目录，相关输出信息均在这个文件夹中。

**输出为三个文本文件，每次捕获会使用进程pid创建新的文件夹，包含三个文件：**

    mleakstacks.txt ： 保存进程中所有内存申请释放相关的堆栈信息，包括总内存大小和唯一的栈ID;
    例如：
        、、、、、、、、
            15360 bytes allocated at callstack id 16325: 
                valloc_node_get+0x1c;
                memery_get_expand+0x8e;
                thread_function+0x110;
                start_thread+0x2f3;
            27648 bytes allocated at callstack id 14214: 
                malloc_node_get+0x1c;
                memery_get_expand+0x46;
                thread_function+0x110;
                start_thread+0x2f3;
        、、、、、、、、        

    mleaksummary.csv 保存结束时的聚合信息，字段为 tgid、comm、分配类型、callstack、未释放字节和对象数;

    mleakstatics.csv： 保存每个周期的快照，第一列为纳秒时间戳，随后为 tgid、comm、分配类型、callstack、未释放字节和对象数;

    mleak.folded：结束时生成的 folded stack 文件，可直接传给 flamegraph.pl;

**数据可视化：**

    tools文件夹中存在三个脚本:

    statisticsdraw.py：将mleakstatics.txt数据转换为折线图，从而分析内存全生命周期，所有的内存使用情况

    summarydraw.py：将mleaksummary.txt数据转换为柱状图，直观获取每个stack的最终的内存消耗情况
    
    flamegraph.pl：将堆栈信息绘制为火焰图

**操作步骤：**
    
```
    cp /tools/statisticsdraw.py ./outdir
    cp /tools/summarydraw.py ./outdir
    cp /tools/flamegraph.pl ./outdir

    #生成总内存分布柱状图
    python3 ./summarydraw.py
    #生成内存增长折线图
    python3 ./statisticsdraw.py
    #生成调用栈火焰图
    ./flamegraph.pl --color=mem --title="malloc() bytes Flame Graph" --countname=bytes < mleak.folded > stacks.svg
    
```

**可视化输出：**

调用栈火焰图：（调用栈的宽度和总内存大小有关）

[![Example](https://github.com/yinwuhui/emleak/blob/main/images/stacksoutput.svg)](https://github.com/yinwuhui/emleak/blob/main/images/stacksoutput.svg)

总内存分布柱状图（横坐标为callstackID，红：内存总量，蓝：申请次数）：

[![Example](https://github.com/yinwuhui/emleak/blob/main/images/summaryoutput.svg)](https://github.com/yinwuhui/emleak/blob/main/images/summaryoutput.svg)

内存变化趋势折线图（横坐标为时间，纵坐标为时刻总量，每条折线对应一个callstackID）：

[![Example](https://github.com/yinwuhui/emleak/blob/main/images/mleakstaticsoutput.svg)](https://github.com/yinwuhui/emleak/blob/main/images/mleakstaticsoutput.svg)

## 关于性能损耗
    对内存本身的读写性能没有影响，但会影响内存申请释放接口的性能。
    性能报告正在编写中。。。

## 自行编译

自行编译对编译环境有要求，参考**原理**章节的介绍。

# 原理

## eBPF技术

参考[ebpf](https://ebpf.io)官网的介绍

## uprobe HOOK

# 编译方法

笔者环境`ubuntu 22.04`， Linux Kernel 4.18以上通用。
**推荐使用`UBUNTU 20.04` 及以上版本的Linux测试。**

## 工具链版本

*   clang 12 以上
*   clang backend: llvm 12 以上
*   kernel config\:CONFIG\_DEBUG\_INFO\_BTF=y (可选)

## 编译
```
    ##预处理：
        由于libbpf-bootstrap项目中一个bug，如果您拉取的时候已修复，这步可以忽略。
        需要修改文件：vim libbpf-bootstrap/vmlinux/x86/vmlinux.h 第一行：
        源数据：vmlinux_601.h
        改为：#include "vmlinux_601.h"

    #获取代码
    git clone --recurse-submodules https://github.com/yinwuhui/emleak.git

    #编译bcc静态开发库libcc.a
    cd bcc
    请参考bcc项目：./bcc/INSTALL.md
    编译完成后:
    cp ./build/src/cc/libbcc.a ../src/bcclib/libbcc.a
    cd ..

    #编译emleak
    apt install gcc g++ make libelf-dev libbpf-dev clang llvm 

    cd src
    make
```

## 后续开发计划
```
    1、支持跟踪用户自定义的内存申请/释放接口
    2、完善内核内存泄漏监测（当前已支持 kmalloc/slab 分配，页分配为实验性选项）
    3、支持启用物理内存泄漏检测
    4、适配主流Linux发行版本
```
    

# 参考资料

[eBPF Documentation](https://ebpf.io/what-is-ebpf/)

[BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)

[bpf(2) — Linux manual page](https://man7.org/linux/man-pages/man2/bpf.2.html)
