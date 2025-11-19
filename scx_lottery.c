/* SPDX-License-Identifier: GPL-2.0 */ // SPDX许可证标识：GPL-2.0
/*
 * SCX Lottery Scheduler - 用户空间部分
 */  // SCX彩票调度器 - 用户空间部分
#include <linux/types.h> // 提供 u64 等整数类型定义
#include <stdarg.h> // 提供 va_list 声明
#include <stdbool.h> // bool 类型
#include <string.h> // memset 原型
#include <scx/common.h> // 包含SCX公共头文件
#include "scx_lottery.bpf.skel.h" // 包含BPF骨架头文件
#include <bpf/bpf.h> // 包含BPF库头文件
#include <bpf/libbpf.h> // libbpf 相关 API
#include <libgen.h> // 包含路径处理库头文件
#include <signal.h> // 包含信号处理头文件
#include <stdio.h> // 包含标准输入输出头文件
#include <unistd.h> // 包含UNIX标准头文件
#include <assert.h> // 包含断言头文件

const char help_fmt[] =
	"彩票调度器，根据任务的优先级分配彩票数量\n" // 帮助信息格式字符串
	"\n" // 空行
	"使用方法: %s [-v] [-h]\n" // 使用方法说明
	"\n" // 空行
	"  -v            打印 libbpf 调试信息\n" // -v选项说明
	"  -h            显示帮助信息并退出\n"; // -h选项说明

static bool verbose; // 是否启用详细模式标志
static volatile int exit_req; // 退出请求标志（volatile确保多线程可见性）

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args) // libbpf打印回调函数
{
	if (level == LIBBPF_DEBUG &&
	    !verbose) // 如果是DEBUG级别且不启用详细模式
		return 0; // 返回0不打印
	return vfprintf(stderr, format, args); // 打印到标准错误输出
}

static void sigint_handler(int sig) // SIGINT信号处理函数
{
	(void)sig; // 避免未使用参数警告
	exit_req = 1; // 设置退出请求标志
}

static void read_stats(struct scx_lottery_bpf *skel,
		       __u64 *stats) // 读取统计信息的函数
{
	int nr_cpus = libbpf_num_possible_cpus(); // 获取系统CPU数量
	assert(nr_cpus > 0); // 断言CPU数量大于0
	__u64 cnts[2][nr_cpus]; // 定义计数数组，2个统计项×CPU数量
	__u32 idx; // 循环索引

	memset(stats, 0, sizeof(stats[0]) * 2); // 将统计数组清零

	for (idx = 0; idx < 2; idx++) { // 遍历2个统计项
		int ret, cpu; // 返回值和CPU循环变量

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, // 从BPF映射中查找统计值
					  cnts[idx]); // 存储到计数数组
		if (ret < 0) // 如果查找失败
			continue; // 继续下一个循环
		for (cpu = 0; cpu < nr_cpus; cpu++) // 遍历所有CPU
			stats[idx] += cnts[idx][cpu]; // 累加每个CPU的统计值
	}
}

int main(int argc, char **argv) // 主函数
{
	struct scx_lottery_bpf *skel; // BPF骨架结构体指针
	struct bpf_link *link; // BPF链接指针
	int opt; // 命令行选项变量
	__u64 ecode; // 退出代码

	libbpf_set_print(libbpf_print_fn); // 设置libbpf打印回调函数
	signal(SIGINT, sigint_handler); // 注册SIGINT信号处理函数
	signal(SIGTERM, sigint_handler); // 注册SIGTERM信号处理函数

restart: // 重启标签（用于调度器重启）
	skel = SCX_OPS_OPEN(lottery_ops, scx_lottery_bpf); // 打开BPF操作

	while ((opt = getopt(argc, argv, "vh")) != -1) { // 解析命令行参数
		switch (opt) { // 根据选项处理
		case 'v': // -v选项：启用详细模式
			verbose = true; // 设置详细模式标志
			break; // 退出switch
		case 'h': // -h选项：显示帮助
		default: // 默认情况或-h选项
			fprintf(stderr, help_fmt,
				basename(argv[0])); // 打印帮助信息
			return opt != 'h'; // 如果是-h则返回0成功，否则返回1失败
		} // switch结束
	} // while循环结束

	SCX_OPS_LOAD(skel, lottery_ops, scx_lottery_bpf, uei); // 加载BPF程序
	link = SCX_OPS_ATTACH(skel, lottery_ops,
			      scx_lottery_bpf); // 附加BPF程序

	printf("彩票调度器已启动，按 Ctrl+C 退出\n"); // 打印启动信息

	while (!exit_req &&
	       !UEI_EXITED(skel, uei)) { // 当不退出且BPF程序未退出时循环
		__u64 stats[2]; // 统计信息数组
		read_stats(skel, stats); // 读取统计信息
		printf("调度次数: %llu, 随机数生成次数: %llu\n",
		       stats[0], // 打印调度次数
		       stats[1]); // 打印随机数生成次数
		fflush(stdout); // 刷新输出缓冲区
		sleep(1); // 休眠1秒
	} // 主循环结束

	bpf_link__destroy(link); // 销毁BPF链接
	ecode = UEI_REPORT(skel, uei); // 获取退出代码报告
	scx_lottery_bpf__destroy(skel); // 销毁BPF骨架

	if (UEI_ECODE_RESTART(ecode)) // 如果退出代码表示需要重启
		goto restart; // 跳转到restart标签重启调度器

	return 0; // 返回成功
} // 主函数结束