/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SCX Lottery Scheduler - BPF部分
 * 实现基于彩票的调度算法
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* 彩票调度参数 */
const volatile u64 default_tickets = 1000; // 默认彩票数量
const volatile u64 max_tickets = 10000;    // 最大彩票数量
const volatile u64 min_tickets = 10;       // 最小彩票数量

/* 统计信息 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u64));
  __uint(max_entries, 2); // [调度次数, 随机数生成次数]
} stats SEC(".maps");

/* 任务彩票信息 */
struct task_lottery_info {
  u64 tickets;            // 任务彩票数量
  u64 last_dispatch_time; // 最后调度时间
};

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct task_lottery_info);
} task_lottery_map SEC(".maps");

/* 调度器退出信息 */
UEI_DEFINE(uei);

/* 获取任务彩票信息 */
struct task_lottery_info *lookup_task_lottery(const struct task_struct *p) {
  struct task_lottery_info *info;

  info = bpf_task_storage_get(&task_lottery_map, (struct task_struct *)p, 0, 0);
  if (!info) {
    scx_bpf_error("task_lottery_info lookup failed for task %p", p);
    return NULL;
  }

  return info;
}

/* 根据 nice 值计算彩票数量 */
static u64 nice_to_tickets(s64 nice) {
  u64 tickets;

  // nice 值范围 [-20, 19]，转换为 [10, 10000] 的彩票范围
  if (nice <= -20)
    tickets = max_tickets;
  else if (nice >= 19)
    tickets = min_tickets;
  else {
    // 线性映射
    s64 nice_range = nice + 20; // [0, 39]
    tickets = max_tickets - (nice_range * (max_tickets - min_tickets)) / 39;
  }

  return tickets;
}

/* 初始化任务的彩票信息 */
s32 BPF_STRUCT_OPS(lottery_init_task, struct task_struct *p,
                   struct scx_init_task_args *args) {
  struct task_lottery_info *info;
  u64 tickets;

  info = bpf_task_storage_get(&task_lottery_map, p, 0,
                              BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!info)
    return -ENOMEM;

  // 根据任务的 nice 值分配彩票
  tickets = nice_to_tickets(p->static_prio - 120); // 转换为 [-20, 19] 范围
  info->tickets = tickets;
  info->last_dispatch_time = scx_bpf_now();

  return 0;
}

/* 选择 CPU - 用于唤醒路径 */
s32 BPF_STRUCT_OPS(lottery_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags) {
  struct task_lottery_info *info;
  bool is_idle = false;
  s32 cpu;

  info = lookup_task_lottery(p);
  if (!info)
    return prev_cpu;

  // 使用默认的 CPU 选择逻辑
  cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
  if (is_idle) {
    // 如果 CPU 空闲，直接在本地队列调度
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    return cpu;
  }

  return cpu;
}

/* 任务入队 */
void BPF_STRUCT_OPS(lottery_enqueue, struct task_struct *p, u64 enq_flags) {
  struct task_lottery_info *info;

  info = lookup_task_lottery(p);
  if (!info)
    return;

  // 将任务添加到全局调度队列，使用彩票数量作为调度依据
  // 在实际实现中，这里会实现彩票选择算法
  scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

/* 任务调度 */
void BPF_STRUCT_OPS(lottery_dispatch, s32 cpu, struct task_struct *prev) {
  // 从全局队列移动任务到当前 CPU 的本地队列
  scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL);
}

/* 统计函数 */
static void stat_inc(u32 idx) {
  u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
  if (cnt_p)
    (*cnt_p)++;
}

/* 任务开始运行 */
void BPF_STRUCT_OPS(lottery_running, struct task_struct *p) {
  struct task_lottery_info *info;

  info = lookup_task_lottery(p);
  if (!info)
    return;

  stat_inc(0); // 增加调度次数统计
}

/* 任务停止运行 */
void BPF_STRUCT_OPS(lottery_stopping, struct task_struct *p, bool runnable) {
  struct task_lottery_info *info;

  info = lookup_task_lottery(p);
  if (!info)
    return;

  info->last_dispatch_time = scx_bpf_now();
}

/* 任务退出 */
void BPF_STRUCT_OPS(lottery_exit_task, struct task_struct *p,
                    struct scx_exit_task_args *args) {
  // 任务退出时不需要特殊处理
}

/* 调度器初始化 */
s32 BPF_STRUCT_OPS_SLEEPABLE(lottery_init) { return 0; }

/* 调度器退出 */
void BPF_STRUCT_OPS(lottery_exit, struct scx_exit_info *ei) {
  UEI_RECORD(uei, ei);
}

/* 注册调度器操作 */
SCX_OPS_DEFINE(lottery_ops, .select_cpu = (void *)lottery_select_cpu,
               .enqueue = (void *)lottery_enqueue,
               .dispatch = (void *)lottery_dispatch,
               .running = (void *)lottery_running,
               .stopping = (void *)lottery_stopping,
               .init_task = (void *)lottery_init_task,
               .exit_task = (void *)lottery_exit_task,
               .init = (void *)lottery_init, .exit = (void *)lottery_exit,
               .name = "lottery");