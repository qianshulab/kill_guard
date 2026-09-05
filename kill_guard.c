// 内核模块：拦截向目标进程发送的 SIGKILL
// 编译后 insmod kill_guard.ko target_pid=<app_pid> block_mode=1
// 卸载：rmmod kill_guard
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/uaccess.h>

static int target_pid = 0;
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "PID to protect from SIGKILL");

static int block_mode = 0;
module_param(block_mode, int, 0644);
MODULE_PARM_DESC(block_mode, "0=observe only, 1=block SIGKILL");

static int kill_count = 0;

static int kill_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    long pid = regs->regs[0];
    int sig = (int)regs->regs[1];

    if (sig == 9 && pid == target_pid) {
        kill_count++;
        if (block_mode) {
            printk(KERN_INFO "kill_guard: ★ BLOCKED SIGKILL #%d to pid=%ld\n", kill_count, pid);
            // 让 syscall 返回 -EPERM
            regs->regs[0] = -EPERM;
            // 跳过 syscall：把 pc 设为 lr（返回地址）
            regs->pc = regs->regs[30];
        } else {
            printk(KERN_INFO "kill_guard: observed SIGKILL #%d to pid=%ld\n", kill_count, pid);
        }
    }
    return 0;
}

static int tgkill_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    long tgid = regs->regs[0];
    long tid = regs->regs[1];
    int sig = (int)regs->regs[2];

    if (sig == 9 && (tgid == target_pid || tid == target_pid)) {
        kill_count++;
        if (block_mode) {
            printk(KERN_INFO "kill_guard: ★ BLOCKED tgkill #%d to tgid=%ld tid=%ld\n", kill_count, tgid, tid);
            regs->regs[0] = -EPERM;
            regs->pc = regs->regs[30];
        } else {
            printk(KERN_INFO "kill_guard: observed tgkill #%d to tgid=%ld\n", kill_count, tgid);
        }
    }
    return 0;
}

static struct kprobe kp_kill = {
    .symbol_name = "__arm64_sys_kill",
    .pre_handler = kill_pre_handler,
};

static struct kprobe kp_tgkill = {
    .symbol_name = "__arm64_sys_tgkill",
    .pre_handler = tgkill_pre_handler,
};

static int __init kill_guard_init(void)
{
    int ret;

    ret = register_kprobe(&kp_kill);
    if (ret < 0) {
        printk(KERN_ERR "kill_guard: kill kprobe failed: %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&kp_tgkill);
    if (ret < 0) {
        printk(KERN_ERR "kill_guard: tgkill kprobe failed: %d\n", ret);
        unregister_kprobe(&kp_kill);
        return ret;
    }

    printk(KERN_INFO "kill_guard: loaded (target_pid=%d mode=%s) — kill/tgkill both hooked\n",
           target_pid, block_mode ? "BLOCK" : "OBSERVE");
    return 0;
}

static void __exit kill_guard_exit(void)
{
    unregister_kprobe(&kp_kill);
    unregister_kprobe(&kp_tgkill);
    printk(KERN_INFO "kill_guard: unloaded (blocked %d kills)\n", kill_count);
}

module_init(kill_guard_init);
module_exit(kill_guard_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Block SIGKILL to target process (frida protection)");
MODULE_AUTHOR("frida-tools");
