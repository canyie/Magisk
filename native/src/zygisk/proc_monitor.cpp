#include <base.hpp>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <linux/ptrace.h>
#include <sys/wait.h>

#include "zygisk.hpp"
#include "ptrace.hpp"

#define INIT_PID 1

#define WEVENT(__status) (((__status) >> 16) & 0xff)

void inject_into(pid_t pid) {
    LOGI("zygisk: injecting into new zygote process %d\n", pid);
    run_finally f([=] { xptrace(PTRACE_DETACH, pid); });

}

bool check_zygote(pid_t pid) {
    char buf[PATH_MAX];
    sprintf(buf, "/proc/%d/attr/current", pid);
    if (auto fp = open_file(buf, "re")) {
        fscanf(fp.get(), "%s", buf);
        if (strcmp(buf, "u:r:zygote:s0") == 0) {
            return true;
        }
    }
    return false;
}

void* init_monitor() {
    xptrace(PTRACE_ATTACH, INIT_PID);

    waitpid(INIT_PID, nullptr, __WALL | __WNOTHREAD);
    xptrace(PTRACE_SETOPTIONS, INIT_PID, nullptr,
            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT);
    xptrace(PTRACE_CONT, INIT_PID);

    for (int status;;) {
        const int pid = waitpid(-1, &status, __WALL | __WNOTHREAD);

        if (pid < 0) // If any error occurs, give up
            goto abandon;

        int event = WEVENT(status);
        int signal = WSTOPSIG(status);
        
        if (!WIFSTOPPED(status) /* Ignore if not ptrace-stop */) {
            goto abandon;
        }

        if (signal == SIGTRAP && event) {
            unsigned long msg;
            xptrace(PTRACE_GETEVENTMSG, pid, nullptr, &msg);

            if (pid == INIT_PID) {
                switch (event) {
                    case PTRACE_EVENT_FORK:
                    case PTRACE_EVENT_VFORK:
                        LOGI("init forked: [%lu]\n", msg);
                        xptrace(PTRACE_SETOPTIONS, (pid_t) msg, nullptr,PTRACE_O_TRACEEXIT);
                        break;
                    case PTRACE_EVENT_EXIT:
                        LOGW("init exited with status: [%lu]\n", msg);
                        [[fallthrough]];
                    default:
                        goto abandon;
                }

                xptrace(PTRACE_CONT, INIT_PID);
            } else {
                switch (event) {
                    case PTRACE_EVENT_EXEC:
                        // As we don't specify PTRACE_O_TRACEEXEC, this event will be triggered AFTER execve() returns
                        if (check_zygote(pid)) {
                            inject_into(pid);
                            break;
                        }
                        [[fallthrough]];
                    case PTRACE_EVENT_EXIT:
                    default:
                        xptrace(PTRACE_DETACH, pid);
                        break;
                }
            }
        } else if (signal == SIGSTOP) {
            // produced by ptrace, just restart process
            xptrace(PTRACE_CONT, pid);
        } else {
            // Not caused by us, resend signal
            xptrace(PTRACE_CONT, pid, nullptr, signal);
        }

    }


    abandon:
    xptrace(PTRACE_DETACH, INIT_PID);
    LOGW("zygisk: stopping process monitor\n");
    return nullptr;
}

void start_zygisk() {
    new_daemon_thread(reinterpret_cast<thread_entry>(&init_monitor));
}



