#include <sys/mount.h>

#include <magisk.hpp>
#include <resetprop.hpp>
#include <utils.hpp>
#include <daemon.hpp>

#include "core.hpp"

#define VLOGD(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

static int bind_mount(const char *from, const char *to) {
    int ret = xmount(from, to, nullptr, MS_BIND, nullptr);
    if (ret == 0)
        VLOGD("bind_mnt", from, to);
    return ret;
}

void create_mirror(const char* filename) {
    static std::string mirror_dir = MAGISKTMP +  "/" MIRRDIR "/dev/__properties__/";
    std::string origin = std::string("/dev/__properties__/") + filename;
    std::string mirror = mirror_dir + filename;
    const char* mirror_raw = mirror.data();
    if (access(mirror_raw, F_OK) == 0)
        return; // Mirror has been created
    close(xopen(mirror_raw, O_RDONLY | O_CREAT | O_CLOEXEC, 0));
    bind_mount(origin.data(), mirror_raw);
}

void load_isolated_props(const std::map<std::string, std::string> &props) {
    for (auto [key, val] : props) {
        const char* filename;
        get_prop_context(key.data(), nullptr, &filename);
        if (!filename) {
            LOGW("Cannot find filename for property %s\n", key.data());
            continue;
        }
        create_mirror(filename);

        // TODO: Implement prop isolation
        setprop(key.data(), val.data(), false);
    }
}
