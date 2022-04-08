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

void create_mirror(std::string raw, std::string mirror, std::string dirty) {
    const char* mirror_raw = mirror.data();
    if (access(mirror_raw, F_OK) == 0)
        return; // Mirror has been created
    close(xopen(mirror_raw, O_RDONLY | O_CREAT | O_CLOEXEC, 0));

    clone_attr(raw.data(), mirror_raw);
    bind_mount(raw.data(), mirror_raw);

    // Create the "dirty" area
    cp_afc(raw.data(), dirty.data());

    // Let any isolated writing performs on it
    bind_mount(dirty.data(), raw.data());
}

void load_isolated_props(const std::map<std::string, std::string> &props) {
    LOGI("Creating mirror for isolated properties\n");
    std::string raw_dir = "/dev/__properties__/";
    std::string mirror_dir = MAGISKTMP + "/" MIRRDIR "/properties/";
    std::string dirty_dir = MAGISKTMP + "/" INTLROOT "/dirty/properties/";

    file_attr attr;
    getattr(raw_dir.data(), &attr);
    mkdirs(mirror_dir, 0);
    setattr(mirror_dir.data(), &attr);
    mkdirs(dirty_dir, 0);
    setattr(dirty_dir.data(), &attr);

    for (auto [key, val] : props) {
        const char* filename;
        get_prop_context(key.data(), &filename, nullptr);
        if (!filename) {
            LOGW("Cannot find context for property %s\n", key.data());
            continue;
        }
        create_mirror(raw_dir + filename, mirror_dir + filename, dirty_dir + filename);
    }
    // Reload properties data to make sure isolated property changes will write to the dirty area
    LOGI("Reloading properties\n");
    reinit_props();

    // Write changes to dirty area
    LOGI("Writing isolated property changes\n");
    for (auto [key, val] : props) {
        setprop(key.data(), val.data(), false);
    }
}
