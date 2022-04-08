#include <sys/mount.h>

#include <magisk.hpp>
#include <utils.hpp>

#include "deny.hpp"
#include "zygisk/zygisk.hpp"

using namespace std;

static void lazy_unmount(const char* mountpoint) {
    if (umount2(mountpoint, MNT_DETACH) != -1)
        LOGD("denylist: Unmounted (%s)\n", mountpoint);
}

#define TMPFS_MNT(dir) (mentry->mnt_type == "tmpfs"sv && str_starts(mentry->mnt_dir, "/" #dir))

void revert_unmount(std::vector<std::string> *prop_areas) {
    vector<string> targets;
    auto mirror_mnt = MAGISKTMP + "/" MIRRDIR;

    // Unmount dummy skeletons and MAGISKTMP
    targets.push_back(MAGISKTMP);
    parse_mnt("/proc/self/mounts", [&](mntent *mentry) {
        if (TMPFS_MNT(system) || TMPFS_MNT(vendor) || TMPFS_MNT(product) || TMPFS_MNT(system_ext))
            targets.emplace_back(mentry->mnt_dir);
        else if (TMPFS_MNT(dev/__properties__)) {
            targets.emplace_back(mentry->mnt_dir);
            if (prop_areas)
                prop_areas->emplace_back(mentry->mnt_dir);
        }
        return true;
    });

    for (auto &s : reversed(targets))
        lazy_unmount(s.data());
    targets.clear();

    // Unmount all Magisk created mounts
    parse_mnt("/proc/self/mounts", [&](mntent *mentry) {
        if (str_contains(mentry->mnt_fsname, BLOCKDIR))
            targets.emplace_back(mentry->mnt_dir);
        return true;
    });

    for (auto &s : reversed(targets))
        lazy_unmount(s.data());
}

void remap_props(std::vector<std::string> &areas) {
    for (auto file : areas) {
        int fd = open(file.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd == -1) {
            // Property area no longer accessible by the process
            continue;
        }
        auto all = find_maps(file.data());
        if (all.empty()) {
            continue;
        }
        for (auto info : all) {
            auto size = info.end - info.start;
            // Remap prop areas to redirect properties to the original
            munmap(reinterpret_cast<void*>(info.start), size);
            xmmap(reinterpret_cast<void*>(info.start), size, PROT_READ,
                 MAP_SHARED | MAP_FIXED, fd, 0);
        }
        close(fd);
    }
}
