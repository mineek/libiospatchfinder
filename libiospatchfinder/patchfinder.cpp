#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp>
#include <stdlib.h>
#include <functional>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

using namespace tihmstar::patchfinder;

struct found_offset {
    char *name;
    uint64_t addr;
};

std::vector<uint8_t> old_readFile(const char *path){
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    });
    struct stat st = {};
    retassure((fd = open(path, O_RDONLY)) != -1, "Failed to open file at path '%s'",path);
    std::vector<uint8_t> ret;
    retassure((fd = open(path, O_RDONLY)) != -1, "Failed to open file at path '%s'",path);
    retassure(!fstat(fd, &st), "Failed to fstat file at path '%s'",path);
    ret.resize(st.st_size);
    retassure(read(fd, ret.data(), ret.size()) == ret.size(), "Failed to read file at path '%s'",path);
    return ret;
}

extern "C" bool isarm64e(void);

void saveToFile(const char *filePath, const void *buf, size_t bufSize){
    FILE *f = NULL;
    cleanup([&]{
        if (f) {
            fclose(f);
        }
    });

    retassure(f = fopen(filePath, "wb"), "failed to create file");
    retassure(fwrite(buf, 1, bufSize, f) == bufSize, "failed to write to file");
}

char *readFromFile(const char *filePath, size_t *outSize){
    FILE *f = fopen(filePath, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *ret = (char*)malloc(size);
    if (ret) fread(ret, size, 1, f);
    fclose(f);
    if (outSize) *outSize = size;

    return ret;
}

extern "C" int find_offsets(const char* kernel_path) {
    info("offsetexporter: %s",VERSION_STRING);
    kernelpatchfinder64 *kpf = nullptr;
    cleanup([&]{
        safeDelete(kpf);
    });
    info("Init KPF('%s')",kernel_path);
    try {
        kpf = kernelpatchfinder64::make_kernelpatchfinder64(kernel_path);
    } catch (tihmstar::exception &e) {
        printf("Failed to init KPF: %s\n",e.what());
        return -1;
    }
    retassure(kpf, "Failed to init KPF");
    info("KPF initialized");
    std::vector<found_offset> offsets;
    auto add_offset = [&](const char *name, uint64_t addr){
        info("Found offset '%s' at 0x%llx",name,addr);
        offsets.push_back({strdup(name), addr});
    };
    try {
    if (isarm64e()) {
        add_offset("vn_kqfilter", kpf->find_function_vn_kqfilter());
    }
    add_offset("base", 0xFFFFFFF007004000);
    add_offset("perfmon_devices", kpf->find_perfmon_devices());
    add_offset("cdevsw", kpf->find_cdevsw());
    add_offset("perfmon_dev_open", kpf->find_bof_with_sting_ref("perfmon: attempt to open unsupported source", 0));
    add_offset("ptov_table", kpf->find_ptov_table());
    add_offset("gVirtBase", kpf->find_gVirtBase());
    add_offset("gPhysBase", kpf->find_gPhysBase());
    add_offset("gPhysSize", (kpf->find_gPhysBase() + 0x8));
    } catch (tihmstar::exception &e) {
        printf("Failed to find offsets: %s\n",e.what());
        return -1;
    }
    int fd = -1;
    retassure((fd = open("/var/mobile/offsets.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644)) != -1, "Failed to open offsets file");
    for (auto &offset : offsets) {
        dprintf(fd, "%s: 0x%llx\n", offset.name, offset.addr);
    }
    info("done finding offsets");
    return 0;
}