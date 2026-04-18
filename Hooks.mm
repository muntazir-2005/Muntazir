// Hooks.mm
// يحتوي على تعريفات دوال الاعتراض وإعداد الهوكات

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <os/log.h>
#import <mach/mach.h>
#include "dobby.h"
#include "fishhook.h"

// دوال الاعتراض التي تم الإعلان عنها في UniversalHook.mm
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
OSStatus my_LSRegisterURL(CFURLRef url, Boolean update);
CFArrayRef my_LSCopyAllApplicationURLs(void);
os_log_t my_os_log_create(const char *subsystem, const char *category);
void my_os_log_set_config(os_log_t log, void *config);
int my_fprintf(FILE *stream, const char *format, ...);
FSEventStreamRef my_FSEventStreamCreate(CFAllocatorRef allocator, FSEventStreamCallback callback, FSEventStreamContext *context, CFArrayRef pathsToWatch, FSEventStreamEventId sinceWhen, CFTimeInterval latency, FSEventStreamCreateFlags flags);
int my_proc_listallpids(void *buffer, int buffersize);
int my_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
const char *my_getprogname(void);
int my_getpid(void);
kern_return_t my_mach_port_allocate(ipc_space_t task, mach_port_right_t right, mach_port_name_t *name);
mach_msg_return_t my_mach_msg(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size, mach_msg_size_t rcv_size, mach_port_t rcv_name, mach_msg_timeout_t timeout, mach_port_t notify);
int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// المتغيرات الأصلية
int (*original_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
OSStatus (*original_LSRegisterURL)(CFURLRef, Boolean);
CFArrayRef (*original_LSCopyAllApplicationURLs)(void);
os_log_t (*original_os_log_create)(const char *, const char *);
void (*original_os_log_set_config)(os_log_t, void *);
int (*original_fprintf)(FILE *, const char *, ...);
FSEventStreamRef (*original_FSEventStreamCreate)(CFAllocatorRef, FSEventStreamCallback, FSEventStreamContext *, CFArrayRef, FSEventStreamEventId, CFTimeInterval, FSEventStreamCreateFlags);
int (*original_proc_listallpids)(void *, int);
int (*original_proc_pidinfo)(int, int, uint64_t, void *, int);
const char *(*original_getprogname)(void);
int (*original_getpid)(void);
kern_return_t (*original_mach_port_allocate)(ipc_space_t, mach_port_right_t, mach_port_name_t *);
mach_msg_return_t (*original_mach_msg)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t, mach_msg_size_t, mach_port_t, mach_msg_timeout_t, mach_port_t);
int (*original_connect)(int, const struct sockaddr *, socklen_t);

// تنفيذ الدوال
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    return original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}
OSStatus my_LSRegisterURL(CFURLRef url, Boolean update) { return noErr; }
CFArrayRef my_LSCopyAllApplicationURLs(void) { return CFArrayCreate(NULL, NULL, 0, NULL); }
os_log_t my_os_log_create(const char *subsystem, const char *category) { return NULL; }
void my_os_log_set_config(os_log_t log, void *config) {}
int my_fprintf(FILE *stream, const char *format, ...) { return 0; }
FSEventStreamRef my_FSEventStreamCreate(CFAllocatorRef a, FSEventStreamCallback c, FSEventStreamContext *ctx, CFArrayRef paths, FSEventStreamEventId id, CFTimeInterval lat, FSEventStreamCreateFlags f) { return NULL; }
int my_proc_listallpids(void *buffer, int buffersize) { return original_proc_listallpids(buffer, buffersize); }
int my_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    if (pid == getpid()) return 0;
    return original_proc_pidinfo(pid, flavor, arg, buffer, buffersize);
}
const char *my_getprogname(void) { return "Finder"; }
int my_getpid(void) { static int fake = 0; if (!fake) fake = arc4random_uniform(1000)+100; return fake; }
kern_return_t my_mach_port_allocate(ipc_space_t t, mach_port_right_t r, mach_port_name_t *n) { return KERN_SUCCESS; }
mach_msg_return_t my_mach_msg(mach_msg_header_t *m, mach_msg_option_t o, mach_msg_size_t s, mach_msg_size_t r, mach_port_t p, mach_msg_timeout_t t, mach_port_t n) { return original_mach_msg(m,o,s,r,p,t,n); }
int my_connect(int fd, const struct sockaddr *addr, socklen_t len) { return original_connect(fd, addr, len); }

// دالة تجميع الهوكات
void setupAllHooks() {
    // fishhook
    struct rebinding rebinds[] = {
        {"sysctl", (void*)my_sysctl, (void**)&original_sysctl},
        {"fprintf", (void*)my_fprintf, (void**)&original_fprintf},
        {"connect", (void*)my_connect, (void**)&original_connect}
    };
    rebind_symbols(rebinds, sizeof(rebinds)/sizeof(rebinds[0]));
    
    // Dobby hooks
    void *LSRegisterURL_ptr = dlsym(RTLD_DEFAULT, "LSRegisterURL");
    if (LSRegisterURL_ptr) DobbyHook(LSRegisterURL_ptr, (void*)my_LSRegisterURL, (void**)&original_LSRegisterURL);
    void *LSCopyAllApps = dlsym(RTLD_DEFAULT, "_LSCopyAllApplicationURLs");
    if (LSCopyAllApps) DobbyHook(LSCopyAllApps, (void*)my_LSCopyAllApplicationURLs, (void**)&original_LSCopyAllApplicationURLs);
    void *os_log_create_ptr = dlsym(RTLD_DEFAULT, "os_log_create");
    if (os_log_create_ptr) DobbyHook(os_log_create_ptr, (void*)my_os_log_create, (void**)&original_os_log_create);
    void *os_log_set_config_ptr = dlsym(RTLD_DEFAULT, "os_log_set_config");
    if (os_log_set_config_ptr) DobbyHook(os_log_set_config_ptr, (void*)my_os_log_set_config, (void**)&original_os_log_set_config);
    void *FSEventStreamCreate_ptr = dlsym(RTLD_DEFAULT, "FSEventStreamCreate");
    if (FSEventStreamCreate_ptr) DobbyHook(FSEventStreamCreate_ptr, (void*)my_FSEventStreamCreate, (void**)&original_FSEventStreamCreate);
    void *proc_listallpids = dlsym(RTLD_DEFAULT, "proc_listallpids");
    if (proc_listallpids) DobbyHook(proc_listallpids, (void*)my_proc_listallpids, (void**)&original_proc_listallpids);
    void *proc_pidinfo = dlsym(RTLD_DEFAULT, "proc_pidinfo");
    if (proc_pidinfo) DobbyHook(proc_pidinfo, (void*)my_proc_pidinfo, (void**)&original_proc_pidinfo);
    void *mach_port_allocate_ptr = dlsym(RTLD_DEFAULT, "mach_port_allocate");
    if (mach_port_allocate_ptr) DobbyHook(mach_port_allocate_ptr, (void*)my_mach_port_allocate, (void**)&original_mach_port_allocate);
    void *mach_msg_ptr = dlsym(RTLD_DEFAULT, "mach_msg");
    if (mach_msg_ptr) DobbyHook(mach_msg_ptr, (void*)my_mach_msg, (void**)&original_mach_msg);
}
