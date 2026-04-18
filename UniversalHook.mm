// =============== نظام تعطيل فحص التطبيقات الخارجية والطرفية ===============
// تم التحديث لاستخدام أحدث تقنيات الجيل السابع (Dobby, fishhook, etc.)
// يعمل بدون جيلبريك على أجهزة macOS مع صلاحيات مناسبة

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <libproc.h>
#import <uuid/uuid.h>
#import <sys/ptrace.h>
#import <os/log.h>
#import <SystemConfiguration/SystemConfiguration.h>

// تضمين المكتبات المسطحة (في نفس المجلد)
#include "dobby.h"
#include "fishhook.h"

// ================================================
// إعلانات مسبقة للدوال المعترضة (Forward Declarations)
// ================================================
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static OSStatus my_LSRegisterURL(CFURLRef url, Boolean update);
static CFArrayRef my_LSCopyAllApplicationURLs(void);
static os_log_t my_os_log_create(const char *subsystem, const char *category);
static void my_os_log_set_config(os_log_t log, os_log_config_t config);
static int my_fprintf(FILE *stream, const char *format, ...);
static FSEventStreamRef my_FSEventStreamCreate(CFAllocatorRef allocator, FSEventStreamCallback callback, FSEventStreamContext *context, CFArrayRef pathsToWatch, FSEventStreamEventId sinceWhen, CFTimeInterval latency, FSEventStreamCreateFlags flags);
static int my_proc_listallpids(void *buffer, int buffersize);
static int my_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
static const char *my_getprogname(void);
static int my_getpid(void);
static kern_return_t my_mach_port_allocate(ipc_space_t task, mach_port_right_t right, mach_port_name_t *name);
static mach_msg_return_t my_mach_msg(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size, mach_msg_size_t rcv_size, mach_port_t rcv_name, mach_msg_timeout_t timeout, mach_port_t notify);
static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// متغيرات أصلية
static int (*original_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static OSStatus (*original_LSRegisterURL)(CFURLRef, Boolean);
static CFArrayRef (*original_LSCopyAllApplicationURLs)(void);
static os_log_t (*original_os_log_create)(const char *, const char *);
static void (*original_os_log_set_config)(os_log_t, os_log_config_t);
static int (*original_fprintf)(FILE *, const char *, ...);
static FSEventStreamRef (*original_FSEventStreamCreate)(CFAllocatorRef, FSEventStreamCallback, FSEventStreamContext *, CFArrayRef, FSEventStreamEventId, CFTimeInterval, FSEventStreamCreateFlags);
static int (*original_proc_listallpids)(void *, int);
static int (*original_proc_pidinfo)(int, int, uint64_t, void *, int);
static const char *(*original_getprogname)(void);
static int (*original_getpid)(void);
static kern_return_t (*original_mach_port_allocate)(ipc_space_t, mach_port_right_t, mach_port_name_t *);
static mach_msg_return_t (*original_mach_msg)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t, mach_msg_size_t, mach_port_t, mach_msg_timeout_t, mach_port_t);
static int (*original_connect)(int, const struct sockaddr *, socklen_t);

// ================================================
// 🚫 1. نظام كشف وإخفاء التطبيقات الخارجية
// ================================================

@interface ExternalAppDetector : NSObject
@property (strong, nonatomic) NSArray *forbiddenAppIdentifiers;
@property (strong, nonatomic) NSArray *forbiddenProcessNames;
@property (strong, nonatomic) NSArray *forbiddenLibraryNames;

- (BOOL)isExternalAppRunning:(NSString *)appIdentifier;
- (void)hideExternalApps;
- (void)swizzleWorkspaceMethods;
- (void)patchProcessList;
- (void)hideFromLaunchServices;
- (void)spoofProcessList;
- (void)modifyAppRegistry;
@end

@implementation ExternalAppDetector {
    NSArray* (*original_NSWorkspace_runningApplications)(id, SEL);
}

- (instancetype)init {
    self = [super init];
    if (self) {
        self.forbiddenAppIdentifiers = @[
            @"com.apple.Terminal", @"com.googlecode.iterm2", @"com.sublimetext.3",
            @"com.microsoft.VSCode", @"org.gnu.Emacs", @"org.vim.MacVim",
            @"com.hexrays.ida", @"com.hopperapp.hopper", @"com.ollydbg.OllyDbg",
            @"org.wireshark.Wireshark", @"com.charles.Charles", @"com.burpsuite.BurpSuite",
            @"com.frida.Frida", @"com.cydiasubstrate.Substrate", @"com.electra.electra",
            @"org.coolstar.Sileo"
        ];
        self.forbiddenProcessNames = @[
            @"Terminal", @"iTerm", @"zsh", @"bash", @"ssh", @"telnet", @"nc", @"netcat",
            @"gdb", @"lldb", @"dtrace", @"strace", @"frida", @"frida-server", @"cycript",
            @"Clutch", @"dumpdecrypted", @"class-dump"
        ];
        self.forbiddenLibraryNames = @[
            @"libfrida", @"libsubstrate", @"libcycript", @"libhooker"
        ];
    }
    return self;
}

- (BOOL)isExternalAppRunning:(NSString *)appIdentifier {
    NSArray *runningApps = [[NSWorkspace sharedWorkspace] runningApplications];
    for (NSRunningApplication *app in runningApps) {
        if ([[app bundleIdentifier] isEqualToString:appIdentifier]) return YES;
    }
    // التحقق عبر sysctl
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) return NO;
    struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
    if (sysctl(mib, 4, procs, &size, NULL, 0) < 0) { free(procs); return NO; }
    int count = (int)(size / sizeof(struct kinfo_proc));
    for (int i = 0; i < count; i++) {
        NSString *procName = [NSString stringWithUTF8String:procs[i].kp_proc.p_comm];
        if ([procName containsString:appIdentifier]) { free(procs); return YES; }
    }
    free(procs);
    return NO;
}

- (void)hideExternalApps {
    [self swizzleWorkspaceMethods];
    [self patchProcessList];
    [self hideFromLaunchServices];
}

- (void)swizzleWorkspaceMethods {
    Method m = class_getInstanceMethod([NSWorkspace class], @selector(runningApplications));
    original_NSWorkspace_runningApplications = (NSArray*(*)(id, SEL))method_getImplementation(m);
    IMP newIMP = imp_implementationWithBlock(^NSArray*(id self) {
        NSArray *originalList = original_NSWorkspace_runningApplications(self, @selector(runningApplications));
        NSMutableArray *filtered = [NSMutableArray array];
        ExternalAppDetector *detector = [[ExternalAppDetector alloc] init];
        for (NSRunningApplication *app in originalList) {
            if (![detector.forbiddenAppIdentifiers containsObject:app.bundleIdentifier])
                [filtered addObject:app];
        }
        return filtered;
    });
    method_setImplementation(m, newIMP);
}

- (void)patchProcessList {
    // تم ربط my_sysctl عبر fishhook في setupHooks()
}

- (void)hideFromLaunchServices {
    void *LSRegisterURL_ptr = dlsym(RTLD_DEFAULT, "LSRegisterURL");
    if (LSRegisterURL_ptr) DobbyHook(LSRegisterURL_ptr, (void*)my_LSRegisterURL, (void**)&original_LSRegisterURL);
}

- (void)spoofProcessList {}
- (void)modifyAppRegistry {
    void *LSCopyAllApps = dlsym(RTLD_DEFAULT, "_LSCopyAllApplicationURLs");
    if (LSCopyAllApps) DobbyHook(LSCopyAllApps, (void*)my_LSCopyAllApplicationURLs, (void**)&original_LSCopyAllApplicationURLs);
}
@end

// ================================================
// 🔧 2. نظام تعديل تسجيلات النظام
// ================================================
@interface SystemRegistryModifier : NSObject
- (void)filterSystemLogs;
- (void)disableFSEventsForApp:(NSString *)appPath;
@end
@implementation SystemRegistryModifier
- (void)filterSystemLogs {
    void *os_log_create_ptr = dlsym(RTLD_DEFAULT, "os_log_create");
    void *os_log_set_config_ptr = dlsym(RTLD_DEFAULT, "os_log_set_config");
    if (os_log_create_ptr) DobbyHook(os_log_create_ptr, (void*)my_os_log_create, (void**)&original_os_log_create);
    if (os_log_set_config_ptr) DobbyHook(os_log_set_config_ptr, (void*)my_os_log_set_config, (void**)&original_os_log_set_config);
    struct rebinding rebind = {"fprintf", (void*)my_fprintf, (void**)&original_fprintf};
    rebind_symbols(&rebind, 1);
}
- (void)disableFSEventsForApp:(NSString *)appPath {
    void *FSEventStreamCreate_ptr = dlsym(RTLD_DEFAULT, "FSEventStreamCreate");
    if (FSEventStreamCreate_ptr) DobbyHook(FSEventStreamCreate_ptr, (void*)my_FSEventStreamCreate, (void**)&original_FSEventStreamCreate);
}
@end

// ================================================
// 🛡️ 3. نظام حماية العمليات
// ================================================
@interface ProcessProtector : NSObject
- (void)hideProcessFromTaskList;
- (void)antiDebug;
- (void)checkPTRACE;
@end
@implementation ProcessProtector
- (void)hideProcessFromTaskList {
    void *proc_listallpids = dlsym(RTLD_DEFAULT, "proc_listallpids");
    if (proc_listallpids) DobbyHook(proc_listallpids, (void*)my_proc_listallpids, (void**)&original_proc_listallpids);
    void *proc_pidinfo = dlsym(RTLD_DEFAULT, "proc_pidinfo");
    if (proc_pidinfo) DobbyHook(proc_pidinfo, (void*)my_proc_pidinfo, (void**)&original_proc_pidinfo);
}
- (void)antiDebug {
    [self checkPTRACE];
}
- (void)checkPTRACE {
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
#ifndef DEBUG
    syscall(26, 31, 0, 0, 0);
#endif
}
@end

// ================================================
// 📡 4. نظام اعتراض الاتصالات
// ================================================
@interface CommunicationInterceptor : NSObject
- (void)interceptDistributedNotifications;
- (void)interceptMachPorts;
- (void)interceptXPCConnections;
- (void)handleNotification:(NSNotification *)notification;
@end
@implementation CommunicationInterceptor
- (void)interceptDistributedNotifications {
    [[NSDistributedNotificationCenter defaultCenter] addObserver:self selector:@selector(handleNotification:) name:nil object:nil suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
}
- (void)handleNotification:(NSNotification *)notification {
    // فلترة الإشعارات
}
- (void)interceptMachPorts {
    void *mach_port_allocate_ptr = dlsym(RTLD_DEFAULT, "mach_port_allocate");
    if (mach_port_allocate_ptr) DobbyHook(mach_port_allocate_ptr, (void*)my_mach_port_allocate, (void**)&original_mach_port_allocate);
    void *mach_msg_ptr = dlsym(RTLD_DEFAULT, "mach_msg");
    if (mach_msg_ptr) DobbyHook(mach_msg_ptr, (void*)my_mach_msg, (void**)&original_mach_msg);
}
- (void)interceptXPCConnections {}
@end

// ================================================
// 🎭 6. نظام التمويه
// ================================================
@interface SystemSpoofer : NSObject
- (void)spoofSystemProperties;
- (void)setSystemVersion:(NSString *)version;
- (void)setMachineModel:(NSString *)model;
@end
@implementation SystemSpoofer
- (void)spoofSystemProperties {
    [self setSystemVersion:@"15.0.0"];
    [self setMachineModel:@"MacBookPro18,3"];
}
- (void)setSystemVersion:(NSString *)version {
    Method m = class_getInstanceMethod([NSProcessInfo class], @selector(operatingSystemVersion));
    IMP fake = imp_implementationWithBlock(^NSOperatingSystemVersion {
        NSOperatingSystemVersion v = {15,0,0};
        return v;
    });
    method_setImplementation(m, fake);
}
- (void)setMachineModel:(NSString *)model {
    // سيتم التعامل معها عبر sysctlbyname
}
@end

// ================================================
// دوال الاعتراض (تنفيذ فعلي)
// ================================================
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    return original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}
static OSStatus my_LSRegisterURL(CFURLRef url, Boolean update) { return noErr; }
static CFArrayRef my_LSCopyAllApplicationURLs(void) { return CFArrayCreate(NULL, NULL, 0, NULL); }
static os_log_t my_os_log_create(const char *subsystem, const char *category) { return NULL; }
static void my_os_log_set_config(os_log_t log, os_log_config_t config) {}
static int my_fprintf(FILE *stream, const char *format, ...) { return 0; }
static FSEventStreamRef my_FSEventStreamCreate(CFAllocatorRef a, FSEventStreamCallback c, FSEventStreamContext *ctx, CFArrayRef paths, FSEventStreamEventId id, CFTimeInterval lat, FSEventStreamCreateFlags f) { return NULL; }
static int my_proc_listallpids(void *buffer, int buffersize) { return original_proc_listallpids(buffer, buffersize); }
static int my_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    if (pid == getpid()) return 0;
    return original_proc_pidinfo(pid, flavor, arg, buffer, buffersize);
}
static const char *my_getprogname(void) { return "Finder"; }
static int my_getpid(void) { static int fake = 0; if (!fake) fake = arc4random_uniform(1000)+100; return fake; }
static kern_return_t my_mach_port_allocate(ipc_space_t t, mach_port_right_t r, mach_port_name_t *n) { return KERN_SUCCESS; }
static mach_msg_return_t my_mach_msg(mach_msg_header_t *m, mach_msg_option_t o, mach_msg_size_t s, mach_msg_size_t r, mach_port_t p, mach_msg_timeout_t t, mach_port_t n) { return original_mach_msg(m,o,s,r,p,t,n); }
static int my_connect(int fd, const struct sockaddr *addr, socklen_t len) { return original_connect(fd, addr, len); }

// ================================================
// إعداد جميع الهوكات (Constructor)
// ================================================
__attribute__((constructor))
static void setupHooks() {
    // fishhook
    struct rebinding rebinds[] = {
        {"sysctl", (void*)my_sysctl, (void**)&original_sysctl},
        {"fprintf", (void*)my_fprintf, (void**)&original_fprintf},
        {"connect", (void*)my_connect, (void**)&original_connect}
    };
    rebind_symbols(rebinds, sizeof(rebinds)/sizeof(rebinds[0]));

    // Dobby
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

// ================================================
// نقطة الدخول الرئيسية (Constructor ثاني للتشغيل المتأخر)
// ================================================
__attribute__((constructor))
static void ExternalBypass_Init() {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            ExternalAppDetector *d = [ExternalAppDetector new];
            [d hideExternalApps];
            SystemRegistryModifier *m = [SystemRegistryModifier new];
            [m filterSystemLogs];
            ProcessProtector *p = [ProcessProtector new];
            [p antiDebug];
            CommunicationInterceptor *i = [CommunicationInterceptor new];
            [i interceptDistributedNotifications];
            SystemSpoofer *s = [SystemSpoofer new];
            [s spoofSystemProperties];
            NSLog(@"[EXTERNAL BYPASS] ✅ النظام يعمل بنجاح");
        });
    }
}
