#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/sysctl.h>

typedef struct kinfo_proc kinfo_proc;

#define VERSION "0.1"
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt " (%s, %d)\n", ## __VA_ARGS__, __func__, __LINE__);

vm_map_t loginwindow_task;
vm_address_t base_address;
uint32_t text_offset;
uint64_t text_size;
uint8_t *text_section;

static int GetBSDProcessList(kinfo_proc **procList, size_t *procCount)
// Returns a list of all BSD processes on the system.  This routine
// allocates the list and puts it in *procList and a count of the
// number of entries in *procCount.  You are responsible for freeing
// this list (use "free" from System framework).
// On success, the function returns 0.
// On error, the function returns a BSD errno value.
{
    int                 err;
    kinfo_proc *        result;
    bool                done;
    static const int    name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    // Declaring name as const requires us to cast it when passing it to
    // sysctl because the prototype doesn't include the const modifier.
    size_t              length;

    assert( procList != NULL);
    assert(*procList == NULL);
    assert(procCount != NULL);

    *procCount = 0;

    // We start by calling sysctl with result == NULL and length == 0.
    // That will succeed, and set length to the appropriate length.
    // We then allocate a buffer of that size and call sysctl again
    // with that buffer.  If that succeeds, we're done.  If that fails
    // with ENOMEM, we have to throw away our buffer and loop.  Note
    // that the loop causes use to call sysctl with NULL again; this
    // is necessary because the ENOMEM failure case sets length to
    // the amount of data returned, not the amount of data that
    // could have been returned.

    result = NULL;
    done = false;
    do {
        assert(result == NULL);

        // Call sysctl with a NULL buffer.

        length = 0;
        err = sysctl( (int *) name, (sizeof(name) / sizeof(*name)) - 1,
                     NULL, &length,
                     NULL, 0);
        if (err == -1) {
            err = errno;
        }

        // Allocate an appropriately sized buffer based on the results
        // from the previous call.

        if (err == 0) {
            result = malloc(length);
            if (result == NULL) {
                err = ENOMEM;
            }
        }

        // Call sysctl again with the new buffer.  If we get an ENOMEM
        // error, toss away our buffer and start again.

        if (err == 0) {
            err = sysctl( (int *) name, (sizeof(name) / sizeof(*name)) - 1,
                         result, &length,
                         NULL, 0);
            if (err == -1) {
                err = errno;
            }
            if (err == 0) {
                done = true;
            } else if (err == ENOMEM) {
                assert(result != NULL);
                free(result);
                result = NULL;
                err = 0;
            }
        }
    } while (err == 0 && ! done);

    // Clean up and establish post conditions.

    if (err != 0 && result != NULL) {
        free(result);
        result = NULL;
    }
    *procList = result;
    if (err == 0) {
        *procCount = length / sizeof(kinfo_proc);
    }

    assert( (err == 0) == (*procList != NULL) );

    return err;
}

static int readmem(mach_vm_address_t address, mach_vm_size_t size, mach_vm_offset_t *buffer)
{
    kern_return_t kr = 0;

    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t info_cnt = sizeof (vm_region_basic_info_data_64_t);
    mach_port_t object_name;
    mach_vm_size_t size_info;
    mach_vm_address_t address_info = address;
    kr = mach_vm_region(loginwindow_task, &address_info, &size_info, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_cnt, &object_name);
    if (kr)
    {
        LOG_ERROR("mach_vm_region failed with error %d", (int)kr);
        return 0;
    }

    // read memory - vm_read_overwrite because we supply the buffer
    mach_vm_size_t nread = 0;
    kr = mach_vm_read_overwrite(loginwindow_task, address, size, (mach_vm_address_t)buffer, &nread);

    if (kr)
    {
        LOG_ERROR("vm_read failed! %d", kr);
        return 0;
    }
    if (nread != size)
    {
        LOG_ERROR("vm_read failed! requested size: 0x%llx read: 0x%llx", size, nread);
        return 0;
    }
    return 1;
}

static int write_memory_int(uint64_t opts_address, uint64_t value)
{
    printf("Writing value %08llx to address %llx.\n", value, opts_address);
    kern_return_t kr = 0;
    /* get original memory protection */
    mach_vm_size_t size = 0;
    mach_port_t object_name = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    /* mach_vm_region will return the address of the map into the address argument so we need to make a copy */
    mach_vm_address_t dummyadr = opts_address;
    if ( (kr = mach_vm_region(loginwindow_task, &dummyadr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name)) )
    {
        LOG_ERROR("mach_vm_region failed with error %d", kr);
        return 0;
    }

    /* change protections, write, and restore original protection */
    task_suspend(loginwindow_task);
    if ( (kr = mach_vm_protect(loginwindow_task, opts_address, (mach_msg_type_number_t)4, FALSE, VM_PROT_WRITE | VM_PROT_READ | VM_PROT_COPY)) )
    {
        LOG_ERROR("mach_vm_protect failed with error %d.", kr);
        return 0;
    }

    if ( (kr = mach_vm_write(loginwindow_task, opts_address, (vm_offset_t)&value, (mach_msg_type_number_t)4)) )
    {
        LOG_ERROR("mach_vm_write failed at 0x%llx with error %d.", opts_address, kr);
        return 0;
    }
    /* restore original protection */
    if ( (kr = mach_vm_protect(loginwindow_task, opts_address, (mach_msg_type_number_t)4, FALSE, info.protection)) )
    {
        LOG_ERROR("mach_vm_protect failed with error %d.", kr);
        return 0;
    }
    task_resume(loginwindow_task);
    return 1;
}

static pid_t get_process_pid(char *name, pid_t last_pid)
{
    kinfo_proc *result = 0;
    size_t count = 0;
    pid_t pid = 0;
    if( GetBSDProcessList(&result,&count) == 0 )
    {
        for (int i = 0; i < count; i++)
        {
            kinfo_proc *proc = &result[i];
            if (strcmp(name, proc->kp_proc.p_comm) == 0) {
                if (proc->kp_proc.p_pid > last_pid && (pid == 0 || proc->kp_proc.p_pid <= pid))
                {
                    pid = proc->kp_proc.p_pid;
                }
            }
        }
    }
    free(result);
    return pid;
}

static void get_main_text_segment()
{
    base_address = 0;
    text_offset = 0;
    text_size = 0;

    struct mach_header header = {0};
    struct mach_header temp_header = {0};
    vm_address_t iter = 0;
    uint32_t found_count = 0;
    while (1)
    {
        vm_address_t addr = iter;
        vm_size_t lsize = 0;
        uint32_t depth;
        mach_vm_size_t bytes_read = 0;
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(loginwindow_task, &addr, &lsize, &depth, (vm_region_info_t)&info, &count))
        {
            break;
        }
        kern_return_t kr = mach_vm_read_overwrite(loginwindow_task, (mach_vm_address_t)addr, (mach_vm_size_t)sizeof(struct mach_header), (mach_vm_address_t)&temp_header, &bytes_read);
        if (kr == KERN_SUCCESS && bytes_read == sizeof(struct mach_header))
        {
            /* only one image with MH_EXECUTE filetype */
            if ( (temp_header.magic == MH_MAGIC || temp_header.magic == MH_MAGIC_64) && temp_header.filetype == MH_EXECUTE)
            {
                base_address = addr;
                memcpy(&header, &temp_header, sizeof(struct mach_header));
                found_count++;
            }
        }
        iter = addr + lsize;
    }
    if (found_count > 1)
    {
        LOG_ERROR("Several executable binaries in process memory");
        base_address = 0;
    }
    if (base_address == 0)
    {
        return;
    }

    uint8_t *loadcmds = malloc(header.sizeofcmds);
    uint32_t mach_header_size = sizeof(struct mach_header);
    if (header.magic == MH_MAGIC_64)
    {
        mach_header_size = sizeof(struct mach_header_64);
    }
    if (!readmem(base_address + mach_header_size, header.sizeofcmds, (mach_vm_offset_t*)loadcmds))
    {
        LOG_ERROR("Unable to read Mach-O load commands");
        return;
    }

    found_count = 0;
    uint32_t cmd_offset = 0;
    for (uint32_t i = 0; i < header.ncmds; i++)
    {
        struct load_command *loadCommand = (struct load_command *)(&loadcmds[cmd_offset]);
        if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segCmd = (struct segment_command*)loadCommand;
            struct section *sec = (struct section*)((char*)segCmd + sizeof(struct segment_command));
            for (uint32_t j = 0; j < segCmd->nsects; j++)
            {
                if (strncmp(sec[j].sectname, "__text", 16) == 0)
                {
                    LOG_ERROR("loginwindow is 32-bit. Not supported.");
                    base_address = 0;
                }
            }
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segCmd64 = (struct segment_command_64*)loadCommand;
            struct section_64 *sec = (struct section_64*)((char*)segCmd64 + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < segCmd64->nsects; j++)
            {
                if (strncmp(sec[j].sectname, "__text", 16) == 0)
                {
                    text_offset = sec[j].offset;
                    text_size = sec[j].size;
                    found_count++;
                }
            }
        }
        cmd_offset += loadCommand->cmdsize;
    }
    free(loadcmds);
    if (found_count > 1)
    {
        LOG_ERROR("Several __text sections in loginwindow executable");
        text_size = 0;
    }
}

static double get_relative_double(uint8_t *position)
{
    double result = 0.0;
    uint64_t offset = position - text_section + (*(uint32_t *)(position)) + 4;
    if (offset + 8 <= text_size)
    {
        result = *(double *)(text_section + offset);
    }
    else
    {
        if (!readmem(base_address + text_offset + offset, 8, (mach_vm_offset_t*)&result))
        {
            result = 0.0;
        }
    }
    return result;
}

static void find_binary_pattern(void *pattern, uint32_t pattern_size, uint8_t ***matches, uint32_t *count, uint64_t from)
{
    *count = 0;
    if (from > text_size)
    {
        return;
    }
    void *pos = memmem(text_section + from, text_size - from, pattern, pattern_size);
    while (pos)
    {
        (*count)++;
        pos = memmem(pos+1, (void*)(text_size + text_section) - pos - 1, pattern, pattern_size);
    }
    *matches = malloc(sizeof(void *) * (*count));
    *count = 0;
    pos = memmem(text_section + from, text_size - from, pattern, pattern_size);
    while (pos)
    {
        (*matches)[*count] = pos;
        (*count)++;
        pos = memmem(pos+1, (void*)(text_size + text_section) - pos - 1, pattern, pattern_size);
    }
}

//returns the offset to instruction 'movsd xmm0, 1.5' within __text section
static uint64_t find_patch_place()
{
    uint8_t **matches = 0;
    uint32_t count = 0;
    uint32_t found_count = 0;
    uint8_t *patch_place = 0;
    find_binary_pattern("\xF2\x0F\x10\x05", 4, &matches, &count, 0);
    for (int i = 0; i < count; i++)
    {
        if (get_relative_double(matches[i]+4) == 1.5)
        {
            patch_place = matches[i];
            found_count += 1;
        }
    }
    if (found_count == 0)
    {
        LOG_ERROR("No timer setup. Patched already?");
        return 0;
    }
    if (found_count > 1)
    {
        LOG_ERROR("Several instructions 'movsd xmm0, 1.5'");
        return 0;
    }
    return patch_place - text_section;
}

static uint64_t find_small_double(uint64_t from)
{
    char pattern[] = "aaaa";
    for (int i = 0x3f18; i < 0x3f74; i++)
    {
        *(int *)(&pattern) = i;
        uint8_t **result;
        uint32_t count;
        find_binary_pattern(pattern, 2, &result, &count, from);
        if (count)
        {
            return result[0] - 6 - text_section;
        }
    }
    LOG_ERROR("Unable to locate new timeinterval gadgets :(");
    return 0;
}

int main(int argc, char **argv)
{
    printf("power_fixer v%s, by binchewer\n------------------------------\n\n", VERSION);
    pid_t pid = 0;
    while ((pid = get_process_pid("loginwindow", pid)))
    {
        printf("Found loginwindow with PID %d\n", pid);

        loginwindow_task = 0;
        if (task_for_pid(mach_task_self(), pid, &loginwindow_task))
        {
            LOG_ERROR("Can't execute task_for_pid! Run me from sudo.");
            exit(1);
        }
        get_main_text_segment();
        if (!base_address)
        {
            LOG_ERROR("Unable to locate loginwindow binary image");
            continue;
        }
        printf("loginwindow base_address is 0x%016lx\n", base_address);
        if (!text_size)
        {
            LOG_ERROR("Unable to locate loginwindow __text section");
            continue;
        }
        printf("loginwindow text section found at offset 0x%x, %llu bytes\n", text_offset, text_size);
        text_section = (uint8_t *)malloc(text_size);
        if (!readmem(base_address + text_offset, text_size, (mach_vm_offset_t*)text_section))
        {
            LOG_ERROR("Unable to dump loginwindow __text section");
            continue;
        }
        uint64_t patch_place = find_patch_place();
        if (patch_place == 0)
        {
            continue;
        }
        printf("Found potential timer setup at %016llx\n", (base_address + text_offset + patch_place));
        uint64_t gadget = find_small_double(patch_place + 8);
        if (gadget == 0)
        {
            continue;
        }
        printf("Found new timer value at %016llx: %lf\n", base_address + text_offset + gadget, *(double *)(&text_section[gadget]));
        if (!write_memory_int(base_address + text_offset + patch_place + 4, gadget - patch_place - 8))
        {
            LOG_ERROR("Unable to patch loginwindow memory");
            continue;
        }
        printf("\n");
    }
    puts("All done.");
    return 0;
}
