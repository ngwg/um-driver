#pragma once
#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <memory>
#include <cassert>
#include <unordered_map>
#include <winternl.h>
#include <type_traits>

typedef CLIENT_ID* p_client_id;

struct ntdll_helper {
    uintptr_t base_address;
    ntdll_helper();

    template <typename T = uintptr_t>
    T get_exported_function(const std::string& function_name) {
        static std::unordered_map<std::string, uintptr_t> cache;
        if (cache.find(function_name) == cache.end())
            cache[function_name] = uintptr_t(GetProcAddress((HMODULE)base_address, function_name.c_str()));
        return reinterpret_cast<T>(cache[function_name]);
    }
};

extern ntdll_helper ntdll_instance;

class memory_manager {
public:
    DWORD process_id{};
    HWND window_handle{};
    std::string process_name;
    std::string window_name;
    HANDLE process_handle{};

public:
    memory_manager(const std::string& proc_name, const std::string& wnd_name = "");

    bool attach_process(const std::string& proc_name);
    bool attach_window(const std::string& wnd_name);

    template <typename T = uintptr_t>
    T read(uintptr_t address) {
        using tNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG);
        static tNtReadVirtualMemory fn = ntdll_instance.get_exported_function<tNtReadVirtualMemory>("NtReadVirtualMemory");

        T buffer{};
        ULONG bytes_read = 0;
        NTSTATUS status = fn(process_handle, reinterpret_cast<PVOID>(address), &buffer, sizeof(T), &bytes_read);
        return (NT_SUCCESS(status) && bytes_read == sizeof(T)) ? buffer : T{};
    }

    template <typename T>
    bool write(uintptr_t address, const T& data) {
        using tNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG);
        static tNtWriteVirtualMemory fn = ntdll_instance.get_exported_function<tNtWriteVirtualMemory>("NtWriteVirtualMemory");

        ULONG bytes_written = 0;
        const void* buffer = std::is_pointer_v<T> ? reinterpret_cast<const void*>(data) : &data;
        NTSTATUS status = fn(process_handle, reinterpret_cast<PVOID>(address), (PVOID)buffer, sizeof(T), &bytes_written);
        return NT_SUCCESS(status) && bytes_written == sizeof(T);
    }

    std::string read_string(uintptr_t address)
    {
        std::int32_t string_lengt = read<std::int32_t>(address + 0x10);
        std::uint64_t string__address = (string_lengt >= 16) ? read<std::uint64_t>(address) : address;

        if (string_lengt == 0 || string_lengt > 255)
        {
            return "string is unknown";
        }


        std::vector<char> buffer(string_lengt + 1, 0);
        ReadProcessMemory(process_handle, reinterpret_cast<void*>(string__address), buffer.data(), buffer.size(), nullptr);

        return std::string(buffer.data(), string_lengt);
    }

    uintptr_t allocate_memory(size_t size, ULONG alloc_type = MEM_COMMIT | MEM_RESERVE, ULONG protect = PAGE_READWRITE);
    bool free_memory(uintptr_t address, size_t size, ULONG free_type = MEM_RELEASE);
    bool protect_memory(uintptr_t address, size_t size, ULONG new_protect, ULONG* old_protect_out = nullptr);
    bool query_memory(uintptr_t address, int info_class, void* out_buffer, SIZE_T size, SIZE_T* returned_size = nullptr);

    uintptr_t get_base_address();

    static DWORD find_process_id(const std::string& proc_name);
    static HANDLE open_process_handle(DWORD pid);
    static MODULEENTRY32W get_module_by_name(DWORD pid, const std::string& module_name);
};

inline std::unique_ptr<memory_manager> g_memory;
