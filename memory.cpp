#include "memory.h"

ntdll_helper ntdll_instance;

ntdll_helper::ntdll_helper() {
	base_address = (uintptr_t)GetModuleHandleA("ntdll.dll");
}

memory_manager::memory_manager(const std::string& proc_name, const std::string& wnd_name)
	: process_name(proc_name), window_name(wnd_name), process_id(0), process_handle(nullptr), window_handle(nullptr)
{
	if (!proc_name.empty()) {
		attach_process(proc_name);
	}
	else if (!wnd_name.empty()) {

	}
	else {
		assert(false && "no prc name or window name should be defined.");
	}
}

bool memory_manager::attach_process(const std::string& proc_name) {
	process_id = find_process_id(proc_name);
	process_handle = open_process_handle(process_id);
	return process_handle != nullptr;
}

bool memory_manager::attach_window(const std::string& wnd_name) {
	window_handle = FindWindowA(nullptr, wnd_name.c_str());
	GetWindowThreadProcessId(window_handle, &process_id);
	process_handle = open_process_handle(process_id);
	return process_handle != nullptr;
}

DWORD memory_manager::find_process_id(const std::string& proc_name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
	std::wstring wide_name(proc_name.begin(), proc_name.end());

	while (Process32NextW(snapshot, &entry)) {
		if (_wcsicmp(entry.szExeFile, wide_name.c_str()) == 0) {
			CloseHandle(snapshot);
			return entry.th32ProcessID;
		}
	}
	CloseHandle(snapshot);
	return 0;
}

HANDLE memory_manager::open_process_handle(DWORD pid) {
	using tNtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
	static tNtOpenProcess fn = ntdll_instance.get_exported_function<tNtOpenProcess>("NtOpenProcess");

	OBJECT_ATTRIBUTES obj_attrs{};
	obj_attrs.Length = sizeof(obj_attrs);

	CLIENT_ID client_id{};
	client_id.UniqueProcess = (HANDLE)(uintptr_t)pid;
	client_id.UniqueThread = nullptr;

	HANDLE h_proc = nullptr;
	NTSTATUS status = fn(&h_proc, PROCESS_ALL_ACCESS, &obj_attrs, &client_id);
	return NT_SUCCESS(status) ? h_proc : nullptr;
}

MODULEENTRY32W memory_manager::get_module_by_name(DWORD pid, const std::string& module_name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snapshot == INVALID_HANDLE_VALUE)
		return {};

	MODULEENTRY32W mod_entry = { sizeof(MODULEENTRY32W) };
	std::wstring wide_name(module_name.begin(), module_name.end());

	while (Module32NextW(snapshot, &mod_entry)) {
		if (_wcsicmp(mod_entry.szModule, wide_name.c_str()) == 0) {
			CloseHandle(snapshot);
			return mod_entry;
		}
	}
	CloseHandle(snapshot);
	return {};
}

uintptr_t memory_manager::allocate_memory(size_t size, ULONG alloc_type, ULONG protect) {
	using tNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
	static tNtAllocateVirtualMemory fn = ntdll_instance.get_exported_function<tNtAllocateVirtualMemory>("NtAllocateVirtualMemory");

	PVOID base = nullptr;
	SIZE_T region_size = size;
	NTSTATUS status = fn(process_handle, &base, 0, &region_size, alloc_type, protect);
	return NT_SUCCESS(status) ? reinterpret_cast<uintptr_t>(base) : 0;
}

bool memory_manager::free_memory(uintptr_t address, size_t size, ULONG free_type) {
	using tNtFreeVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
	static tNtFreeVirtualMemory fn = ntdll_instance.get_exported_function<tNtFreeVirtualMemory>("NtFreeVirtualMemory");

	PVOID base = (PVOID)address;
	SIZE_T region_size = size;
	NTSTATUS status = fn(process_handle, &base, &region_size, free_type);
	return NT_SUCCESS(status);
}

bool memory_manager::protect_memory(uintptr_t address, size_t size, ULONG new_protect, ULONG* old_protect_out) {
	using tNtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
	static tNtProtectVirtualMemory fn = ntdll_instance.get_exported_function<tNtProtectVirtualMemory>("NtProtectVirtualMemory");

	PVOID base = (PVOID)address;
	SIZE_T region_size = size;
	ULONG old_protect = 0;
	NTSTATUS status = fn(process_handle, &base, &region_size, new_protect, &old_protect);
	if (old_protect_out) *old_protect_out = old_protect;
	return NT_SUCCESS(status);
}

bool memory_manager::query_memory(uintptr_t address, int info_class, void* out_buffer, SIZE_T size, SIZE_T* returned_size) {
	using tNtQueryVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, int, PVOID, SIZE_T, PSIZE_T);
	static tNtQueryVirtualMemory fn = ntdll_instance.get_exported_function<tNtQueryVirtualMemory>("NtQueryVirtualMemory");

	NTSTATUS status = fn(process_handle, (PVOID)address, info_class, out_buffer, size, returned_size);
	return NT_SUCCESS(status);
}
uintptr_t memory_manager::get_base_address() {
	static auto base = uintptr_t(get_module_by_name(process_id, process_name).modBaseAddr);
	return base;
}