#include <iostream>

#include "memory/memory.h" // include the memory header here so we can use its functions

int main()
{
    g_memory = std::make_unique<memory_manager>("RobloxPlayerBeta.exe", "Roblox");

    uintptr_t base = g_memory->get_base_address(); // getting base address
    uintptr_t visual_engine = g_memory->read<uintptr_t>(base + 0x6DEC860); // base address + visualengine address

    printf("visualengine: 0x%llX\n", visual_engine); // printing it 
    // std::cout << "visualengine: << std::hex << visual_engine << std::endl; // printing with cout
}

