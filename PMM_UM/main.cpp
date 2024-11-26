#include <Windows.h>
#include <iostream>
// IOCTLs
#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_MAP_PAGES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_UNMAP_PAGES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_PHYSICAL_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main()
{
    HANDLE hDevice = CreateFile(L"\\\\.\\PageTest", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to open device" << std::endl;
        return 1;
    }

    DWORD bytesReturned = 0;
    // Map the pages
    if (!DeviceIoControl(hDevice, IOCTL_MAP_PAGES, NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        std::cout << "Failed to send IOCTL" << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    std::cout << "Mapped pages" << std::endl;
    
    // Physical base, which is PML entry 256. This could be anything (if non canonical, you have to sign extend)
    // One might prefer to use the first free entry. Preferably one that is usually mapped for usermode.
    const char* physicalBase = reinterpret_cast<char*>(0xFFFF800000000000ull);

    // Get the physical address of the test pool
    char* testPool = nullptr;
    if (!DeviceIoControl(hDevice, IOCTL_GET_PHYSICAL_ADDRESS, &testPool, sizeof(char*), &testPool, sizeof(char*), &bytesReturned, NULL))
    {
        std::cout << "Failed to send IOCTL" << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    std::cout << "TestPool PA: " << std::hex << reinterpret_cast<uint64_t>(testPool) << std::endl;

    // Read from the test pool
    uint64_t value = *(uint64_t*)(physicalBase + reinterpret_cast<uint64_t>(testPool));
    std::cout << "Value at PA " << std::hex << reinterpret_cast<uint64_t>(testPool) << " is 0x" << value << std::endl;

    // Write to the test pool
    *(uint64_t*)(physicalBase + reinterpret_cast<uint64_t>(testPool)) = 0xDEADBEEF;
    value = *(uint64_t*)(physicalBase + reinterpret_cast<uint64_t>(testPool));
    std::cout << "Value at PA " << std::hex << reinterpret_cast<uint64_t>(testPool) << " is 0x" << value << std::endl;

	// Read for 1 minute and print every 5 seconds
    for (int i = 0; i < 12; i++)
    {
        value = *(uint64_t*)(physicalBase + reinterpret_cast<uint64_t>(testPool));
        std::cout << "Value at PA " << std::hex << reinterpret_cast<uint64_t>(testPool) << " is 0x" << value << std::endl;
        Sleep(5000);
    }

    // Unmap the pages
	if (!DeviceIoControl(hDevice, IOCTL_UNMAP_PAGES, NULL, 0, NULL, 0, &bytesReturned, NULL))
	{
		std::cout << "Failed to send IOCTL" << std::endl;
		CloseHandle(hDevice);
		return 1;
	}

	std::cout << "Unmapped pages" << std::endl;

    // Close the handle and return
    CloseHandle(hDevice);
    return 0;
}
