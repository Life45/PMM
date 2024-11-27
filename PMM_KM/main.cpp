#include <ntddk.h>
#include <intrin.h>
#include <../external/ia32-doc/out/ia32.hpp>

#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_MAP_PAGES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_UNMAP_PAGES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_PHYSICAL_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
extern "C" VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
extern "C" NTSTATUS DispatchIoctl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
extern "C" NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\PageTest");
UNICODE_STRING g_SymbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\PageTest");

typedef struct _HOST_PAGE_TABLE
{
    __declspec(align(0x1000)) pml4e_64 Pml4[512];

    __declspec(align(0x1000)) pdpte_64 Pdpt[512];

    __declspec(align(0x1000)) pde_64 Pd[64][512];

} HOST_PAGE_TABLE, * PHOST_PAGE_TABLE;

HOST_PAGE_TABLE* Table = nullptr;
PVOID TestPool = nullptr;
PHYSICAL_ADDRESS TestPoolPa = {0};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = nullptr;

    status = IoCreateDevice(DriverObject, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    DeviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(DeviceObject);
        return status;
    }

    // Allocate the page table and the test pool
    Table = (HOST_PAGE_TABLE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOST_PAGE_TABLE), 'pgpg');
    TestPool = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8, 'pgpg');

    // Write to the test pool
    *(UINT64*)TestPool = 0x1234567890ABCDEF;

    // Get the physical address of the test pool
    TestPoolPa = MmGetPhysicalAddress(TestPool);

    DbgPrint("TestPool PA: %p\n", TestPoolPa.QuadPart);

    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&g_SymbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);

    ExFreePoolWithTag(Table, 'pgpg');
    ExFreePoolWithTag(TestPool, 'pgpg');
}

pml4e_64 pml4eOriginal = { 0 };
PHYSICAL_ADDRESS paOfPml4e = { 0 };

bool UnmapPages()
{
    // Disable interrupts until we are done
    _disable();

    // Get the virtual address of the page directory
    pml4e_64* currentPml4e = (pml4e_64*)MmGetVirtualForPhysical(paOfPml4e);

    if (!currentPml4e)
    {
        _enable();
        return false;
    }

    // Restore the original page directory
    *currentPml4e = pml4eOriginal;

    // Re-enable interrupts
    _enable();
    

	// Print the pool value
	DbgPrint("TestPool value: %p\n", *(PVOID**)TestPool);
    return true;
}

bool MapPages(cr3 cr3)
{
    // Disable interrupts until we are done
    _disable();

    // Get the physical address of the page directory
    uint64_t paOfDTB = cr3.address_of_page_directory << 12;

    DbgPrint("paOfDTB: %p\n", paOfDTB);

    PHYSICAL_ADDRESS pa = { 0 };
    pa.QuadPart = paOfDTB + 256 * sizeof(pml4e_64);

    pml4e_64* currentPml4e = (pml4e_64*)MmGetVirtualForPhysical(pa);

    if (!currentPml4e)
    {
        _enable();
        return false;
    }

    DbgPrint("currentPml4e PA: %p\n", pa.QuadPart);
    DbgPrint("currentPml4e VA: %p\n", currentPml4e);

    paOfPml4e = pa;
    pml4eOriginal = *currentPml4e;

    // Map 2 MB large pages
    // We will map 64 GB of physical memory with this.
    pml4e_64* Pml4e = &Table->Pml4[256];
    Pml4e->flags = 0;
    Pml4e->present = 1;
    Pml4e->write = 1;
    Pml4e->supervisor = 1;
    Pml4e->page_frame_number = MmGetPhysicalAddress(Table->Pdpt).QuadPart >> 12; // PageSize
    for (UINT64 i = 0; i < 64; i++) // 64 GB
    {
        pdpte_64* Pdpte = &Table->Pdpt[i];
        Pdpte->flags = 0;
        Pdpte->present = 1;
        Pdpte->write = 1;
        Pdpte->supervisor = 1;
        Pdpte->page_frame_number = MmGetPhysicalAddress(&Table->Pd[i]).QuadPart >> 12; // PageSize

        for (UINT64 j = 0; j < 512; j++)
        {
            pde_2mb_64* Pde = (pde_2mb_64*)&Table->Pd[i][j];
            Pde->flags = 0;
            Pde->present = 1;
            Pde->write = 1;
            Pde->large_page = 1;
            Pde->supervisor = 1; // User/supervisor; if 0, user-mode accesses are not allowed to the 2-MByte page referenced by this entry.
            Pde->page_frame_number = (i * 512 + j); // 2MB pages
        }
    }

	// Change the current table
    *currentPml4e = *Pml4e;

    DbgPrint("Pml4e: %p\n", Pml4e);

	// Flush TLB
    __wbinvd(); // Write back and invalidate cache
	// Just in case
    auto cr4 = __readcr4();
    __writecr4(cr4 & ~(1ULL << 7)); // Clear PGE flag
    __writecr4(cr4); // Set PGE flag again	

    // Re-enable interrupts
    _enable();
    return true;
}

NTSTATUS DispatchIoctl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    if (irpStack)
    {
        ULONG ctlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

        switch (ctlCode)
        {
        case IOCTL_TEST:
        {
            KdPrint(("IOCTL_TEST\n"));
            cr3 cr3{ 0 };
            cr3.flags = __readcr3();

            DbgPrint("cr3: %p\n", cr3.flags);
            break;
        }
        case IOCTL_MAP_PAGES:
        {
            DbgPrint("IOCTL_MAP_PAGES\n");
            cr3 cr3{ 0 };
            cr3.flags = __readcr3();
            MapPages(cr3);
            break;
        }
        case IOCTL_UNMAP_PAGES:
        {
            DbgPrint("IOCTL_UNMAP_PAGES\n");
            UnmapPages();
            break;
        }
        case IOCTL_GET_PHYSICAL_ADDRESS:
        {
            DbgPrint("IOCTL_GET_PHYSICAL_ADDRESS\n");
			PVOID* pva = (PVOID*)Irp->AssociatedIrp.SystemBuffer;
            *pva = (PVOID)TestPoolPa.QuadPart;
			Irp->IoStatus.Information = sizeof(PVOID);
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
