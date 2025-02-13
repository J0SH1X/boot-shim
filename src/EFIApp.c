#include "EFIApp.h"

VOID JumpToAddress(
	EFI_HANDLE ImageHandle, 
	uint32_t addr
)
{

	EFI_STATUS Status;
	UINTN MemMapSize = 0;
	EFI_MEMORY_DESCRIPTOR* MemMap = 0;
	UINTN MapKey = 0;
	UINTN DesSize = 0;
	UINT32 DesVersion = 0;

	/* Entry */
	VOID(*entry)() = (VOID*) addr;

	gBS->GetMemoryMap(
		&MemMapSize, 
		MemMap, 
		&MapKey, 
		&DesSize, 
		&DesVersion
	);

	/* Shutdown */
	Status = gBS->ExitBootServices(
		ImageHandle, 
		MapKey
	);

	if (EFI_ERROR(Status))
	{
		Print(L"Failed to exit BS\n");
		return;
	}

	/* De-initialize */
	ArmDeInitialize();

	/* Lets go */
	entry();

}

BOOLEAN CheckElf32Header(Elf32_Ehdr* bl_elf_hdr)
{

	EFI_PHYSICAL_ADDRESS ElfEntryPoint;
	EFI_STATUS Status = EFI_SUCCESS;

	if (bl_elf_hdr == NULL) return FALSE;

	// Sanity check: Signature
	if (bl_elf_hdr->e_ident[EI_MAG0] != ELFMAG0 ||
		bl_elf_hdr->e_ident[EI_MAG1] != ELFMAG1 ||
		bl_elf_hdr->e_ident[EI_MAG2] != ELFMAG2 ||
		bl_elf_hdr->e_ident[EI_MAG3] != ELFMAG3)
	{
		Print(L"Fail: Invalid ELF magic\n");
		return FALSE;
	}

	// Sanity check: Architecture
	if (bl_elf_hdr->e_machine != EM_ARM)
	{
		Print(L"Fail: Not ARM architecture ELF32 file\n");
		return FALSE;
	}

	// Sanity check: exec
	if (bl_elf_hdr->e_type != ET_EXEC)
	{
		Print(L"Fail: Not EXEC ELF\n");
		return FALSE;
	}

	// Sanity check: entry point and size
	ElfEntryPoint = bl_elf_hdr->e_entry;
	Status = gBS->AllocatePages(
		AllocateAddress, 
		EfiLoaderCode, 
		1, 
		&ElfEntryPoint
	);

	if (EFI_ERROR(Status))
	{
		Print(L"Fail: Invalid entry point\n");
		return FALSE;
	}

	// Free page allocated
	gBS->FreePages(
		ElfEntryPoint, 
		1
	);

	// Sanity check: program header entries. At least one should present.
	if (bl_elf_hdr->e_phnum < 1)
	{
		Print(L"Fail: Less than one program header entry found\n");
		return FALSE;
	}

	return TRUE;
}

// This is the actual entrypoint.
// Application entrypoint (must be set to 'efi_main' for gnu-efi crt0 compatibility)
EFI_STATUS efi_main(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *SystemTable
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_BLOCK_IO_PROTOCOL *BlockIo = NULL;
    EFI_HANDLE *HandleBuffer = NULL;
    UINTN HandleCount = 0;
    EFI_PARTITION_ENTRY *PartitionEntry = NULL;
    EFI_DEVICE_PATH_PROTOCOL *DevicePath;
    UINTN PartitionIndex = 0;
    VOID *PayloadBuffer = NULL;
    UINTN PayloadSize = 0;
    EFI_PHYSICAL_ADDRESS UefiEntryPoint = PAYLOAD_ENTRY_POINT_ADDR_INVALID;
    VOID *PayloadLoadSec;
    EFI_FILE_INFO *PayloadFileInformation = NULL;
    UINTN PayloadFileInformationSize = 0;
    Elf32_Ehdr *PayloadElf32Ehdr = NULL;
    Elf32_Phdr *PayloadElf32Phdr = NULL;
    UINTN PayloadSectionOffset = 0;
    UINTN PayloadLength = 0;
    
#if defined(_GNU_EFI)
    InitializeLib(ImageHandle, SystemTable);
#endif
    
    // Locate all block devices
    Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiBlockIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
    if (EFI_ERROR(Status)) {
        goto exit;
    }
    
    for (UINTN i = 0; i < HandleCount; i++) {
        Status = gBS->HandleProtocol(HandleBuffer[i], &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
        if (EFI_ERROR(Status) || !BlockIo->Media->MediaPresent) {
            continue;
        }
        
        Status = GetGptPartitionByName(BlockIo, L"lk", &PartitionEntry, &PartitionIndex);
        if (!EFI_ERROR(Status)) {
            break;
        }
    }
    
    if (PartitionEntry == NULL) {
        goto exit;
    }
    
    PayloadSize = PartitionEntry->EndingLBA * BlockIo->Media->BlockSize;
    Status = gBS->AllocatePool(EfiLoaderData, PayloadSize, &PayloadBuffer);
    if (EFI_ERROR(Status)) {
        goto exit;
    }
    
    Status = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, PartitionEntry->StartingLBA, PayloadSize, PayloadBuffer);
    if (EFI_ERROR(Status)) {
        goto cleanup;
    }
    
    PayloadElf32Ehdr = (Elf32_Ehdr *)PayloadBuffer;
    if (!CheckElf32Header(PayloadElf32Ehdr)) {
        goto cleanup;
    }
    
    UefiEntryPoint = PayloadElf32Ehdr->e_entry;
    PayloadElf32Phdr = (Elf32_Phdr *)((UINTN)PayloadBuffer + PayloadElf32Ehdr->e_phoff);
    
    for (UINTN ph_idx = 0; ph_idx < PayloadElf32Ehdr->e_phnum; ph_idx++) {
        if (PayloadElf32Phdr[ph_idx].p_type == PT_LOAD) {
            PayloadSectionOffset = PayloadElf32Phdr[ph_idx].p_offset;
            PayloadLength = PayloadElf32Phdr[ph_idx].p_memsz;
            PayloadLoadSec = (VOID *)((UINTN)PayloadBuffer + PayloadSectionOffset);
            break;
        }
    }
    
    if (PayloadSectionOffset == 0 || PayloadLength == 0) {
        goto cleanup;
    }
    
    JumpToAddress(ImageHandle, UefiEntryPoint, PayloadLoadSec, PayloadLength);
    
cleanup:
    gBS->FreePool(PayloadBuffer);
    
exit:
    return Status;
}


