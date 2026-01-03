#pragma once

namespace cache
{
	std::uintptr_t game_cr3;
	std::uintptr_t pooledPML4Table;
	std::uintptr_t cave_base = 0;
	std::uintptr_t cave_base_2 = 0;
	std::uintptr_t ntos_image_base = 0;

	NTSTATUS( __fastcall* io_create_driver )( _In_opt_ PUNICODE_STRING Driver, PDRIVER_INITIALIZE INIT );

	std::uint8_t raw_shellcode[ ] = {
		0x90,
		0x48, 0xB8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xE0
	};
}

#define DEVICE_HANDLE _(L"{windows-codecave}")