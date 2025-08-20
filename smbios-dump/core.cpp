#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <q-tee/common/common.h>
#include <q-tee/smbios/smbios.h>

#define SMB_FIELD_OFFSET(STRUCT, MEMBER) (sizeof(SMBIOS::StructureHeader_t) + Q_OFFSETOF(STRUCT, MEMBER))

#if defined(Q_OS_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

struct RawSMBIOSData_t
{
	BYTE Used20CallingMethod;
	BYTE SMBIOSMajorVersion;
	BYTE SMBIOSMinorVersion;
	BYTE DmiRevision;
	DWORD Length;
	BYTE SMBIOSTableData[];
};
#elif defined(Q_OS_LINUX)
#include <sys/stat.h>
#else
#error "target platform is not supported!"
#endif

constexpr const char* arrStructureType[] =
{
	"Platform Firmware Information",
	"System Information",
	"Baseboard Information",
	"System Enclosure",
	"Processor Information",
	"Memory Controller Information",
	"Memory Module Information",
	"Cache Information",
	"Port Connector Information",
	"System Slots",
	"On-board Devices Information",
	"OEM Strings",
	"System Configuration Options",
	"Firmware Language Information",
	"Group Associations",
	"System Event Log",
	"Physical Memory Array",
	"Memory Device",
	"Memory 32-bit Error Information",
	"Memory Array Mapped Address",
	"Memory Device Mapped Address",
	"Built-in Pointing Device",
	"Portable Battery",
	"System Reset",
	"Hardware Security",
	"System Power Controls",
	"Voltage Probe",
	"Cooling Device",
	"Termperature Probe",
	"Electrical Current Probe",
	"Out-of-band Remote Access",
	"Boot Integrity Services",
	"System Boot Information",
	"Memory 64-bit Error Information",
	"Management Device",
	"Management Device Component",
	"Management Device Threshold Data",
	"Memory Channel",
	"IPMI Device Information",
	"System Power Supply",
	"Additional Information",
	"On-board Devices Extended Information",
	"Management Controller Host Interface",
	"TPM Device",
	"Processor Additional Information",
	"Firmware Inventory Information",
	"String Property"
};

constexpr const char* arrBaseBoardType[] =
{
	"Unknown",
	"Other",
	"Server Blade",
	"Connectivity Switch",
	"System Management Module",
	"Processor Module",
	"I/O Module",
	"Memory Module",
	"Daughter board",
	"Motherboard",
	"Processor/Memory Module",
	"Processor/IO Module",
	"Interconnect board"
};

constexpr const char* arrMemoryType[] =
{
	"Other",
	"Unknown",
	"Standard",
	"Fast Page Mode",
	"EDO",
	"Parity",
	"ECC",
	"SIMM",
	"DIMM",
	"Burst EDO",
	"SDRAM",
};

constexpr const char* arrOnBoardDeviceType[] =
{
	"Other",
	"Unknown",
	"Video",
	"SCSI Controller",
	"Ethernet",
	"Token Ring",
	"Sound",
	"PATA Controller",
	"SATA Controller",
	"SAS Controller",
	"Wireless LAN",
	"Bluetooth",
	"WWAN",
	"eMMC",
	"NVMe Controller",
	"UFS Controller"
};

constexpr const char* arrMemoryErrorType[] =
{
	"Other",
	"Unknown",
	"OK",
	"Bad Read",
	"Parity",
	"Single-bit",
	"Double-bit",
	"Multi-bit",
	"Nibble",
	"Checksum",
	"CRC",
	"Corrected Single-bit",
	"Corrected",
	"Uncorrectable"
};

constexpr const char* arrMemoryErrorGranularity[] =
{
	"Other",
	"Unknown",
	"Device Level",
	"Memory Partition Level"
};

constexpr const char* arrMemoryErrorOperation[] =
{
	"Other",
	"Unknown",
	"Read",
	"Write",
	"Partial Write"
};

constexpr const char* arrProbeLocation[] =
{
	"Other",
	"Unknown",
	"Processor",
	"Disk",
	"Peripheral Bay",
	"System Management Module",
	"Motherboard",
	"Memory Module",
	"Processor Module",
	"Power Unit",
	"Add-in Card",
	"Front Panel Board",
	"Back Panel Board",
	"Power System Board",
	"Drive Back Plane"
};

constexpr const char* arrStatus[] =
{
	"Other",
	"Unknown",
	"OK",
	"Non-critical",
	"Critical",
	"Non-recoverable"
};

constexpr const char* arrSizeUnit[] =
{
	"KiB",
	"MiB",
	"GiB"
};

constexpr const char* arrVoltage[] =
{
	"5V",
	"3.3V",
	"2.9V"
};

static void HandleStructure(const SMBIOS::StructureHeader_t* pStructure, const char** arrStringMap, const std::uint32_t uVersion)
{
	std::printf("\n[%s]\n",
		pStructure->nType > SMBIOS::TYPE_END_OF_TABLE ? "OEM Specific" :
		pStructure->nType == SMBIOS::TYPE_INACTIVE ? "Inactive" :
		pStructure->nType == SMBIOS::TYPE_END_OF_TABLE ? "End of Table" :
		arrStructureType[pStructure->nType]);

	switch (pStructure->nType)
	{
	case SMBIOS::TYPE_PLATFORM_FIRMWARE_INFORMATION:
	{
		const auto pPFI = reinterpret_cast<const SMBIOS::PlatformFirmwareInformation_t*>(pStructure->arrData);
		std::printf("Vendor: %s\nFirmware Version: %s\nStarting Address Segment: 0x%02X\nFirmware Release Data: %s\n",
			arrStringMap[pPFI->nVendor],
			arrStringMap[pPFI->nFirmwareVersion],
			pPFI->uStartingAddressSegment,
			arrStringMap[pPFI->nFirmwareReleaseDate]);

		std::uint32_t nFirmwareRomSize = pPFI->nFirmwareRomSize;
		std::uint8_t nFirmwareRomSizeUnit = 0U;
		if (nFirmwareRomSize == 0xFF && pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::PlatformFirmwareInformation_t, uEmbededControllerFirmwareMinorRelease) + 1U)
		{
			nFirmwareRomSize = pPFI->nExtendedFirmwareRomSize;
			nFirmwareRomSizeUnit = pPFI->nExtendedFirmwareRomSizeUnit + 1U;
		}
		else
			nFirmwareRomSize = (nFirmwareRomSize + 1U) * 64U;
		std::printf("Firmware ROM Size: %" PRIu32 "%s\n", nFirmwareRomSize, arrSizeUnit[nFirmwareRomSizeUnit]);

		constexpr const char* arrCharacteristics[] =
		{
			"Unknown",
			"Not supported",
			"ISA is supported",
			"MCA is supported",
			"EISA is supported",
			"PCI is supported",
			"PCMCIA is supported",
			"Plug and Play is supported",
			"APM",
			"Firmware is upgradeable",
			"Shadowing is allowed",
			"VL-VESA is supported",
			"ESCD is supported",
			"Boot from CD is supported",
			"Selectable boot is supported",
			"Firmware ROM is socketed",
			"Boot from PCMCIA is supported",
			"EDD is supported",
			"NEC 9800 3.5\" / 1.2M / 360RPM floppy is supported",
			"Toshiba 3.5\" / 1.2M / 360RPM floppy is supported",
			"5.25\" / 360KB floppy is supported",
			"5.25\" / 1.2MB floppy is supported",
			"3.5\" / 720KB floppy is supported",
			"3.5\" / 2.88MB floppy is supported",
			"Print screen service is supported",
			"Keyboard services is supported",
			"Serial services is supported",
			"Printer services is supported",
			"CGA/Mono Video services are supported",
			"NEC PC-98"
		};

		std::printf("Firmware Characteristics:\n");
		for (std::uint64_t i = 2ULL; i <= 31ULL; ++i)
		{
			if (pPFI->ullFirmwareCharacteristics & (1ULL << i))
				std::printf("\t%s\n", arrCharacteristics[i - 2ULL]);
		}

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::PlatformFirmwareInformation_t, uFirmwareCharacteristicsExtension1))
			break;

		constexpr const char* arrCharacteristicsExtension1[] =
		{
			"ACPI is supported",
			"Legacy USB is supported",
			"AGP is supported",
			"I2O boot is supported",
			"LS-120 boot is supported",
			"ATAPI ZIP boot is supported",
			"1394 boot is supported",
			"Smart battery is supported",
		};
		for (std::uint8_t i = 0U; i < Q_ARRAYSIZE(arrCharacteristicsExtension1); ++i)
		{
			if (pPFI->uFirmwareCharacteristicsExtension1 & (1U << i))
				std::printf("\t%s\n", arrCharacteristicsExtension1[i]);
		}

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::PlatformFirmwareInformation_t, uFirmwareCharacteristicsExtension2))
			break;

		constexpr const char* arrCharacteristicsExtension2[] =
		{
			"BIOS Boot Specification is supported",
			"Function key-initiated network service boot is supported",
			"Targeted content distribution is enabled",
			"UEFI Specification is supported",
			"Virtual machine",
			"Manufacturing mode is supported",
			"Manufacturing mode is enabled",
			"Reserved"
		};
		for (std::uint8_t i = 0U; i < Q_ARRAYSIZE(arrCharacteristicsExtension2); ++i)
		{
			if (pPFI->uFirmwareCharacteristicsExtension2 & (1U << i))
				std::printf("\t%s\n", arrCharacteristicsExtension2[i]);
		}

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::PlatformFirmwareInformation_t, uPlatformFirmwareMajorRelease))
			break;

		std::printf("Platform Firmware Version: %u.%u\n", pPFI->uPlatformFirmwareMajorRelease, pPFI->uPlatformFirmwareMinorRelease);
		if (pPFI->uEmbededControllerFirmwareMajorRelease != 0xFF && pPFI->uEmbededControllerFirmwareMinorRelease != 0xFF)
			std::printf("Embeded Controller Version: %u.%u\n", pPFI->uEmbededControllerFirmwareMajorRelease, pPFI->uEmbededControllerFirmwareMinorRelease);
		
		break;
	}
	case SMBIOS::TYPE_SYSTEM_INFORMATION:
	{
		const auto pSI = reinterpret_cast<const SMBIOS::SystemInformation_t*>(pStructure->arrData);
		std::printf("Manufacturer: %s\nProduct: %s\nVersion: %s\nSerial Number: %s\n",
			arrStringMap[pSI->nManufacturer],
			arrStringMap[pSI->nProduct],
			arrStringMap[pSI->nVersion],
			arrStringMap[pSI->nSerialNumber]);
		
		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemInformation_t, arrUUID))
			break;

		std::printf("UUID: %08X-%04X-%04X-%04X-%08X%04X\n", *reinterpret_cast<const std::uint32_t*>(pSI->arrUUID), *reinterpret_cast<const std::uint16_t*>(&pSI->arrUUID[4]), *reinterpret_cast<const std::uint16_t*>(&pSI->arrUUID[6]), *reinterpret_cast<const std::uint16_t*>(&pSI->arrUUID[8]), *reinterpret_cast<const std::uint32_t*>(&pSI->arrUUID[10]), *reinterpret_cast<const std::uint16_t*>(&pSI->arrUUID[14]));
		
		constexpr const char* arrWakeUpType[] =
		{
			"Reserved",
			"Other",
			"Unknown",
			"APM Timer",
			"Modem Ring",
			"LAN Remote",
			"Power Switch",
			"PCI PME",
			"Power Restored"
		};
		std::printf("Wake Up Type: %s\n", arrWakeUpType[pSI->nWakeUpType]);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemInformation_t, nSkuNumber))
			break;

		std::printf("SKU Number: %s\nFamily: %s\n", arrStringMap[pSI->nSkuNumber], arrStringMap[pSI->nFamily]);
		break;
	}
	case SMBIOS::TYPE_BASEBOARD_INFORMATION:
	{
		const auto pBI = reinterpret_cast<const SMBIOS::BaseboardInformation_t*>(pStructure->arrData);
		std::printf("Manufacturer: %s\nProduct: %s\nVersion: %s\nSerial Number: %s\nAsset Tag: %s\n",
			arrStringMap[pBI->nManufacturer],
			arrStringMap[pBI->nProduct],
			arrStringMap[pBI->nVersion],
			arrStringMap[pBI->nSerialNumber],
			arrStringMap[pBI->nAssetTag]);

		constexpr const char* arrFeatureFlags[] =
		{
			"Hosting Board",
			"Requires Daughter or Auxiliary Card",
			"Removable",
			"Replaceable",
			"Hot-swappable"
		};
		std::printf("Feature Flags:\n");
		for (unsigned int i = 0U; i < 5U; ++i)
		{
			if (pBI->uFeatureFlags & (1U << i))
				std::printf("\t%s\n", arrFeatureFlags[i]);
		}
		std::printf("Board Type: %s\n", arrBaseBoardType[pBI->nBoardType - 1U]);

		std::printf("Contained Object Handles: %u\n", pBI->nContainedObjectHandleCount);
		for (std::uint8_t i = 0U; i < pBI->nContainedObjectHandleCount; ++i)
			std::printf("%u. 0x%04X\n", i + 1U, pBI->arrContainedObjectHandles[i]);

		break;
	}
	case SMBIOS::TYPE_SYSTEM_ENCLOSURE:
	{
		const auto pSE = reinterpret_cast<const SMBIOS::SystemEnclosure_t*>(pStructure->arrData);

		constexpr const char* arrChassisType[] =
		{
			"Other",
			"Unknown",
			"Desktop",
			"Low Profile Desktop",
			"Pizza Box",
			"Mini Tower",
			"Tower",
			"Portable",
			"Laptop",
			"Notebook",
			"Hand Held",
			"Docking Station",
			"All in One",
			"Sub Notebook",
			"Space-saving",
			"Lunch Box",
			"Main Server Chassis",
			"Expansion Chassis",
			"SubChassis",
			"Bus Expansion Chassis",
			"Peripheral Chassis",
			"RAID Chassis",
			"Rack Mount Chassis",
			"Sealed-case PC",
			"Multi-system Chassis",
			"Compact PCI",
			"Advanced TCA",
			"Blade",
			"Blade Enclosure",
			"Tablet",
			"Convertible",
			"Detachable",
			"IoT Gateway",
			"Embedded PC",
			"Mini PC",
			"Stick PC"
		};
		std::printf("Manufacturer: %s\nType: %s\nVersion: %s\nSerial Number: %s\nAsset Tag Number: %s\n",
			arrStringMap[pSE->nManufacturer],
			arrChassisType[pSE->nChassisType - 1U],
			arrStringMap[pSE->nVersion],
			arrStringMap[pSE->nSerialNumber],
			arrStringMap[pSE->nAssetTagNumber]);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemEnclosure_t, nBootUpState))
			break;

		constexpr const char* arrState[] =
		{
			"Other",
			"Unknown",
			"Safe",
			"Warning",
			"Critical",
			"Non-recoverable"
		};

		constexpr const char* arrSecurityState[] =
		{
			"Other",
			"Unknown",
			"None",
			"External interface locked out",
			"External interface enabled"
		};
		std::printf("Boot Up State: %s\nPower Supply State: %s\nThermal State: %s\nSecurity Status: %s\n",
			arrState[pSE->nBootUpState - 1U],
			arrState[pSE->nPowerSupplyState - 1U],
			arrState[pSE->nThermalState - 1U],
			arrSecurityState[pSE->nSecurityStatus - 1U]);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemEnclosure_t, uOemDefined))
			break;

		if (pSE->nHeight == 0U)
			std::printf("Height: None\n");
		else
			std::printf("Height: %uU\n", pSE->nHeight);
		if (pSE->nPowerCordsNumber == 0U)
			std::printf("Power cords: None\n");
		else
			std::printf("Power cords: %u\n", pSE->nPowerCordsNumber);

		// @test: it seems wrong?
		std::printf("Contained Elements: %u\n", pSE->nContainedElementCount);
		if (pSE->nContainedElementRecordLength >= sizeof(SMBIOS::EnclosureContainedElement_t))
		{
			for (std::uint8_t i = 0U; i < pSE->nContainedElementCount; ++i)
			{
				const SMBIOS::EnclosureContainedElement_t* pContainedElement = &pSE->arrContainedElements[i];
				const char* szType = pContainedElement->nTypeSelect ? arrStructureType[pContainedElement->nType] : arrBaseBoardType[pContainedElement->nType - 1U];
				if (pContainedElement->nMinCount == pContainedElement->nMaxCount)
					std::printf("%u. %s: %u\n", i + 1U, szType, pContainedElement->nMinCount);
				else
					std::printf("%u. %s: %u-%u\n", i + 1U, szType, pContainedElement->nMinCount, pContainedElement->nMaxCount);
			}
		}

		const std::uint32_t nTotalContainedElementsSize = pSE->nContainedElementRecordLength * pSE->nContainedElementCount;
		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemEnclosure_t, arrContainedElements) + nTotalContainedElementsSize)
			break;

		std::printf("SKU Number: %s\n", arrStringMap[*reinterpret_cast<const SMBIOS::StringIndex_t*>(reinterpret_cast<const std::uint8_t*>(pSE->arrContainedElements) + nTotalContainedElementsSize)]);
		break;
	}
	case SMBIOS::TYPE_PROCESSOR_INFORMATION:
	{
		const auto pPI = reinterpret_cast<const SMBIOS::ProcessorInformation_t*>(pStructure->arrData);

		SMBIOS::ProcessorFamilyExtended_t nFamilyIndex = pPI->nFamily;
		if (nFamilyIndex == SMBIOS::PROCESSOR_FAMILY_EXTENDED && pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, nFamilyExtended))
			nFamilyIndex = pPI->nFamilyExtended;
		const char* szManufacturer = arrStringMap[pPI->nManufacturer];

		constexpr const char* arrType[] =
		{
			"Other",
			"Unknown",
			"Central Processor",
			"Math Processor",
			"DSP Processor",
			"Video Processor"
		};

		using namespace SMBIOS;
		constexpr struct { ProcessorFamilyExtended_t nIndex; const char* szValue; } arrFamily[] =
		{
			{ PROCESSOR_FAMILY_OTHER, "Other" },
			{ PROCESSOR_FAMILY_UNKNOWN, "Unknown" },
			{ PROCESSOR_FAMILY_8086, "8086" },
			{ PROCESSOR_FAMILY_80286, "80286" },
			{ PROCESSOR_FAMILY_I386, "i386" },
			{ PROCESSOR_FAMILY_I486, "i486" },
			{ PROCESSOR_FAMILY_8087, "8087" },
			{ PROCESSOR_FAMILY_80287, "80287" },
			{ PROCESSOR_FAMILY_80387, "80387" },
			{ PROCESSOR_FAMILY_80487, "80487" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM, "Pentium" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_PRO, "Pentium Pro" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_II, "Pentium II" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_MMX, "Pentium MMX" },
			{ PROCESSOR_FAMILY_INTEL_CELERON, "Celeron" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_II_XEON, "Pentium II Xeon"},
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_III, "Pentium III" },
			{ PROCESSOR_FAMILY_M1, "M1" },
			{ PROCESSOR_FAMILY_M2, "M2" },
			{ PROCESSOR_FAMILY_INTEL_CELERON_M, "Celeron M" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_4HT, "Pentium 4 HT" },
			{ PROCESSOR_FAMILY_INTEL, "Intel" },

			{ PROCESSOR_FAMILY_AMD_DURON, "Duron" },
			{ PROCESSOR_FAMILY_AMD_K5, "K5" },
			{ PROCESSOR_FAMILY_AMD_K6, "K6" },
			{ PROCESSOR_FAMILY_AMD_K6_2, "K6-2" },
			{ PROCESSOR_FAMILY_AMD_K6_3, "K6-3" },
			{ PROCESSOR_FAMILY_AMD_ATHLON, "Athlon" },
			{ PROCESSOR_FAMILY_AMD_29000, "AMD29000" },
			{ PROCESSOR_FAMILY_AMD_K6_2PLUS, "K6-2+" },
			{ PROCESSOR_FAMILY_PPC, "Power PC" },
			{ PROCESSOR_FAMILY_PPC_601, "Power PC 601" },
			{ PROCESSOR_FAMILY_PPC_603, "Power PC 603" },
			{ PROCESSOR_FAMILY_PPC_603PLUS, "Power PC 603+" },
			{ PROCESSOR_FAMILY_PPC_604, "Power PC 604" },
			{ PROCESSOR_FAMILY_PPC_620, "Power PC 620" },
			{ PROCESSOR_FAMILY_PPC_X704, "Power PC x704" },
			{ PROCESSOR_FAMILY_PPC_750, "Power PC 750" },
			{ PROCESSOR_FAMILY_INTEL_CORE_DUO, "Core Duo" },
			{ PROCESSOR_FAMILY_INTEL_CORE_DUO_MOBILE, "Core Duo Mobile" },
			{ PROCESSOR_FAMILY_INTEL_CORE_SOLO_MOBILE, "Core Solo Mobile" },
			{ PROCESSOR_FAMILY_INTEL_ATOM, "Atom" },
			{ PROCESSOR_FAMILY_INTEL_CORE_M, "Core M" },
			{ PROCESSOR_FAMILY_INTEL_CORE_M3, "Core m3" },
			{ PROCESSOR_FAMILY_INTEL_CORE_M5, "Core m5" },
			{ PROCESSOR_FAMILY_INTEL_CORE_M7, "Core m7" },
			{ PROCESSOR_FAMILY_ALPHA, "Alpha" },
			{ PROCESSOR_FAMILY_ALPHA_21064, "Alpha 21064" },
			{ PROCESSOR_FAMILY_ALPHA_21066, "Alpha 21066" },
			{ PROCESSOR_FAMILY_ALPHA_21164, "Alpha 21164" },
			{ PROCESSOR_FAMILY_ALPHA_21164PC, "Alpha 21164PC" },
			{ PROCESSOR_FAMILY_ALPHA_21164A, "Alpha 21164a" },
			{ PROCESSOR_FAMILY_ALPHA_21264, "Alpha 21264" },
			{ PROCESSOR_FAMILY_ALPHA_21364, "Alpha 21364" },
			{ PROCESSOR_FAMILY_AMD_TURION_II_ULTRA_MOBILE_M, "Turion II Ultra Dual-Core Mobile M" },
			{ PROCESSOR_FAMILY_AMD_TURION_II_MOBILE_M, "Turion II Dual-Core Mobile M" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_II_M, "Athlon II Dual-Core M" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_6100, "Opteron 6100" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_4100, "Opteron 4100" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_6200, "Opteron 6200" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_4200, "Opteron 4200" },
			{ PROCESSOR_FAMILY_AMD_FX, "FX" },
			{ PROCESSOR_FAMILY_MIPS, "MIPS" },
			{ PROCESSOR_FAMILY_MIPS_R4000, "MIPS R4000" },
			{ PROCESSOR_FAMILY_MIPS_R4200, "MIPS R4200" },
			{ PROCESSOR_FAMILY_MIPS_R4400, "MIPS R4400" },
			{ PROCESSOR_FAMILY_MIPS_R4600, "MIPS R4600" },
			{ PROCESSOR_FAMILY_MIPS_R10000, "MIPS R10000" },
			{ PROCESSOR_FAMILY_AMD_C, "C-Series" },
			{ PROCESSOR_FAMILY_AMD_E, "E-Series" },
			{ PROCESSOR_FAMILY_AMD_A, "A-Series" },
			{ PROCESSOR_FAMILY_AMD_G, "G-Series" },
			{ PROCESSOR_FAMILY_AMD_Z, "Z-Series" },
			{ PROCESSOR_FAMILY_AMD_R, "R-Series" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_4300, "Opteron 4300" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_6300, "Opteron 6300" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_3300, "Opteron 3300" },
			{ PROCESSOR_FAMILY_AMD_FIREPRO, "FirePro" },
			{ PROCESSOR_FAMILY_SPARC, "SPARC" },
			{ PROCESSOR_FAMILY_SUPERSPARC, "SuperSPARC" },
			{ PROCESSOR_FAMILY_MIRCOSPARC_II, "MicroSPARC II" },
			{ PROCESSOR_FAMILY_MIRCOSPARC_IIEP, "MicroSPARC IIep" },
			{ PROCESSOR_FAMILY_ULTRASPARC, "UltraSPARC" },
			{ PROCESSOR_FAMILY_ULTRASPARC_II, "UltraSPARC II" },
			{ PROCESSOR_FAMILY_ULTRASPARC_I2, "UltraSPARC Iii" },
			{ PROCESSOR_FAMILY_ULTRASPARC_III, "UltraSPARC III" },
			{ PROCESSOR_FAMILY_ULTRASPARC_III1, "UltraSPARC IIIi" },

			{ PROCESSOR_FAMILY_68040, "68040" },
			{ PROCESSOR_FAMILY_68XXX, "68XXX" },
			{ PROCESSOR_FAMILY_68000, "68000" },
			{ PROCESSOR_FAMILY_68010, "68010" },
			{ PROCESSOR_FAMILY_68020, "68020" },
			{ PROCESSOR_FAMILY_68030, "68030" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_X4_QUAD_CORE, "Athlon X4" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_X1000, "Opteron X1000" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_X2000, "Opteron X2000" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_A, "Opteron A-Series" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_X3000, "Opteron X3000" },
			{ PROCESSOR_FAMILY_AMD_ZEN, "Zen" },

			{ PROCESSOR_FAMILY_HOBBIT, "Hobbit" },

			{ PROCESSOR_FAMILY_CRUSOE_TM5000, "Crusoe TM5000" },
			{ PROCESSOR_FAMILY_CRUSOE_TM3000, "Crusoe TM3000" },
			{ PROCESSOR_FAMILY_EFFICEON_TM8000, "Efficeon TM8000" },

			{ PROCESSOR_FAMILY_WEITEK, "Weitek" },

			{ PROCESSOR_FAMILY_ITANIUM, "Itanium" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_64, "Athlon 64" },
			{ PROCESSOR_FAMILY_AMD_OPTERON, "Opteron" },
			{ PROCESSOR_FAMILY_AMD_SEMPRON, "Sempron" },
			{ PROCESSOR_FAMILY_AMD_TURION_64_MOBILE, "Turion 64 Mobile" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_DUAL_CORE, "Dual-Core Opteron" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_64_X2_DUAL_CORE, "Athlon 64 X2" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_64_X2_MOBILE, "Turion 64 X2 Mobile" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_QUAD_CORE, "Opteron Quad-Core" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_GEN3, "Opteron Third-Generation" },
			{ PROCESSOR_FAMILY_AMD_PHENOM_FX_QUAD_CORE, "Phenom FX Quad-Core" },
			{ PROCESSOR_FAMILY_AMD_PHENOM_X4_QUAD_CORE, "Phenom X4 Quad-Core" },
			{ PROCESSOR_FAMILY_AMD_PHENOM_X2_DUAL_CORE, "Phenom X2 Dual-Core" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_X2_DUAL_CORE, "Athlon X2 Dual-Core" },
			{ PROCESSOR_FAMILY_PARISC, "PA-RISC" },
			{ PROCESSOR_FAMILY_PARISC_8500, "PA-RISC 8500" },
			{ PROCESSOR_FAMILY_PARISC_8000, "PA-RISC 8000" },
			{ PROCESSOR_FAMILY_PARISC_7300LC, "PA-RISC 7300LC" },
			{ PROCESSOR_FAMILY_PARISC_7200, "PA-RISC 7200" },
			{ PROCESSOR_FAMILY_PARISC_7100LC, "PA-RISC 7100LC" },
			{ PROCESSOR_FAMILY_PARISC_7100, "PA-RISC 7100" },

			{ PROCESSOR_FAMILY_V30, "V30" },
			{ PROCESSOR_FAMILY_INTEL_XEON_QUAD_CORE_3200, "Xeon Quad-Core 3200" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_3000, "Xeon Dual-Core 3000" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_5300, "Xeon Quad-Core 5300" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_5100, "Xeon Dual-Core 5100" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_5000, "Xeon Dual-Core 5000" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_LV, "Xeon Dual-Core LV" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_ULV, "Xeon Dual-Core ULV" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_7100, "Xeon Dual-Core 7100" },
			{ PROCESSOR_FAMILY_INTEL_XEON_QUAD_CORE_5400, "Xeon Quad-Core 5400" },
			{ PROCESSOR_FAMILY_INTEL_XEON_QUAD_CORE, "Xeon Quad-Core" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_5200, "Xeon Dual-Core 5200" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_7200, "Xeon Dual-Core 7200" },
			{ PROCESSOR_FAMILY_INTEL_XEON_QUAD_CORE_7300, "Xeon Quad-Core 7300" },
			{ PROCESSOR_FAMILY_INTEL_XEON_QUAD_CORE_7400, "Xeon Quad-Core 7400" },
			{ PROCESSOR_FAMILY_INTEL_XEON_MULTI_CORE_7400, "Xeon Multi-Core 7400" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_III_XEON, "Pentium III Xeon" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_III_SPEEDSTEP, "Pentium III SpeedStep" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_4, "Pentium 4" },
			{ PROCESSOR_FAMILY_INTEL_XEON, "Xeon" },
			{ PROCESSOR_FAMILY_AS400, "AS400" },
			{ PROCESSOR_FAMILY_INTEL_XEON_MP, "Xeon MP" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_XP, "Athlon XP" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_MP, "Athlon MP" },
			{ PROCESSOR_FAMILY_INTEL_ITANIUM_2, "Itanium 2" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_M, "Pentium M" },
			{ PROCESSOR_FAMILY_INTEL_CELERON_D, "Celeron D" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_D, "Pentium D" },
			{ PROCESSOR_FAMILY_INTEL_PENTIUM_EXTREME, "Pentium Extreme Edition" },
			{ PROCESSOR_FAMILY_INTEL_CORE_SOLO, "Core Solo" },
			/* 0xBE handled as a special case */
			{ PROCESSOR_FAMILY_INTEL_CORE_2_DUO, "Core 2 Duo" },
			{ PROCESSOR_FAMILY_INTEL_CORE_2_SOLO, "Core 2 Solo" },
			{ PROCESSOR_FAMILY_INTEL_CORE_2_EXTREME, "Core 2 Extreme" },
			{ PROCESSOR_FAMILY_INTEL_CORE_2_QUAD, "Core 2 Quad" },
			{ PROCESSOR_FAMILY_INTEL_CORE_2_EXTREME_MOBILE, "Core 2 Extreme Mobile" },
			{ PROCESSOR_FAMILY_INTEL_CORE_2_DUO_MOBILE, "Core 2 Duo Mobile" },
			{ PROCESSOR_FAMILY_INTEL_CORE_2_SOLO_MOBILE, "Core 2 Solo Mobile" },
			{ PROCESSOR_FAMILY_INTEL_CORE_I7, "Core i7" },
			{ PROCESSOR_FAMILY_INTEL_CELERON_DUAL_CORE, "Celeron Dual-Core" },
			{ PROCESSOR_FAMILY_IBM390, "IBM390" },
			{ PROCESSOR_FAMILY_G4, "G4" },
			{ PROCESSOR_FAMILY_G5, "G5" },
			{ PROCESSOR_FAMILY_G6_ESA390, "ESA/390 G6" },
			{ PROCESSOR_FAMILY_ZARCHITECTURE, "z/Architecture" },
			{ PROCESSOR_FAMILY_INTEL_CORE_I5, "Core i5" },
			{ PROCESSOR_FAMILY_INTEL_CORE_I3, "Core i3" },
			{ PROCESSOR_FAMILY_INTEL_CORE_I9, "Core i9" },
			{ PROCESSOR_FAMILY_INTEL_XEON_D, "Xeon D" },

			{ PROCESSOR_FAMILY_VIA_C7_M, "C7-M" },
			{ PROCESSOR_FAMILY_VIA_C7_D, "C7-D" },
			{ PROCESSOR_FAMILY_VIA_C7, "C7" },
			{ PROCESSOR_FAMILY_VIA_EDEN, "Eden" },
			{ PROCESSOR_FAMILY_INTEL_XEON_MULTI_CORE, "Xeon Multi-Core" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_3XXX, "Xeon Dual-Core 3XXX" },
			{ PROCESSOR_FAMILY_INTEL_XEON_QUAD_CORE_3XXX, "Xeon Quad-Core 3XXX" },
			{ PROCESSOR_FAMILY_VIA_NANO, "Nano" },
			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_5XXX, "Xeon Dual-Core 5XXX" },
			{ PROCESSOR_FAMILY_INTEL_XEON_QUAD_CORE_5XXX, "Xeon Quad-Core 5XXX" },

			{ PROCESSOR_FAMILY_INTEL_XEON_DUAL_CORE_7XXX, "Xeon Dual-Core 7XXX" },
			{ PROCESSOR_FAMILY_INTEL_XEON_QUAD_CORE_7XXX, "Xeon Quad-Core 7XXX" },
			{ PROCESSOR_FAMILY_INTEL_XEON_MULTI_CORE_7XXX, "Xeon Multi-Core 7XXX" },
			{ PROCESSOR_FAMILY_INTEL_XEON_MULTI_CORE_3400, "Xeon Multi-Core 3400" },

			{ PROCESSOR_FAMILY_AMD_OPTERON_3000, "Opteron 3000" },
			{ PROCESSOR_FAMILY_AMD_SEMPRON_II, "Sempron II" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_QUAD_CORE_EMBEDDED, "Embedded Opteron Quad-Core" },
			{ PROCESSOR_FAMILY_AMD_PHENOM_TRIPLE_CORE, "Phenom Triple-Core" },
			{ PROCESSOR_FAMILY_AMD_TURION_ULTRA_DUAL_CORE, "Turion Ultra Dual-Core Mobile" },
			{ PROCESSOR_FAMILY_AMD_TURION_DUAL_CORE_MOBILE, "Turion Dual-Core Mobile" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_DUAL_CORE, "Athlon Dual-Core" },
			{ PROCESSOR_FAMILY_AMD_SEMPRON_SI, "Sempron SI" },
			{ PROCESSOR_FAMILY_AMD_PHENOM_II, "Phenom II" },
			{ PROCESSOR_FAMILY_AMD_ATHLON_II, "Athlon II" },
			{ PROCESSOR_FAMILY_AMD_OPTERON_SIX_CORE, "Opteron Six-Core" },
			{ PROCESSOR_FAMILY_AMD_SEMPRON_M, "Sempron M" },

			{ PROCESSOR_FAMILY_I860, "i860" },
			{ PROCESSOR_FAMILY_I960, "i960" },

			{ PROCESSOR_FAMILY_ARMV7, "ARMv7" },
			{ PROCESSOR_FAMILY_ARMV8, "ARMv8" },
			{ PROCESSOR_FAMILY_ARMV9, "ARMv9" },
			{ PROCESSOR_FAMILY_ARM_RESERVED, "ARM" },
			{ PROCESSOR_FAMILY_SH3, "SH-3" },
			{ PROCESSOR_FAMILY_SH4, "SH-4" },

			{ PROCESSOR_FAMILY_ARM, "ARM" },
			{ PROCESSOR_FAMILY_STRONGARM, "StrongARM" },

			{ PROCESSOR_FAMILY_6X86, "6x86" },
			{ PROCESSOR_FAMILY_MEDIAGX, "MediaGX" },
			{ PROCESSOR_FAMILY_MII, "MII" },

			{ PROCESSOR_FAMILY_WINCHIP, "WinChip" },
			{ PROCESSOR_FAMILY_DSP, "DSP" },
			{ PROCESSOR_FAMILY_VIDEO_PROCESSOR, "Video Processor" },

			{ PROCESSOR_FAMILY_RV32, "RV32" },
			{ PROCESSOR_FAMILY_RV64, "RV64" },
			{ PROCESSOR_FAMILY_RV128, "RV128" },

			{ PROCESSOR_FAMILY_LOONGARCH, "LoongArch" },
			{ PROCESSOR_FAMILY_LOONGSON_1, "Loongson 1" },
			{ PROCESSOR_FAMILY_LOONGSON_2, "Loongson 2" },
			{ PROCESSOR_FAMILY_LOONGSON_3, "Loongson 3" },
			{ PROCESSOR_FAMILY_LOONGSON_2K, "Loongson 2K" },
			{ PROCESSOR_FAMILY_LOONGSON_3A, "Loongson 3A" },
			{ PROCESSOR_FAMILY_LOONGSON_3B, "Loongson 3B" },
			{ PROCESSOR_FAMILY_LOONGSON_3C, "Loongson 3C" },
			{ PROCESSOR_FAMILY_LOONGSON_3D, "Loongson 3D" },
			{ PROCESSOR_FAMILY_LOONGSON_3E, "Loongson 3E" },
			{ PROCESSOR_FAMILY_LOONGSON_DUAL_CORE_2K_2XXX, "Loongson Dual-Core 2K 2XXX" },
			{ PROCESSOR_FAMILY_LOONGSON_QUAD_CORE_3A_5XXX, "Loongson Quad-Core 3A 5XXX" },
			{ PROCESSOR_FAMILY_LOONGSON_MULTI_CORE_3A_5XXX, "Loongson Multi-Core 3A 5XXX" },
			{ PROCESSOR_FAMILY_LOONGSON_QUAD_CORE_3B_5XXX, "Loongson Quad-Core 3B 5XXX" },
			{ PROCESSOR_FAMILY_LOONGSON_MULTI_CORE_3B_5XXX, "Loongson Multi-Core 3B 5XXX" },
			{ PROCESSOR_FAMILY_LOONGSON_MULTI_CORE_3C_5XXX, "Loongson Multi-Core 3C 5XXX" },
			{ PROCESSOR_FAMILY_LOONGSON_MULTI_CORE_3D_5XXX, "Loongson Multi-Core 3D 5XXX" },

			{ PROCESSOR_FAMILY_INTEL_CORE_3, "Core 3" },
			{ PROCESSOR_FAMILY_INTEL_CORE_5, "Core 5" },
			{ PROCESSOR_FAMILY_INTEL_CORE_7, "Core 7" },
			{ PROCESSOR_FAMILY_INTEL_CORE_9, "Core 9" },
			{ PROCESSOR_FAMILY_INTEL_CORE_ULTRA_3, "Core Ultra 3" },
			{ PROCESSOR_FAMILY_INTEL_CORE_ULTRA_5, "Core Ultra 5" },
			{ PROCESSOR_FAMILY_INTEL_CORE_ULTRA_7, "Core Ultra 7" },
			{ PROCESSOR_FAMILY_INTEL_CORE_ULTRA_9, "Core Ultra 9" }
		};

		const char* szFamily = "Reserved";
		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, uL1CacheHandle) && nFamilyIndex == PROCESSOR_FAMILY_ALPHA && ::strstr(szManufacturer, "Intel") != nullptr)
			szFamily = "Pentium Pro";
		else if (nFamilyIndex == (PROCESSOR_FAMILY_INTEL_CORE_2 | PROCESSOR_FAMILY_AMD_K7))
		{
			if (::strstr(szManufacturer, "Intel") != nullptr)
				szFamily = "Core 2";
			else if (::strstr(szManufacturer, "AMD") != nullptr || ::strstr(szManufacturer, "Advanced Micro Devices") != nullptr)
				szFamily = "K7";
			else
				szFamily = "Core 2 / K7";
		}
		else
		{
			for (const auto [nIndex, szValue] : arrFamily)
			{
				if (nIndex == nFamilyIndex)
				{
					szFamily = szValue;
					break;
				}
			}
		}
		std::printf("Socket Designation: %s\nType: %s\nFamily: %s\nManufacturer: %s\n",
			arrStringMap[pPI->nSocketDesignation],
			arrType[pPI->nType - 1U],
			szFamily,
			szManufacturer);

		// @todo: cpuid

		std::printf("Version: %s\n", arrStringMap[pPI->nVersion]);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, nSocketType))
		{
			if (pPI->bVoltageLegacyMode)
				std::printf("Voltage: %.1fV\n", static_cast<float>(pPI->uVoltageValue) / 10);
			else
			{
				std::printf("Voltage: ");
				SMBIOS::VoltageFlags_t uVoltageFlags = pPI->uVoltageFlags;
				for (std::uint8_t i = 0U; i < 3U; ++i)
				{
					if (uVoltageFlags & (1U << i))
					{
						uVoltageFlags &= ~(1U << i);
						std::printf("%s%c", arrVoltage[i], uVoltageFlags != 0U ? '/' : '\n');
					}
				}
			}
		}

		if (pPI->uExternalClock == 0U)
			std::printf("External Clock: Unknown\n");
		else
			std::printf("External Clock: %uMHz\n", pPI->uExternalClock);

		if (pPI->uMaxSpeed == 0U)
			std::printf("Max Speed (System Supported): Unknown\n");
		else
			std::printf("Max Speed (System Supported): %uMHz\n", pPI->uMaxSpeed);

		std::printf("Current Speed (System Boot): %uMHz\n", pPI->uCurrentSpeed);

		constexpr const char* arrActiveStatus[] =
		{
			"Unknown",
			"Enabled",
			"Disabled by User",
			"Idle"
		};

		constexpr const char* arrUpgrade[] =
		{
			"Other",
			"Unknown",
			"Daugher Board",
			"Socket ZIF",
			"Replaceable Piggy Bank",
			"None",
			"Socket LIF",
			"Slot 1",
			"Slot 2",
			"Socket 370-pin",
			"Slot A",
			"Slot M",
			"Socket 423",
			"Socket A",
			"Socket 478",
			"Socket 454",
			"Socket 940",
			"Socket 939",
			"Socket mPGA604",
			"Socket LGA771",
			"Socket LGA775",
			"Socket S1",
			"Socket AM2",
			"Socket F",
			"Socket LGA1366",
			"Socket G34",
			"Socket AM3",
			"Socket C32",
			"Socket LGA1156",
			"Socket LGA1567",
			"Socket PGA988A",
			"Socket BGA1288",
			"Socket rPGA988B",
			"Socket BGA1023",
			"Socket BGA1224",
			"Socket LGA1155",
			"Socket LGA1356",
			"Socket LGA2011",
			"Socket FS1",
			"Socket FS2",
			"Socket FM1",
			"Socket FM2",
			"Socket LGA2011-3",
			"Socket LGA1356-3",
			"Socket LGA1150",
			"Socket BGA1168",
			"Socket BGA1234",
			"Socket BGA1364",
			"Socket AM4",
			"Socket LGA1151",
			"Socket BGA1356",
			"Socket BGA1440",
			"Socket BGA1515",
			"Socket LGA3647-1",
			"Socket SP3",
			"Socket SP3r2",
			"Socket LGA2066",
			"Socket BGA1392",
			"Socket BGA1510",
			"Socket BGA1528",
			"Socket LGA4189",
			"Socket LGA1200",
			"Socket LGA4677",
			"Socket LGA1700",
			"Socket BGA1744",
			"Socket BGA1781",
			"Socket BGA1211",
			"Socket BGA2422",
			"Socket LGA1211",
			"Socket LGA2422",
			"Socket LGA5773",
			"Socket BGA5773",
			"Socket AM5",
			"Socket SP5",
			"Socket SP6",
			"Socket BGA883",
			"Socket BGA1190",
			"Socket BGA4129",
			"Socket LGA4710",
			"Socket LGA7529",
			"Socket BGA1964",
			"Socket BGA1792",
			"Socket BGA2049",
			"Socket BGA2551",
			"Socket LGA1851",
			"Socket BGA2114",
			"Socket BGA2833",
		};

		std::printf("Status: %s\nSocket: %s\n", arrActiveStatus[pPI->nStatus], pPI->bSocketPopulated ? "Populated" : "Unpopulated");
		
		if (pPI->nUpgrade != PROCESSOR_UPGRADE_WILDCARD)
			std::printf("Upgrade: %s\n", arrUpgrade[pPI->nUpgrade - 1U]);
		else if (pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, nSocketType))
			std::printf("Socket Type: %s\n", arrStringMap[pPI->nSocketType]);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, uL1CacheHandle))
			break;

		std::printf("L1 Cache Handle: 0x%04X\nL2 Cache Handle: 0x%04X\nL3 Cache Handle: 0x%04X\n", pPI->uL1CacheHandle, pPI->uL2CacheHandle, pPI->uL3CacheHandle);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, nSerialNumber))
			break;

		std::printf("Serial Number: %s\nAsset Tag: %s\nPart Number: %s\n",
			arrStringMap[pPI->nSerialNumber],
			arrStringMap[pPI->nAssetTag],
			arrStringMap[pPI->nPartNumber]);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, nCoreCount))
			break;

		constexpr const char* arrCharacteristics[] =
		{
			"Unknown",
			"64-bit Capable",
			"Multi-Core",
			"Hardware Thread",
			"Execute Protection",
			"Enhanced Virtualization",
			"Power/Performance Control",
			"128-bit Capable",
			"ARM64 SoC ID",
		};
		std::printf("Characteristics:\n");
		for (std::uint16_t i = 1U; i < 9U; ++i)
		{
			if (pPI->uCharacteristics & (1U << i))
				std::printf("\t%s\n", arrCharacteristics[i - 1U]);
		}

		std::uint16_t nCoreCount = pPI->nCoreCount;
		std::uint16_t nCoreEnabled = pPI->nCoreEnabled;
		std::uint16_t nThreadCount = pPI->nThreadCount;

		if (pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, nCoreCountExtended))
		{
			if (nCoreCount == 0xFF)
				nCoreCount = pPI->nCoreCountExtended;
			if (nCoreEnabled == 0xFF)
				nCoreEnabled = pPI->nCoreEnabledExtended;
			if (nThreadCount == 0xFF)
				nThreadCount = pPI->nThreadCountExtended;
		}

		if (nCoreCount == 0U)
			std::printf("Core Count: Unknown\n");
		else
			std::printf("Core Count: %" PRIu16 "\n", nCoreCount);
		
		if (nCoreEnabled == 0U)
			std::printf("Core Enabled: Unknown\n");
		else
			std::printf("Core Enabled: %" PRIu16 "\n", nCoreEnabled);

		if (nThreadCount == 0U)
			std::printf("Thread Count: Unknown\n");
		else
			std::printf("Thread Count: %" PRIu16 "\n", nThreadCount);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::ProcessorInformation_t, nThreadEnabled))
			break;

		std::printf("Thread Enabled: %" PRIu16 "\n", pPI->nThreadEnabled);
		break;
	}
	case SMBIOS::TYPE_MEMORY_CONTROLLER_INFORMATION:
	{
		const auto pMCI = reinterpret_cast<const SMBIOS::MemoryControllerInformation_t*>(pStructure->arrData);

		constexpr const char* arrErrorDetectingMethod[] =
		{
			"Other",
			"Unknown",
			"None",
			"8-bit Parity",
			"32-bit ECC",
			"64-bit ECC",
			"128-bit ECC",
			"CRC",
		};
		std::printf("Error Detecting Method: %s\nError Correcting Capability:\n", arrErrorDetectingMethod[pMCI->nErrorDetectingMethod - 1U]);
		
		constexpr const char* arrErrorCorrectingCapability[] =
		{
			"Other",
			"Unknown",
			"None",
			"Single-bit",
			"Double-bit",
			"Scrubbing"
		};
		for (std::uint8_t i = 0U; i < Q_ARRAYSIZE(arrErrorCorrectingCapability); ++i)
		{
			if (pMCI->uErrorCorrectingCapability & (1U << i))
				std::printf("\t%s\n", arrErrorCorrectingCapability[i]);
		}

		constexpr const char* arrInterleaveSupportType[] =
		{
			"Other",
			"Unknown",
			"One-Way",
			"Two-Way",
			"Four-Way",
			"Eight-Way",
			"Sixteen-Way"
		};
		std::printf("Supported Interleave: %s\nCurrent Interleave: %s\nMax Memory Module Size: %" PRIu64 "MiB\nMax Total Memory Size: %" PRIu64 "MiB\nSupported Speeds:\n",
			arrInterleaveSupportType[pMCI->nSupportedInterleave - 1U],
			arrInterleaveSupportType[pMCI->nCurrentInterleave - 1U],
			1ULL << pMCI->nMaxMemoryModuleSize,
			(1ULL << pMCI->nMaxMemoryModuleSize) * pMCI->nAssociatedMemorySlotsCount);
		
		constexpr const char* arrSupportedSpeed[] =
		{
			"Other",
			"Unknown",
			"70ns",
			"60ns",
			"50ns"
		};
		for (std::uint16_t i = 0U; i < Q_ARRAYSIZE(arrSupportedSpeed); ++i)
		{
			if (pMCI->uSupportedSpeeds & (1U << i))
				std::printf("\t%s\n", arrSupportedSpeed[i]);
		}
		
		std::printf("Supported Types:\n");
		for (std::uint16_t i = 0U; i < Q_ARRAYSIZE(arrMemoryType); ++i)
		{
			if (pMCI->uSupportedTypes & (1U << i))
				std::printf("\t%s\n", arrMemoryType[i]);
		}

		std::printf("Voltage: ");
		SMBIOS::VoltageFlags_t uVoltageFlags = pMCI->uMemoryModuleVoltage;
		for (std::uint8_t i = 0U; i < Q_ARRAYSIZE(arrVoltage); ++i)
		{
			if (uVoltageFlags & (1U << i))
			{
				uVoltageFlags &= ~(1U << i);
				std::printf("%s%c", arrVoltage[i], uVoltageFlags != 0U ? '/' : '\n');
			}
		}

		std::printf("Associated Memory Slots: %u\n", pMCI->nAssociatedMemorySlotsCount);
		for (std::uint8_t i = 0U; i < pMCI->nAssociatedMemorySlotsCount; ++i)
			std::printf("%u. 0x%04X\n", i + 1U, pMCI->arrMemoryModuleConfigurationHandles[i]);

		const std::uint32_t nTotalAssociatedMemorySlotsSize = sizeof(std::uint16_t) * pMCI->nAssociatedMemorySlotsCount;
		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::MemoryControllerInformation_t, arrMemoryModuleConfigurationHandles) + nTotalAssociatedMemorySlotsSize)
			break;

		const auto uEnabledErrorCorrectingCapabilites = *reinterpret_cast<const SMBIOS::MemoryControllerErrorCorrectingCapability_t*>(pStructure->arrData + Q_OFFSETOF(SMBIOS::MemoryControllerInformation_t, arrMemoryModuleConfigurationHandles) + nTotalAssociatedMemorySlotsSize);
		std::printf("Enabled Error Correcting Capabilities:\n");
		for (std::uint8_t i = 0U; i < Q_ARRAYSIZE(arrErrorCorrectingCapability); ++i)
		{
			if (uEnabledErrorCorrectingCapabilites & (1U << i))
				std::printf("\t%s\n", arrErrorCorrectingCapability[i]);
		}

		break;
	}
	case SMBIOS::TYPE_MEMORY_MODULE_INFORMATION:
	{
		const auto pMMI = reinterpret_cast<const SMBIOS::MemoryModuleInformation_t*>(pStructure->arrData);
		std::printf("Socket Designation: %s\n", arrStringMap[pMMI->nSocketDesignation]);

		if (pMMI->uBankConnections == 0xFF)
			std::printf("Bank Connections: None\n");
		else if ((pMMI->uBankConnections & 0xF0) == 0xF0)
			std::printf("Bank Connections: %u", pMMI->uBankConnections >> 4U);
		else if ((pMMI->uBankConnections & 0x0F) == 0x0F)
			std::printf("Bank Connections: %u", pMMI->uBankConnections & 0x0F);
		else
			std::printf("Bank Connections: %u %u", pMMI->uBankConnections >> 4U, pMMI->uBankConnections & 0x0F);

		if (pMMI->uCurrentSpeed != 0U)
			std::printf("Current Speed: %uns\n", pMMI->uCurrentSpeed);
		else
			std::printf("Current Speed: Unknown\n");

		std::printf("Current Memory Type:\n");
		for (std::uint8_t i = 0U; i < Q_ARRAYSIZE(arrMemoryType); ++i)
		{
			if (pMMI->uCurrentMemoryType & (1U << i))
				std::printf("\t%s\n", arrMemoryType[i]);
		}

		// @test: not sure as it isn't clear could installed has Q_SMBIOS_MEMORY_MODULE_SIZE_NOT_ENABLED value?
		if (pMMI->nInstalledSize == Q_SMBIOS_MEMORY_MODULE_SIZE_NOT_DETERMINABLE ||
			pMMI->nInstalledSize == Q_SMBIOS_MEMORY_MODULE_SIZE_NOT_INSTALLED)
			std::printf("Installed Size: %s\n", pMMI->nInstalledSize == Q_SMBIOS_MEMORY_MODULE_SIZE_NOT_DETERMINABLE ? "Not Determinable" : "Not Installed");
		else
			std::printf("Installed Size: %" PRIu64 "MiB (%s)\n", 1ULL << pMMI->nInstalledSize, pMMI->bInstalledDoubleBank ? "Double-Bank" : "Single-Bank");

		// @test: not sure as it isn't clear could enabled has Q_SMBIOS_MEMORY_MODULE_SIZE_NOT_DETERMINABLE value?
		if (pMMI->nEnabledSize == Q_SMBIOS_MEMORY_MODULE_SIZE_NOT_ENABLED ||
			pMMI->nEnabledSize == Q_SMBIOS_MEMORY_MODULE_SIZE_NOT_INSTALLED)
			std::printf("Enabled Size: %s\n", pMMI->nEnabledSize == Q_SMBIOS_MEMORY_MODULE_SIZE_NOT_ENABLED ? "Not Enabled" : "Not Installed");
		else
			std::printf("Enabled Size: %" PRIu64 "MiB (%s)\n", 1ULL << pMMI->nEnabledSize, pMMI->bEnabledDoubleBank ? "Double-Bank" : "Single-Bank");

		constexpr const char* arrErrorStatus[] =
		{
			"OK",
			"Uncorrectable",
			"Correctable",
			"Uncorrectable & Correctable"
		};
		std::printf("Error Status: %s\n", (pMMI->uErrorStatus& Q_SMBIOS_MEMORY_MODULE_ERROR_LOG) ? "Event Log" : arrErrorStatus[pMMI->uErrorStatus]);
		break;
	}
	case SMBIOS::TYPE_CACHE_INFORMATION:
	{
		const auto pCI = reinterpret_cast<const SMBIOS::CacheInformation_t*>(pStructure->arrData);
		std::printf("Socket Designation: %s\n", arrStringMap[pCI->nSocketDesignation]);

		constexpr const char* arrLocation[] =
		{
			"Internal",
			"External",
			"Reserved",
			"Unknown"
		};
		constexpr const char* arrOperationalMode[] =
		{
			"Write Through",
			"Write Back",
			"Varies with Memory Address",
			"Unknown"
		};
		std::printf("Configuration:\n\tLevel: %u\n\tSocketed: %s\n\tLocation: %s\n\tOperational Mode: %s\n",
			pCI->nLevel,
			pCI->bSocketed ? " true" : "false",
			arrLocation[pCI->nLocation],
			arrOperationalMode[pCI->nOperationalMode]);

		if (pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::CacheInformation_t, nAssociativity) + 1U)
		{
			const std::uint64_t nMaxSizeKiB = (pCI->nMaxSizeExtendedGranularity ? (pCI->nMaxSizeExtended * 64U) : pCI->nMaxSizeExtended);
			const std::uint64_t nInstalledSizeKiB = (pCI->nInstalledSizeExtendedGranularity ? (pCI->nInstalledSizeExtended * 64U) : pCI->nInstalledSizeExtended);
			std::printf("Max Size: %" PRIu64 "%s\nInstalled Size: %" PRIu64 "%s\n",
				nMaxSizeKiB >= 1024U ? nMaxSizeKiB / 1024U : nMaxSizeKiB, arrSizeUnit[nMaxSizeKiB >= 1024U],
				nInstalledSizeKiB >= 1024U ? nInstalledSizeKiB / 1024U : nInstalledSizeKiB, arrSizeUnit[nInstalledSizeKiB >= 1024U]);
		}
		else
		{
			const std::uint32_t nMaxSizeKiB = (pCI->nMaxSizeGranularity ? (pCI->nMaxSize * 64U) : pCI->nMaxSize);
			const std::uint32_t nInstalledSizeKiB = (pCI->nInstalledSizeGranularity ? (pCI->nInstalledSize * 64U) : pCI->nInstalledSize);
			std::printf("Max Size: %" PRIu32 "%s\nInstalled Size: %" PRIu32 "%s\n",
				nMaxSizeKiB >= 1024U ? nMaxSizeKiB / 1024U : nMaxSizeKiB, arrSizeUnit[nMaxSizeKiB >= 1024U],
				nInstalledSizeKiB >= 1024U ? nInstalledSizeKiB / 1024U : nInstalledSizeKiB, arrSizeUnit[nInstalledSizeKiB >= 1024U]);
		}

		constexpr const char* arrSRAMType[] =
		{
			"Other",
			"Unknown",
			"Non-Burst",
			"Burst",
			"Pipeline Burst",
			"Synchronous",
			"Asynchronous"
		};
		std::printf("Supported SRAM Type:\n");
		for (std::uint16_t i = 0U; i < Q_ARRAYSIZE(arrSRAMType); ++i)
		{
			if (pCI->uSupportedSRAMType & (1U << i))
				std::printf("\t%s\n", arrSRAMType[i]);
		}

		std::printf("Current SRAM Type:\n");
		for (std::uint16_t i = 0U; i < Q_ARRAYSIZE(arrSRAMType); ++i)
		{
			if (pCI->uCurrentSRAMType & (1U << i))
				std::printf("\t%s\n", arrSRAMType[i]);
		}

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::CacheInformation_t, uSpeed))
			break;

		if (pCI->uSpeed != 0U)
			std::printf("Speed: %uns\n", pCI->uSpeed);
		else
			std::printf("Speed: Unknown\n");

		constexpr const char* arrErrorCorrectionType[] =
		{
			"Other",
			"Unknown",
			"None",
			"Parity",
			"Single-bit ECC",
			"Multi-bit ECC",
		};
		constexpr const char* arrSystemCacheType[] =
		{
			"Other",
			"Unknown",
			"Instruction",
			"Data",
			"Unified"
		};
		constexpr const char* arrAssociativity[] =
		{
			"Other",
			"Unknown",
			"Direct Mapped",
			"2-way Set",
			"4-way Set",
			"Fully",
			"8-way Set",
			"16-way Set",
			"12-way Set",
			"24-way Set",
			"32-way Set",
			"48-way Set",
			"64-way Set",
			"20-way Set"
		};
		std::printf("Error Correction Type: %s\nSystem Cache Type: %s\nAssociativity: %s\n",
			arrErrorCorrectionType[pCI->nErrorCorrectionType - 1U],
			arrSystemCacheType[pCI->nSystemCacheType - 1U],
			arrAssociativity[pCI->nAssociativity - 1U]);
		break;
	}
	case SMBIOS::TYPE_PORT_CONNECTOR_INFORMATION:
	{
		const auto pPCI = reinterpret_cast<const SMBIOS::PortConnectorInformation_t*>(pStructure->arrData);

		constexpr const char* arrConnectorType[] =
		{
			"None",
			"Centronics",
			"Mini Centronics",
			"Proprietary",
			"DB-25 male",
			"DB-25 female",
			"DB-15 male",
			"DB-15 female",
			"DB-9 male",
			"DB-9 female",
			"RJ-11",
			"RJ-45",
			"50-pin MiniSCSI",
			"Mini-DIN",
			"Micro-DIN",
			"PS/2",
			"Infrared",
			"HP-HIL",
			"Access Bus (USB)",
			"SSA SCSI",
			"Circular DIN-8 male",
			"Circular DIN-8 female",
			"On Board IDE",
			"On Board Floppy",
			"9-pin Dual Inline (pin 10 cut)",
			"25-pin Dual Inline (pin 26 cut)",
			"50-pin Dual Inline",
			"68-pin Dual Inline",
			"On Board Sound Input From CD-ROM",
			"Mini-Centronics Type-14",
			"Mini-Centronics Type-26",
			"Mini-Jack (headphones)",
			"BNC",
			"IEEE 1394",
			"SAS/SATA Plug Receptacle",
			"USB Type-C Receptacle"
		};

		constexpr const char* arrConnectorExtraType[] =
		{
			"PC-98",
			"PC-98Hireso",
			"PC-H98",
			"PC-98Note",
			"PC-98Full"
		};
		
		constexpr const char* arrPortType[] =
		{
			"None",
			"Parallel Port XT/AT Compatible",
			"Parallel Port PS/2",
			"Parallel Port ECP",
			"Parallel Port EPP",
			"Parallel Port ECP/EPP",
			"Serial Port XT/AT Compatible",
			"Serial Port 16450 Compatible",
			"Serial Port 16550 Compatible",
			"Serial Port 16550A Compatible",
			"SCSI Port",
			"MIDI Port",
			"Joystick Port",
			"Keyboard Port",
			"Mouse Port",
			"SSA SCSI",
			"USB",
			"FireWire (IEEE P1394)",
			"PCMCIA Type I",
			"PCMCIA Type II",
			"PCMCIA Type III",
			"Card bus",
			"Access Bus Port",
			"SCSI II",
			"SCSI Wide",
			"PC-98",
			"PC-98 Hireso",
			"PC-H98",
			"Video Port",
			"Audio Port",
			"Modem Port",
			"Network Port",
			"SATA",
			"SAS",
			"MFDP (Multi-Function Display Port)",
			"Thunderbolt"
		};

		constexpr const char* arrPortExtraType[] =
		{
			"8251 Compatible",
			"8251 FIFO Compatible"
		};

		std::printf("Internal Reference Designator: %s\nInternal Connector Type: %s\nExternal Reference Designator: %s\nExternal Connector Type: %s\nPort Type: %s\n",
			arrStringMap[pPCI->nInternalReferenceDesignator],
			pPCI->nInternalConnectorType == SMBIOS::PORT_CONNECTOR_OTHER ?
				arrStringMap[pPCI->nInternalReferenceDesignator] :
				(pPCI->nInternalConnectorType >= SMBIOS::PORT_CONNECTOR_PC_98) ?
					arrConnectorExtraType[pPCI->nInternalConnectorType - SMBIOS::PORT_CONNECTOR_PC_98] :
					arrConnectorType[pPCI->nInternalConnectorType],
			arrStringMap[pPCI->nExternalReferenceDesignator],
			pPCI->nExternalConnectorType == SMBIOS::PORT_CONNECTOR_OTHER ?
				arrStringMap[pPCI->nExternalReferenceDesignator] :
				(pPCI->nExternalConnectorType >= SMBIOS::PORT_CONNECTOR_PC_98) ?
					arrConnectorExtraType[pPCI->nInternalConnectorType - SMBIOS::PORT_CONNECTOR_PC_98] :
					arrConnectorType[pPCI->nExternalConnectorType],
			pPCI->nPortType == SMBIOS::PORT_OTHER ? "Other" :
				pPCI->nPortType >= SMBIOS::PORT_8251_COMPATIBLE ?
					arrPortExtraType[pPCI->nPortType - SMBIOS::PORT_8251_COMPATIBLE] :
					arrPortType[pPCI->nPortType]);
		break;
	}
	case SMBIOS::TYPE_SYSTEM_SLOTS:
	{
		const auto pSS = reinterpret_cast<const SMBIOS::SystemSlots_t*>(pStructure->arrData);

		using namespace SMBIOS;
		constexpr struct { SlotType_t nIndex; const char* szValue; } arrSlotTypes[] =
		{
			{ SLOT_OTHER, "Other" },
			{ SLOT_UNKNOWN, "Unknown" },
			{ SLOT_ISA, "ISA" },
			{ SLOT_MCA, "MCA" },
			{ SLOT_EISA, "EISA" },
			{ SLOT_PCI, "PCI" },
			{ SLOT_PCMCIA, "PC Card (PCMCIA)" },
			{ SLOT_VLVESA, "VL-VESA" },
			{ SLOT_PROPRIETARY, "Proprietary" },
			{ SLOT_PROCESSOR_CARD, "Processor Card" },
			{ SLOT_PROPRIETARY_MEMORY_CARD, "Proprietary Memory Card" },
			{ SLOT_IO_RISER_CARD, "I/O Riser Card" },
			{ SLOT_NUBUS, "NuBus" },
			{ SLOT_PCI_66MHZ, "PCI 66MHz Capable" },
			{ SLOT_AGP, "AGP" },
			{ SLOT_AGP_2X, "AGP 2X" },
			{ SLOT_AGP_4X, "AGP 4X" },
			{ SLOT_PCI_X, "PCI-X" },
			{ SLOT_AGP_8X, "AGP 8X" },
			{ SLOT_M2_SOCKET_1_DP, "M.2 Socket 1-DP" },
			{ SLOT_M2_SOCKET_1_SD, "M.2 Socket 1-SD" },
			{ SLOT_M2_SOCKET_2, "M.2 Socket 2" },
			{ SLOT_M2_SOCKET_3, "M.2 Socket 3" },
			{ SLOT_MXM_TYPE_I, "MXM Type I" },
			{ SLOT_MXM_TYPE_II, "MXM Type II" },
			{ SLOT_MXM_TYPE_III, "MXM Type III" },
			{ SLOT_MXM_TYPE_III_HE, "MXM Type III-HE" },
			{ SLOT_MXM_TYPE_IV, "MXM Type IV" },
			{ SLOT_MXM3_TYPE_A, "MXM 3.0 Type A" },
			{ SLOT_MXM3_TYPE_B, "MXM 3.0 Type B" },
			{ SLOT_PCIE2_U2, "PCI Express 2 SFF-8639 (U.2)" },
			{ SLOT_PCIE3_U2, "PCI Express 3 SFF-8639 (U.2)" },
			{ SLOT_PCIE_MINI_52PIN_BOTTOM, "PCI Express Mini 52-pin with bottom-side keep-outs" },
			{ SLOT_PCIE_MINI_52PIN, "PCI Express Mini 52-pin without bottom-side keep-outs" },
			{ SLOT_PCIE_MINI_76PIN, "PCI Express Mini 76-pin" },
			{ SLOT_PCIE4_U2, "PCI Express 4 SFF-8639 (U.2)" },
			{ SLOT_PCIE5_U2, "PCI Express 5 SFF-8639 (U.2)" },
			{ SLOT_OCP_NIC3_SFF, "OCP NIC 3.0 SFF" },
			{ SLOT_OCP_NIC3_LFF, "OCP NIC 3.0 LFF" },
			{ SLOT_OCP_NIC3, "OCP NIC Prior to 3.0" },

			{ SLOT_CXL_FLEXBUS1, "CXL Flexbus 1.0" },

			{ SLOT_PC98_C20, "PC-98/C20" },
			{ SLOT_PC98_C24, "PC-98/C24" },
			{ SLOT_PC98_E, "PC-98/E" },
			{ SLOT_PC98_LOCAL_BUS, "PC-98/Local Bus" },
			{ SLOT_PC98_CARD, "PC-98/Card" },
			{ SLOT_PCIE, "PCI Express" },
			{ SLOT_PCIE_X1, "PCI Express x1" },
			{ SLOT_PCIE_X2, "PCI Express x2" },
			{ SLOT_PCIE_X4, "PCI Express x4" },
			{ SLOT_PCIE_X8, "PCI Express x8" },
			{ SLOT_PCIE_X16, "PCI Express x16" },
			{ SLOT_PCIE2, "PCI Express 2" },
			{ SLOT_PCIE2_X1, "PCI Express 2 x1" },
			{ SLOT_PCIE2_X2, "PCI Express 2 x2" },
			{ SLOT_PCIE2_X4, "PCI Express 2 x4" },
			{ SLOT_PCIE2_X8, "PCI Express 2 x8" },
			{ SLOT_PCIE2_X16, "PCI Express 2 x16" },
			{ SLOT_PCIE3, "PCI Express 3" },
			{ SLOT_PCIE3_X1, "PCI Express 3 x1" },
			{ SLOT_PCIE3_X2, "PCI Express 3 x2" },
			{ SLOT_PCIE3_X4, "PCI Express 3 x4" },
			{ SLOT_PCIE3_X8, "PCI Express 3 x8" },
			{ SLOT_PCIE3_X16, "PCI Express 3 x16" },
			{ SLOT_PCIE4, "PCI Express 4" },
			{ SLOT_PCIE4_X1, "PCI Express 4 x1" },
			{ SLOT_PCIE4_X2, "PCI Express 4 x2" },
			{ SLOT_PCIE4_X4, "PCI Express 4 x4" },
			{ SLOT_PCIE4_X8, "PCI Express 4 x8" },
			{ SLOT_PCIE4_X16, "PCI Express 4 x16" },
			{ SLOT_PCIE5, "PCI Express 5" },
			{ SLOT_PCIE5_X1, "PCI Express 5 x1" },
			{ SLOT_PCIE5_X2, "PCI Express 5 x2" },
			{ SLOT_PCIE5_X4, "PCI Express 5 x4" },
			{ SLOT_PCIE5_X8, "PCI Express 5 x8" },
			{ SLOT_PCIE5_X16, "PCI Express 5 x16" },
			{ SLOT_PCIE6, "PCI Express 6+" },
			{ SLOT_EDSFF_E1, "EDSFF E1" },
			{ SLOT_EDSFF_E3, "EDSFF E3" }
		};

		const char* szSlotType = "Reserved";
		for (const auto [nIndex, szValue] : arrSlotTypes)
		{
			if (nIndex == pSS->nSlotType)
			{
				szSlotType = szValue;
				break;
			}
		}

		constexpr const char* arrDataBusWidth[] =
		{
			"Other",
			"Unknown",
			"8-bit",
			"16-bit",
			"32-bit",
			"64-bit",
			"128-bit",
			"1x or x1",
			"2x or x2",
			"4x or x4",
			"8x or x8",
			"12x or x12",
			"16x or x16",
			"32x or x32"
		};

		constexpr const char* arrCurrentUsage[] =
		{
			"Other",
			"Unknown",
			"Available",
			"In Use",
			"Unavailable"
		};

		constexpr const char* arrSlotLength[] =
		{
			"Other",
			"Unknown",
			"Short",
			"Long",
			"2.5\" drive form factor",
			"3.5\" drive form factor"
		};

		std::printf("Slot Designation: %s\nSlot Type: %s\nSlot Databus Width: %s\nCurrent Usage: %s\nSlot Length: %s\n",
			arrStringMap[pSS->nSlotDesignation],
			szSlotType,
			arrDataBusWidth[pSS->nSlotDataBusWidth - 1U],
			arrCurrentUsage[pSS->nCurrentUsage - 1U],
			arrSlotLength[pSS->nSlotLength - 1U]);

		// @todo: slot id

		constexpr const char* arrCharacteristics[] =
		{
			"Unknown",
			"5V is provided",
			"3.3V is provided",
			"Opening is shared",
			"PC Card-16 is supported",
			"PC Card supports CardBus",
			"PC Card supports Zoom Video",
			"PC Card supports Modem Ring Resume"
		};

		std::printf("Slot Characteristics:\n");
		for (std::uint16_t i = 0U; i < Q_ARRAYSIZE(arrCharacteristics); ++i)
		{
			if (pSS->uSlotCharacteristics & (1U << i))
				std::printf("\t%s\n", arrCharacteristics[i]);
		}

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemSlots_t, uSlotCharacteristicsExtended))
			break;

		constexpr const char* arrCharacteristicsExtended[] =
		{
			"PCI supports PME signal",
			"Slot supports hot-plug devices",
			"PCI supports SMBus signal",
			"PCIe supports bifurcation",
			"Slot supports async/surprise removal",
			"Flexbus slot, CXL 1.0 capable",
			"Flexbus slot, CXL 2.0 capable",
			"Flexbus slot, CXL 3.0 capable"
		};
		for (std::uint16_t i = 0U; i < Q_ARRAYSIZE(arrCharacteristicsExtended); ++i)
		{
			if (pSS->uSlotCharacteristicsExtended & (1U << i))
				std::printf("\t%s\n", arrCharacteristicsExtended[i]);
		}

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemSlots_t, nSegmentGroupNumber))
			break;

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemSlots_t, nDataBusWidth))
		{
			std::printf("Peer Base Data: S:%04X / B:%02X / F:%u / D:%u\n", pSS->nSegmentGroupNumber, pSS->nBusNumber, pSS->uFunctionNumber, pSS->uDeviceNumber);
			break;
		}

		std::printf("Peer Base Data: S:%04X / B:%02X / F:%u / D:%u / W:%u\n", pSS->nSegmentGroupNumber, pSS->nBusNumber, pSS->uFunctionNumber, pSS->uDeviceNumber, pSS->nDataBusWidth);
		std::printf("Peer Groups: %u\n", pSS->nPeerGroupingCount);
		for (std::uint8_t i = 0U; i < pSS->nPeerGroupingCount; ++i)
		{
			const SMBIOS::SystemSlotsPeerGroup_t* pPeerGroup = &pSS->arrPeerGroups[i];
			std::printf("%u. S:%04X / B:%02X / F:%u / D:%u / W:%u\n", i + 1U, pPeerGroup->uSegmentGroupNumber, pPeerGroup->uBusNumber, pPeerGroup->uFunctionNumber, pPeerGroup->uDeviceNumber, pPeerGroup->nDataBusWidth);
		}

		const std::uint32_t nTotalPeerGroupsSize = sizeof(SMBIOS::SystemSlotsPeerGroup_t) * pSS->nPeerGroupingCount;
		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemSlots_t, arrPeerGroups) + nTotalPeerGroupsSize)
			break;
		
		const std::uint8_t* pStructureEnd = reinterpret_cast<const std::uint8_t*>(pSS->arrPeerGroups) + nTotalPeerGroupsSize;
		
		const std::uint8_t uSlotInformation = pStructureEnd[0];
		if (uSlotInformation != 0U)
			std::printf("Slot Information: %u\n", uSlotInformation);

		const std::uint8_t nSlotPhysicalWidth = pStructureEnd[1];
		std::printf("Slot Physical Width: %u\n", nSlotPhysicalWidth);

		const std::uint16_t nSlotPitch = *reinterpret_cast<const std::uint16_t*>(pStructureEnd + 2);
		if (nSlotPitch != 0U)
			std::printf("Slot Pitch: %.1fmm\n", static_cast<float>(nSlotPitch) / 100);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemSlots_t, arrPeerGroups) + nTotalPeerGroupsSize + 3U)
			break;

		constexpr const char* arrSlotHeight[] =
		{
			"Not applicable",
			"Other",
			"Unknown",
			"Full",
			"Low-profile"
		};
		const SMBIOS::SlotHeight_t nSlotHeight = pStructureEnd[4];
		std::printf("Slot Height: %s\n", arrSlotHeight[nSlotHeight]);
		break;
	}
	case SMBIOS::TYPE_ONBOARD_DEVICES_INFORMATION:
	{
		const auto pOBDI = reinterpret_cast<const SMBIOS::OnBoardDevicesInformation_t*>(pStructure->arrData);

		const std::uint8_t nCount = (pStructure->nLength - 4U) >> 1U;
		for (std::uint8_t i = 0U; i < nCount; ++i)
		{
			const SMBIOS::OnBoardDevice_t* pOnBoardDevice = &pOBDI->arrDevices[i];
			std::printf("%u. Type: %s\n   Enabled: %s\n   Description: %s\n", i + 1U,
				arrOnBoardDeviceType[pOnBoardDevice->nType - 1U],
				pOnBoardDevice->bEnabled ? "true" : "false",
				arrStringMap[pOnBoardDevice->nDescription]);
		}

		break;
	}
	case SMBIOS::TYPE_OEM_STRINGS:
	{
		const auto pOS = reinterpret_cast<const SMBIOS::OemStrings_t*>(pStructure->arrData);

		for (std::uint8_t i = 1U; i <= pOS->nCount; ++i)
			std::printf("%u. %s\n", i, arrStringMap[i]);

		break;
	}
	case SMBIOS::TYPE_SYSTEM_CONFIGURATION_OPTIONS:
	{
		const auto pSCO = reinterpret_cast<const SMBIOS::SystemConfigurationOptions_t*>(pStructure->arrData);

		for (std::uint8_t i = 1U; i <= pSCO->nCount; ++i)
			std::printf("%u. %s\n", i, arrStringMap[i]);

		break;
	}
	case SMBIOS::TYPE_FIRMWARE_LANGUAGE_INFORMATION:
	{
		const auto pFLI = reinterpret_cast<const SMBIOS::FirmwareLanguageInformation_t*>(pStructure->arrData);

		// @test: is there a way to get rid of this version check, so that we dont depend on it at all?
		if (uVersion >= 0x020100)
			std::printf("Lanugage Format: %s\n", pFLI->bUseAbbreviatedFormat ? "Abbreviated" : "Long");

		std::printf("Installable Languages: %u\n", pFLI->nInstallableLanguagesCount);
		for (std::uint8_t i = 1U; i <= pFLI->nInstallableLanguagesCount; ++i)
			std::printf("%u. %s\n", i, arrStringMap[i]);

		std::printf("Current Language: %s\n", arrStringMap[pFLI->nCurrentLanguage]);
		break;
	}
	case SMBIOS::TYPE_GROUP_ASSOCIATIONS:
	{
		const auto pGA = reinterpret_cast<const SMBIOS::GroupAssociations_t*>(pStructure->arrData);

		const std::uint8_t nCount = (pStructure->nLength - 5U) / 3U;
		std::printf("Name: %s\nItems: %u\n", arrStringMap[pGA->nGroupName], nCount);
		for (std::uint8_t i = 0U; i < nCount; ++i)
		{
			const SMBIOS::GroupAssociationsItem_t* pItem = &pGA->arrItems[i];
			std::printf("%u. Item Type: %s\n   Item Handle: 0x%04X\n", i + 1U, arrStructureType[pItem->nType], pItem->uHandle);
		}

		break;
	}
	case SMBIOS::TYPE_SYSTEM_EVENT_LOG:
	{
		const auto pSEL = reinterpret_cast<const SMBIOS::SystemEventLog_t*>(pStructure->arrData);

		constexpr const char* arrAccessMethod[] =
		{
			"Indexed I/O, one 8-bit index port, one 8-bit data port",
			"Indexed I/O, two 8-bit index ports, one 8-bit data port",
			"Indexed I/O, one 16-bit index port, one 8-bit data port",
			"Memory-mapped physical 32-bit address",
			"General-purpose non-volatile data functions"
		};

		std::printf("Area Length: %u\nHeader Start Offset: 0x%04X\nData Start Offset: 0x%04X\nAccess Method: %s\nStatus: %s, %s\n",
			pSEL->nAreaLength,
			pSEL->uHeaderStartOffset,
			pSEL->uDataStartOffset,
			pSEL->nAccessMethod >= 0x80 ? "OEM Specific" : arrAccessMethod[pSEL->nAccessMethod],
			pSEL->bAreaValid ? "Valid" : "Invalid", pSEL->bAreaFull ? "Full" : "Not Full");

		if (pSEL->uChangeToken == 0U)
			std::printf("Change Token: None\n");
		else
			std::printf("Change Token: 0x%08X\n", pSEL->uChangeToken);

		switch (pSEL->nAccessMethod)
		{
		case SMBIOS::EVENT_LOG_ACCESS_METHOD_IO_ONE_8BIT_INDEX_ONE_8BIT_DATA:
		case SMBIOS::EVENT_LOG_ACCESS_METHOD_IO_TWO_8BIT_INDEX_ONE_8BIT_DATA:
		case SMBIOS::EVENT_LOG_ACCESS_METHOD_IO_ONE_16BIT_INDEX_ONE_8BIT_DATA:
			std::printf("Access Address: Index - 0x%04X, Data - 0x%04X\n", pSEL->uIndexAddress, pSEL->uDataAddress);
			break;
		case SMBIOS::EVENT_LOG_ACCESS_METHOD_MEMORY_MAPPED_PHYSICAL_32BIT_ADDRESS:
			std::printf("Access Address: 0x%08X\n", pSEL->uAccessMethodAddress);
			break;
		case SMBIOS::EVENT_LOG_ACCESS_METHOD_GENERAL_PURPOSE_NON_VOLATILE:
			std::printf("Access Address: GPNV Handle - 0x%04X\n", pSEL->uHandleGPNV);
			break;
		default:
			std::printf("Access Address: Unknown\n");
			break;
		}

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::SystemEventLog_t, nHeaderFormat))
			break;

		std::printf("Header Format: %s\n", pSEL->nHeaderFormat >= 0x80 ? "OEM Specific" : pSEL->nHeaderFormat == 1U ? "Type 1" : "No Header");
		
		if (pSEL->nTypeDescriptorCount != 0U)
		{
			constexpr const char* arrType[] =
			{
				"Single-bit ECC memory error",
				"Multi-bit ECC memory error",
				"Parity memory error",
				"Bus timeout",
				"I/O channel block",
				"Software NMI",
				"POST memory resize",
				"POST error",
				"PCI parity error",
				"PCI system error",
				"CPU failure",
				"EISA failsafe timer timeout",
				"Correctable memory log disabled",
				"Logging disabled",
				"Reserved",
				"System limit exceeded",
				"Asynchronous hardware timer expired",
				"System configuration information",
				"Hard disk information",
				"System reconfigured",
				"Uncorrectable CPU-complex error",
				"Log area reset/cleared",
				"System boot"
			};
			constexpr const char* arrFormatType[] =
			{
				"None",
				"Handle",
				"Multiple-event",
				"Multiple-event handle",
				"POST results bitmap",
				"System management",
				"Multiple-event system management"
			};

			std::printf("Type Descriptors: %u\n", pSEL->nTypeDescriptorCount);
			for (std::uint8_t i = 0U; i < pSEL->nTypeDescriptorCount; ++i)
			{
				// @todo: we must also note that length may vary
				const SMBIOS::EventLogTypeDescriptor_t* pTypeDescriptor = &pSEL->arrTypeDescriptorsList[i];
				std::printf("%u. Type: %s\n   Format Type: %s\n", i + 1U,
					pTypeDescriptor->nLogType == SMBIOS::EVENT_LOG_END ? "End of log" : arrType[pTypeDescriptor->nLogType - 1U],
					arrFormatType[pTypeDescriptor->nVariableDataFormatType]);
			}

			// @todo: log records itself aren't dumped
		}

		break;
	}
	case SMBIOS::TYPE_PHYSICAL_MEMORY_ARRAY:
	{
		const auto pPMA = reinterpret_cast<const SMBIOS::PhysicalMemoryArray_t*>(pStructure->arrData);
		
		using namespace SMBIOS;
		constexpr struct { SMBIOS::MemoryArrayLocation_t nIndex; const char* szValue; } arrLocation[] =
		{
			{ MEMORY_ARRAY_LOCATION_OTHER, "Other" },
			{ MEMORY_ARRAY_LOCATION_UNKNOWN, "Unknown" },
			{ MEMORY_ARRAY_LOCATION_SYSTEM_BOARD, "System Board Or Motherboard" },
			{ MEMORY_ARRAY_LOCATION_ISA, "ISA Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_EISA, "EISA Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_PCI, "PCI Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_MCA, "MCA Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_PCMCIA, "PCMCIA Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_PROPRIETARY, "Proprietary Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_NUBUS, "NuBus" },

			{ MEMORY_ARRAY_LOCATION_PC98_C20, "PC-98/C20 Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_PC98_C24, "PC-98/C24 Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_PC98_E, "PC-98/E Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_PC98_LOCAL_BUS, "PC-98/Local Bus Add-on Card" },
			{ MEMORY_ARRAY_LOCATION_CXL, "CXL Add-on Card" }
		};

		const char* szLocation = "Reserved";
		for (const auto [nIndex, szValue] : arrLocation)
		{
			if (nIndex == pPMA->nLocation)
			{
				szLocation = szValue;
				break;
			}
		}

		constexpr const char* arrUse[] =
		{
			"Other",
			"Unknown",
			"System Memory",
			"Video Memory",
			"Flash Memory",
			"Non-volatile RAM",
			"Cache Memory"
		};

		constexpr const char* arrErrorCorrectionType[] =
		{
			"Other",
			"Unknown",
			"None",
			"Parity",
			"Single-bit ECC",
			"Multi-bit ECC",
			"CRC"
		};

		std::uint64_t ullMaxCapacity = pPMA->uMaxCapacity;
		if (ullMaxCapacity == 0x80000000)
			ullMaxCapacity = pPMA->ullMaxCapacityExtended;

		std::printf("Location: %s\nUse: %s\nMemory Error Correction Type: %s\nMax Capacity: %" PRIu64 "%s\n",
			szLocation,
			arrUse[pPMA->nUse - 1U],
			arrErrorCorrectionType[pPMA->nMemoryErrorCorrection - 1U],
			ullMaxCapacity >= 0x100'000 ? (ullMaxCapacity / 0x100'000) : (ullMaxCapacity >= 0x400 ? (ullMaxCapacity / 0x400) : ullMaxCapacity),
			arrSizeUnit[ullMaxCapacity >= 0x10'0000 ? 2 : (ullMaxCapacity >= 0x400 ? 1 : 0)]);

		if (pPMA->uMemoryErrorInformationHandle == 0xFFFE || pPMA->uMemoryErrorInformationHandle == Q_SMBIOS_HANDLE_INVALID)
			std::printf("Memory Error Information Handle: %s\n", pPMA->uMemoryErrorInformationHandle == 0xFFFE ? "Not Provided" : "No Error");
		else
			std::printf("Memory Error Information Handle: 0x%04X\n", pPMA->uMemoryErrorInformationHandle);

		std::printf("Memory Devices Count: %u\n", pPMA->nMemoryDevicesCount);
		break;
	}
	case SMBIOS::TYPE_MEMORY_DEVICE:
	{
		const auto pMD = reinterpret_cast<const SMBIOS::MemoryDevice_t*>(pStructure->arrData);
		std::printf("Physical Memory Array Handle: 0x%04X\n", pMD->uPhysicalMemoryArrayHandle);

		if (pMD->uMemoryErrorInformationHandle == 0xFFFE || pMD->uMemoryErrorInformationHandle == Q_SMBIOS_HANDLE_INVALID)
			std::printf("Memory Error Information Handle: %s\n", pMD->uMemoryErrorInformationHandle == 0xFFFE ? "Not Provided" : "No Error");
		else
			std::printf("Memory Error Information Handle: 0x%04X\n", pMD->uMemoryErrorInformationHandle);

		if (pMD->nTotalWidth == 0xFFFF)
			std::printf("Total Width: Unknown\n");
		else
			std::printf("Total Width: %u\n", pMD->nTotalWidth);

		if (pMD->nDataWidth == 0xFFFF)
			std::printf("Data Width: Unknown\n");
		else
			std::printf("Data Width: %u\n", pMD->nDataWidth);

		std::uint32_t nSize = pMD->nSize;
		std::uint32_t nSizeGranularity = pMD->nSizeGranulatiry;
		if (nSize == 0x7FFF)
		{
			nSize = pMD->nSizeExtended;
			nSizeGranularity = pMD->nSizeExtendedGranulatiry;
		}

		if (nSize == 0U)
			std::printf("Size: None\n");
		else if (nSize == 0xFFFF)
			std::printf("Size: Unknown\n");
		else
			std::printf("Size: %" PRIu32 "%s\n", nSize, arrSizeUnit[nSizeGranularity ^ 1U]);

		constexpr const char* arrFormFactor[] =
		{
			"Other",
			"Unknown",
			"SIMM",
			"SIP",
			"Chip",
			"DIP",
			"ZIP",
			"Proprietary Card",
			"DIMM",
			"TSOP",
			"Row Of Chips",
			"RIMM",
			"SODIMM",
			"SRIMM",
			"FB-DIMM",
			"Die"
		};
		std::printf("Form Factor: %s\n", arrFormFactor[pMD->nFormFactor - 1U]);

		if (pMD->uDeviceSet == 0U)
			std::printf("Device Set: None\n");
		else if (pMD->uDeviceSet == 0xFF)
			std::printf("Device Set: Unknown\n");
		else
			std::printf("Device Set: %u\n", pMD->uDeviceSet);

		constexpr const char* arrType[] =
		{
			"Other",
			"Unknown",
			"DRAM",
			"EDRAM",
			"VRAM",
			"SRAM",
			"RAM",
			"ROM",
			"Flash",
			"EEPROM",
			"FEPROM",
			"EPROM",
			"CDRAM",
			"3DRAM",
			"SDRAM",
			"SGRAM",
			"RDRAM",
			"DDR",
			"DDR2",
			"DDR2 FB-DIMM",
			"Reserved",
			"Reserved",
			"Reserved",
			"DDR3",
			"FBD2",
			"DDR4",
			"LPDDR",
			"LPDDR2",
			"LPDDR3",
			"LPDDR4",
			"Logical non-volatile device",
			"HBM",
			"HBM2",
			"DDR5",
			"LPDDR5",
			"HBM3"
		};
		std::printf("Device Locator: %s\nBank Locator: %s\nMemory Type: %s\n",
			arrStringMap[pMD->nDeviceLocator],
			arrStringMap[pMD->nBankLocator],
			arrType[pMD->nMemoryType - 1U]);

		static const char* arrTypeDetail[] =
		{
			"Other",
			"Unknown",
			"Fast-paged",
			"Static Column",
			"Pseudo-static",
			"Rambus",
			"Synchronous",
			"CMOS",
			"EDO",
			"Window DRAM",
			"Cache DRAM",
			"Non-Volatile",
			"Registered (Buffered)",
			"Unregistered (Unbuffered)",
			"LRDIMM"
		};
		std::printf("Type Detail:\n");
		for (std::uint16_t i = 1U; i < Q_ARRAYSIZE(arrTypeDetail); ++i)
		{
			if (pMD->uTypeDetail & (1U << i))
				std::printf("\t%s\n", arrTypeDetail[i]);
		}

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::MemoryDevice_t, uSpeed))
			break;

		std::uint32_t uSpeed = pMD->uSpeed;
		if (uSpeed == 0xFFFF)
			uSpeed = pMD->uSpeedExtended;

		if (uSpeed == 0U)
			std::printf("Speed: Unknown\n");
		else
			std::printf("Speed: %" PRIu32 "MT/s\n", uSpeed);

		std::printf("Manufacturer: %s\nSerial Number: %s\nAsset Tag: %s\nPart Number: %s\n", arrStringMap[pMD->nManufacturer], arrStringMap[pMD->nSerialNumber], arrStringMap[pMD->nAssetTag], arrStringMap[pMD->nPartNumber]);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::MemoryDevice_t, uAttributes))
			break;

		std::printf("Rank: %u\n", pMD->uRank);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::MemoryDevice_t, uAttributes) + 1U)
			break;

		std::uint32_t uConfiguredSpeed = pMD->uConfiguredSpeed;
		if (uConfiguredSpeed == 0xFFFF)
			uConfiguredSpeed = pMD->uConfiguredSpeedExtended;

		if (uConfiguredSpeed == 0U)
			std::printf("Configured Speed: Unknown\n");
		else
			std::printf("Configured Speed: %" PRIu32 "MT/s\n", uConfiguredSpeed);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::MemoryDevice_t, uMinVoltage))
			break;

		std::printf("Min Voltage: %" PRIu16 "mV\nMax Voltage: %" PRIu16 "mV\nConfigured Voltage: %" PRIu16 "mV\n", pMD->uMinVoltage, pMD->uMaxVoltage, pMD->uConfiguredVoltage);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::MemoryDevice_t, nMemoryTechnology))
			break;

		constexpr const char* arrTechnology[] =
		{
			"Other",
			"Unknown",
			"DRAM",
			"NVDIMM-N",
			"NVDIMM-F",
			"NVDIMM-P",
			"Intel Optane DC persistent memory",
			"MRDIMM"
		};
		std::printf("Memory Technology: %s\n", arrTechnology[pMD->nMemoryTechnology - 1U]);

		constexpr const char* arrOperatingModeCapability[] =
		{
			"Other",
			"Unknown",
			"Volatile memory",
			"Byte-accessible persistent memory",
			"Block-accessible persistent memory"
		};

		std::printf("Operating Mode Capability:\n");
		for (std::uint16_t i = 1U; i < Q_ARRAYSIZE(arrOperatingModeCapability); ++i)
		{
			if (pMD->uOperatingModeCapability & (1U << i))
				std::printf("\t%s\n", arrOperatingModeCapability[i]);
		}

		std::printf("Firmware Version: %s\n", arrStringMap[pMD->nFirmwareVersion]);

		if (pMD->uModuleManufacturerID == 0U)
			std::printf("Module Manufacturer ID: Unknown\n");
		else
			std::printf("Module Manufacturer ID: 0x%04X\n", pMD->uModuleManufacturerID);

		if (pMD->uModuleProductID == 0U)
			std::printf("Module Product ID: Unknown\n");
		else
			std::printf("Module Product ID: 0x%04X\n", pMD->uModuleProductID);

		if (pMD->uMemorySubsystemControllerManufacturerID == 0U)
			std::printf("Subsystem Controller Manufacturer ID: Unknown\n");
		else
			std::printf("Subsystem Controller Manufacturer ID: 0x%04X\n", pMD->uMemorySubsystemControllerManufacturerID);

		if (pMD->uMemorySubsystemControllerProductID == 0U)
			std::printf("Subsystem Controller Product ID: Unknown\n");
		else
			std::printf("Subsystem Controller Product ID: 0x%04X\n", pMD->uMemorySubsystemControllerProductID);

		if (pMD->ullNonVolatileSize == 0ULL)
			std::printf("Non Volatile Size: None\n");
		else if (pMD->ullNonVolatileSize == ~0ULL)
			std::printf("Non Volatile Size: Unknown\n");
		else
			std::printf("Non Volatile Size: %" PRIu64 "\n", pMD->ullNonVolatileSize);

		if (pMD->ullVolatileSize == 0ULL)
			std::printf("Volatile Size: None\n");
		else if (pMD->ullVolatileSize == ~0ULL)
			std::printf("Volatile Size: Unknown\n");
		else
			std::printf("Volatile Size: %" PRIu64 "\n", pMD->ullVolatileSize);

		if (pMD->ullCacheSize == 0ULL)
			std::printf("Cache Size: None\n");
		else if (pMD->ullCacheSize == ~0ULL)
			std::printf("Cache Size: Unknown\n");
		else
			std::printf("Cache Size: %" PRIu64 "\n", pMD->ullCacheSize);

		if (pMD->ullLogicalSize == 0ULL)
			std::printf("Logical Size: None\n");
		else if (pMD->ullLogicalSize == ~0ULL)
			std::printf("Logical Size: Unknown\n");
		else
			std::printf("Logical Size: %" PRIu64 "\n", pMD->ullLogicalSize);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::MemoryDevice_t, uPMIC0ManufacturerID))
			break;

		if (pMD->uPMIC0ManufacturerID == 0U)
			std::printf("PMIC0 Manufacturer ID: Unknown\n");
		else
			std::printf("PMIC0 Manufacturer ID: 0x%04X\n", pMD->uPMIC0ManufacturerID);

		if (pMD->uPMIC0RevisionNumber == 0xFF00)
			std::printf("PMIC0 Revision Number: Unknown\n");
		else
			std::printf("PMIC0 Revision Number: 0x%04X\n", pMD->uPMIC0RevisionNumber);
		
		if (pMD->uRCDManufacturerID == 0U)
			std::printf("RCD Manufacturer ID: Unknown\n");
		else
			std::printf("RCD Manufacturer ID: 0x%04X\n", pMD->uRCDManufacturerID);

		if (pMD->uRCDRevisionNumber == 0xFF00)
			std::printf("RCD Revision Number: Unknown\n");
		else
			std::printf("RCD Revision Number: 0x%04X\n", pMD->uRCDRevisionNumber);

		break;
	}
	case SMBIOS::TYPE_MEMORY_32BIT_ERROR_INFORMATION:
	{
		const auto pMEI = reinterpret_cast<const SMBIOS::Memory32ErrorInformation_t*>(pStructure->arrData);
		std::printf("Type: %s\nGranularity: %s\nOperation: %s\n",
			arrMemoryErrorType[pMEI->nType - 1U],
			arrMemoryErrorGranularity[pMEI->nGranularity - 1U],
			arrMemoryErrorOperation[pMEI->nOperation - 1U]);

		if (pMEI->uVendorSyndrome == 0U)
			std::printf("Vendor Syndrome: Unknown\n");
		else
			std::printf("Vendor Syndrome: 0x%08X\n", pMEI->uVendorSyndrome);

		if (pMEI->uArrayErrorAddress == 0x80000000)
			std::printf("Array Error Address: Unknown\n");
		else
			std::printf("Array Error Address: 0x%08X\n", pMEI->uArrayErrorAddress);

		if (pMEI->uDeviceErrorAddress == 0x80000000)
			std::printf("Device Error Address: Unknown\n");
		else
			std::printf("Device Error Address: 0x%08X\n", pMEI->uDeviceErrorAddress);

		if (pMEI->uResolution == 0x80000000)
			std::printf("Resolution: Unknown\n");
		else
			std::printf("Resolution: 0x%08X\n", pMEI->uResolution);

		break;
	}
	case SMBIOS::TYPE_MEMORY_ARRAY_MAPPED_ADDRESS:
	{
		const auto pMAMA = reinterpret_cast<const SMBIOS::MemoryArrayMappedAddress_t*>(pStructure->arrData);

		std::uint64_t ullStartingAddress = pMAMA->uStartingAddress;
		if (ullStartingAddress == ~0U)
			ullStartingAddress = pMAMA->ullStartingAddressExtended;

		std::uint64_t ullEndingAddress = pMAMA->uEndingAddress;
		if (ullEndingAddress == ~0U)
			ullEndingAddress = pMAMA->ullEndingAddressExtended;

		std::printf("Starting Address: 0x%016" PRIX64 "\nEnding Address: 0x%016" PRIX64 "\nArray Handle: 0x%04X\nPartition Width: %u\n",
			ullStartingAddress,
			ullEndingAddress,
			pMAMA->uArrayHandle,
			pMAMA->nPartitionWidth);
		break;
	}
	case SMBIOS::TYPE_MEMORY_DEVICE_MAPPED_ADDRESS:
	{
		const auto pMDMA = reinterpret_cast<const SMBIOS::MemoryDeviceMappedAddress_t*>(pStructure->arrData);

		std::uint64_t ullStartingAddress = pMDMA->uStartingAddress;
		if (ullStartingAddress == ~0U)
			ullStartingAddress = pMDMA->ullStartingAddressExtended;

		std::uint64_t ullEndingAddress = pMDMA->uEndingAddress;
		if (ullEndingAddress == ~0U)
			ullEndingAddress = pMDMA->ullEndingAddressExtended;

		std::printf("Starting Address: 0x%016" PRIX64 "\nEnding Address: 0x%016" PRIX64 "\nDevice Handle: 0x%04X\nArray Mapped Address Handle: 0x%04X\n",
			ullStartingAddress,
			ullEndingAddress,
			pMDMA->uDeviceHandle,
			pMDMA->uArrayMappedAddressHandle);

		if (pMDMA->uPartitionRowPosition == 0xFF)
			std::printf("Partition Row Position: Unknown\n");
		else
			std::printf("Partition Row Position: %u\n", pMDMA->uPartitionRowPosition);

		if (pMDMA->uInterleavePosition == 0xFF)
			std::printf("Interleave Position: Unknown\n");
		else
			std::printf("Interleave Position: %u\n", pMDMA->uInterleavePosition);

		if (pMDMA->uInterleaveDataDepth == 0xFF)
			std::printf("Interleave Data Depth: Unknown\n");
		else
			std::printf("Interleave Data Depth: %u\n", pMDMA->uInterleaveDataDepth);

		break;
	}
	case SMBIOS::TYPE_BUILTIN_POINTING_DEVICE:
	{
		const auto pBPD = reinterpret_cast<const SMBIOS::BuiltinPointingDevice_t*>(pStructure->arrData);

		constexpr const char* arrType[] =
		{
			"Other",
			"Unknown",
			"Mouse",
			"Track Ball",
			"Track Point",
			"Glide Point",
			"Touch Pad",
			"Touch Screen",
			"Optical Sensor"
		};

		using namespace SMBIOS;
		constexpr struct { SMBIOS::PointingDeviceInterface_t nIndex; const char* szValue; } arrInterfaceType[] =
		{
			{ POINTING_DEVICE_INTERFACE_OTHER, "Other" },
			{ POINTING_DEVICE_INTERFACE_UNKNOWN, "Unknown" },
			{ POINTING_DEVICE_INTERFACE_SERIAL, "Serial" },
			{ POINTING_DEVICE_INTERFACE_PS2, "PS/2" },
			{ POINTING_DEVICE_INTERFACE_INFRARED, "Infrared" },
			{ POINTING_DEVICE_INTERFACE_HP_HIL, "HP-HIL" },
			{ POINTING_DEVICE_INTERFACE_BUS_MOUSE, "Bus Mouse" },
			{ POINTING_DEVICE_INTERFACE_ADB, "ADB (Apple Desktop Bus)" },
			{ POINTING_DEVICE_INTERFACE_BUS_MOUSE_DB9, "Bus Mouse DB-9" },
			{ POINTING_DEVICE_INTERFACE_BUS_MOUSE_MICRO_DIN, "Bus Mouse micro-DIN" },
			{ POINTING_DEVICE_INTERFACE_USB, "USB" },
			{ POINTING_DEVICE_INTERFACE_I2C, "I2C" },
			{ POINTING_DEVICE_INTERFACE_SPI, "SPI" }
		};
		const char* szInterface = "Reserved";
		for (const auto [nIndex, szValue] : arrInterfaceType)
		{
			if (nIndex == pBPD->nInterface)
			{
				szInterface = szValue;
				break;
			}
		}

		std::printf("Type: %s\nInterface: %s\nButtons Count: %u\n", arrType[pBPD->nType - 1U], szInterface, pBPD->nButtonsCount);
		break;
	}
	case SMBIOS::TYPE_PORTABLE_BATTERY:
	{
		const auto pPB = reinterpret_cast<const SMBIOS::PortableBattery_t*>(pStructure->arrData);
		std::printf("Location: %s\nManufacturer: %s\n", arrStringMap[pPB->nLocation], arrStringMap[pPB->nManufacturer]);

		if (pPB->nManufactureDate == Q_SMBIOS_STRING_INVALID)
			std::printf("Manufacture Date: %u.%u.%u\n", pPB->nManufactureDaySBDS, pPB->nManufactureMonthSBDS, pPB->nManufactureYearSBDS);
		else
			std::printf("Manufacture Date: %s\n", arrStringMap[pPB->nManufactureDate]);

		if (pPB->nSerialNumber == Q_SMBIOS_STRING_INVALID)
			std::printf("Serial Number: 0x%04X\n", pPB->uSerialNumberSBDS);
		else
			std::printf("Serial Number: %s\n", arrStringMap[pPB->nSerialNumber]);

		constexpr const char* arrChemistry[] =
		{
			"Other",
			"Unknown",
			"Lead Acid",
			"Nickel Cadmium",
			"Nickel Metal Hydride",
			"Lithium Ion",
			"Zinc Air",
			"Lithium Polymer"
		};

		std::printf("\nDevice Name: %s\nDevice Chemistry: %s\n",
			arrStringMap[pPB->nDeviceName],
			(pPB->nDeviceChemistry == SMBIOS::PORTABLE_BATTERY_CHEMISTRY_UNKNOWN && pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::PortableBattery_t, nDeviceChemistrySBDS)) ?
				arrStringMap[pPB->nDeviceChemistrySBDS] :
				arrChemistry[pPB->nDeviceChemistry - 1U]);

		if (pPB->uDesignCapacity == 0U)
			std::printf("Design Capacity: Unknown\n");
		else
		{
			if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::PortableBattery_t, uDesignCapacityMultiplier))
				std::printf("Design Capacity: %umWh\n", pPB->uDesignCapacity);
			else
				std::printf("Design Capacity: %" PRIu32 "mWh\n", static_cast<std::uint32_t>(pPB->uDesignCapacity) * pPB->uDesignCapacityMultiplier);
		}

		if (pPB->uDesignVoltage == 0U)
			std::printf("Design Voltage: Unknown\n");
		else
			std::printf("Design Voltage: %umV\n", pPB->uDesignVoltage);

		if (const char* szVersionNumber = arrStringMap[pPB->nVersionNumberSBDS]; szVersionNumber != nullptr)
			std::printf("Version Number: %s\n", szVersionNumber);
		else
			std::printf("Version Number: Unknown\n");

		if (pPB->uMaxDataError == 0xFF)
			std::printf("Max Error: Unknown\n");
		else
			std::printf("Max Error: %u%%\n", pPB->uMaxDataError);

		if (pStructure->nLength <= SMB_FIELD_OFFSET(SMBIOS::PortableBattery_t, uOemSpecific))
			break;

		std::printf("OEM Specific: 0x%08X\n", pPB->uOemSpecific);
		break;
	}
	case SMBIOS::TYPE_SYSTEM_RESET:
	{
		const auto pSR = reinterpret_cast<const SMBIOS::SystemReset_t*>(pStructure->arrData);

		static const char* arrBootOption[] =
		{
			"Operating System",
			"System Utilities",
			"Do Not Reboot"
		};
		std::printf("Status: %s\nBoot Option: %s\nBoot Option On Limit: %s\nWatchdog Timer: %s\n",
			pSR->bStatus ? "true" : "false",
			arrBootOption[pSR->nBootOption - 1U],
			arrBootOption[pSR->nBootOptionOnLimit - 1U],
			pSR->bWatchdogTimer ? "true" : "false");

		if (pSR->nResetCount == 0xFFFF)
			std::printf("Reset Count: Unknown\n");
		else
			std::printf("Reset Count: %u\n", pSR->nResetCount);

		if (pSR->nResetLimit == 0xFFFF)
			std::printf("Reset Limit: Unknown\n");
		else
			std::printf("Reset Limit: %u\n", pSR->nResetLimit);

		if (pSR->uTimerInterval == 0xFFFF)
			std::printf("Timer Interval: Unknown\n");
		else
			std::printf("Timer Interval: %um\n", pSR->uTimerInterval);

		if (pSR->uTimeout == 0xFFFF)
			std::printf("Timeout: Unknown\n");
		else
			std::printf("Timeout: %um\n", pSR->uTimeout);

		break;
	}
	case SMBIOS::TYPE_HARDWARE_SECURITY:
	{
		const auto pHS = reinterpret_cast<const SMBIOS::HardwareSecurity_t*>(pStructure->arrData);

		constexpr const char* arrSecurityStatus[] =
		{
			"Disabled",
			"Enabled",
			"Not Implemented",
			"Unknown"
		};
		std::printf("Front Panel Reset Status: %s\nAdministrator Password Status: %s\nKeyboard Password Status: %s\nPower On Password Status: %s\n",
			arrSecurityStatus[pHS->nFrontPanelResetStatus],
			arrSecurityStatus[pHS->nAdministratorPasswordStatus],
			arrSecurityStatus[pHS->nKeyboardPasswordStatus],
			arrSecurityStatus[pHS->nPowerOnPasswordStatus]);
		break;
	}
	case SMBIOS::TYPE_SYSTEM_POWER_CONTROLS:
	{
		const auto pSPC = reinterpret_cast<const SMBIOS::SystemPowerControls_t*>(pStructure->arrData);

		std::printf("Next Scheduled Power-On:");
		if (pSPC->uNextPowerOnMonth >= 0x01 && pSPC->uNextPowerOnMonth <= 0x12)
			std::printf(" %02X", pSPC->uNextPowerOnMonth);
		else
			std::printf(" *");
		if (pSPC->uNextPowerOnDay >= 0x01 && pSPC->uNextPowerOnDay <= 0x31)
			std::printf("-%02X", pSPC->uNextPowerOnDay);
		else
			std::printf("-*");
		if (pSPC->uNextPowerOnHour <= 0x23)
			std::printf(" %02X", pSPC->uNextPowerOnHour);
		else
			std::printf(" *");
		if (pSPC->uNextPowerOnMinute <= 0x59)
			std::printf(":%02X", pSPC->uNextPowerOnMinute);
		else
			std::printf(":*");
		if (pSPC->uNextPowerOnSecond <= 0x59)
			std::printf(":%02X", pSPC->uNextPowerOnSecond);
		else
			std::printf(":*");
		std::printf("\n");
		break;
	}
	case SMBIOS::TYPE_VOLTAGE_PROBE:
	{
		const auto pVP = reinterpret_cast<const SMBIOS::VoltageProbe_t*>(pStructure->arrData);
		std::printf("Description: %s\nLocation: %s\nStatus: %s\n", arrStringMap[pVP->nDescription], arrProbeLocation[pVP->nLocation - 1U], arrStatus[pVP->nStatus - 1U]);

		if (pVP->uMaxValue == 0x8000)
			std::printf("Max Value: Unknown\n");
		else
			std::printf("Max Value: %umV\n", pVP->uMaxValue);

		if (pVP->uMinValue == 0x8000)
			std::printf("Min Value: Unknown\n");
		else
			std::printf("Min Value: %umV\n", pVP->uMinValue);

		if (pVP->uResolution == 0x8000)
			std::printf("Resolution: Unknown\n");
		else
			std::printf("Resolution: %.1fmV\n", static_cast<float>(pVP->uResolution) / 10);

		if (pVP->uTolerance == 0x8000)
			std::printf("Tolerance: Unknown\n");
		else
			std::printf("Tolerance: %.umV\n", pVP->uTolerance);

		if (pVP->uAccuracy == 0x8000)
			std::printf("Accuracy: Unknown\n");
		else
			std::printf("Accuracy: %.2f%%\n", static_cast<float>(pVP->uAccuracy) / 100);

		std::printf("OEM Specific: 0x%08X\n", pVP->uOemDefined);

		if (pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::VoltageProbe_t, uNominalValue))
		{
			if (pVP->uNominalValue == 0x8000)
				std::printf("Nominal Value: Unknown\n");
			else
				std::printf("Nominal Value: %umV\n", pVP->uNominalValue);
		}

		break;
	}
	case SMBIOS::TYPE_COOLING_DEVICE:
	{
		const auto pCD = reinterpret_cast<const SMBIOS::CoolingDevice_t*>(pStructure->arrData);

		using namespace SMBIOS;
		constexpr struct { SMBIOS::CoolingDeviceType_t nIndex; const char* szIndex; } arrTypes[] =
		{
			{ COOLING_DEVICE_OTHER, "Other" },
			{ COOLING_DEVICE_UNKNOWN, "Unknown" },
			{ COOLING_DEVICE_FAN, "Fan" },
			{ COOLING_DEVICE_CENTRIFUGAL_BLOWER, "Centrifugal Blower" },
			{ COOLING_DEVICE_CHIP_FAN, "Chip Fan" },
			{ COOLING_DEVICE_CABINET_FAN, "Cabinet Fan" },
			{ COOLING_DEVICE_POWER_SUPPLY_FAN, "Power Supply Fan" },
			{ COOLING_DEVICE_HEAT_PIPE, "Heat Pipe" },
			{ COOLING_DEVICE_INTEGRATED_REFRIGERATION, "Integrated Refrigeration" },
			{ COOLING_DEVICE_ACTIVE_COOLING, "Active Cooling" },
			{ COOLING_DEVICE_PASSIVE_COOLING, "Passive Cooling" }
		};

		const char* szType = "Reserved";
		for (const auto [nIndex, szValue] : arrTypes)
		{
			if (nIndex == pCD->nType)
			{
				szType = szValue;
				break;
			}
		}

		std::printf("Temperature Probe Handle: 0x%04X\nType: %s\nStatus: %s\n",
			pCD->uTemperatureProbeHandle,
			szType,
			arrStatus[pCD->nStatus - 1U]);

		if (pCD->uCoolingUnitGroup == 0U)
			std::printf("Cooling Unit Group: None\n");
		else
			std::printf("Cooling Unit Group: %u\n", pCD->uCoolingUnitGroup);

		std::printf("OEM Specific: 0x%08X\n", pCD->uOemDefined);

		if (pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::CoolingDevice_t, uNominalSpeed))
		{
			if (pCD->uNominalSpeed == 0x8000)
				std::printf("Nominal Speed: Unknown\n");
			else
				std::printf("Nominal Speed: %uRPM\n", pCD->uNominalSpeed);
		}

		if (pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::CoolingDevice_t, nDescription))
			std::printf("Description: %s\n", arrStringMap[pCD->nDescription]);

		break;
	}
	case SMBIOS::TYPE_TEMPERATURE_PROBE:
	{
		const auto pTP = reinterpret_cast<const SMBIOS::TemperatureProbe_t*>(pStructure->arrData);
		std::printf("Description: %s\nLocation: %s\nStatus: %s\n", arrStringMap[pTP->nDescription], arrProbeLocation[pTP->nLocation - 1U], arrStatus[pTP->nStatus - 1U]);

		if (pTP->uMaxValue == 0x8000)
			std::printf("Max Value: Unknown\n");
		else
			std::printf("Max Value: %.1fC\n", static_cast<float>(pTP->uMaxValue) / 10);

		if (pTP->uMinValue == 0x8000)
			std::printf("Min Value: Unknown\n");
		else
			std::printf("Min Value: %.1fC\n", static_cast<float>(pTP->uMinValue) / 10);

		if (pTP->uResolution == 0x8000)
			std::printf("Resolution: Unknown\n");
		else
			std::printf("Resolution: %.3fC\n", static_cast<float>(pTP->uResolution) / 1000);

		if (pTP->uTolerance == 0x8000)
			std::printf("Tolerance: Unknown\n");
		else
			std::printf("Tolerance: %.1fC\n", static_cast<float>(pTP->uTolerance) / 10);

		if (pTP->uAccuracy == 0x8000)
			std::printf("Accuracy: Unknown\n");
		else
			std::printf("Accuracy: %.2f%%\n", static_cast<float>(pTP->uAccuracy) / 100);

		std::printf("OEM Specific: 0x%08X\n", pTP->uOemDefined);

		if (pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::TemperatureProbe_t, uNominalValue))
		{
			if (pTP->uNominalValue == 0x8000)
				std::printf("Nominal Value: Unknown\n");
			else
				std::printf("Nominal Value: %.1fC\n", static_cast<float>(pTP->uNominalValue) / 10);
		}

		break;
	}
	case SMBIOS::TYPE_ELECTRICAL_CURRENT_PROBE:
	{
		const auto pECP = reinterpret_cast<const SMBIOS::ElectricalCurrentProbe_t*>(pStructure->arrData);
		std::printf("Description: %s\nLocation: %s\nStatus: %s\n", arrStringMap[pECP->nDescription], arrProbeLocation[pECP->nLocation - 1U], arrStatus[pECP->nStatus - 1U]);

		if (pECP->uMaxValue == 0x8000)
			std::printf("Max Value: Unknown\n");
		else
			std::printf("Max Value: %umA\n", pECP->uMaxValue);

		if (pECP->uMinValue == 0x8000)
			std::printf("Min Value: Unknown\n");
		else
			std::printf("Min Value: %umA\n", pECP->uMinValue);

		if (pECP->uResolution == 0x8000)
			std::printf("Resolution: Unknown\n");
		else
			std::printf("Resolution: %umA\n", pECP->uResolution);

		if (pECP->uTolerance == 0x8000)
			std::printf("Tolerance: Unknown\n");
		else
			std::printf("Tolerance: %.1fmA\n", static_cast<float>(pECP->uTolerance) / 10);

		if (pECP->uAccuracy == 0x8000)
			std::printf("Accuracy: Unknown\n");
		else
			std::printf("Accuracy: %.2f%%\n", static_cast<float>(pECP->uAccuracy) / 100);

		std::printf("OEM Specific: 0x%08X\n", pECP->uOemDefined);

		if (pStructure->nLength > SMB_FIELD_OFFSET(SMBIOS::ElectricalCurrentProbe_t, uNominalValue))
		{
			if (pECP->uNominalValue == 0x8000)
				std::printf("Nominal Value: Unknown\n");
			else
				std::printf("Nominal Value: %umA\n", pECP->uNominalValue);
		}

		break;
	}
	case SMBIOS::TYPE_OUTOFBAND_REMOTE_ACCESS:
	{
		const auto pORA = reinterpret_cast<const SMBIOS::OutOfBandRemoteAccess_t*>(pStructure->arrData);
		std::printf("Manufacturer: %s\nInbound Connection: %s\nOutbound Connection: %s\n",
			arrStringMap[pORA->nManufacturer],
			pORA->bInboundConnection ? "true" : "false",
			pORA->bOutboundConnection ? "true" : "false");
		break;
	}
	case SMBIOS::TYPE_BOOT_INTEGRITY_SERVICES_ENTRY_POINT:
	{
		break;
	}
	case SMBIOS::TYPE_SYSTEM_BOOT_INFORMATION:
	{
		const auto pSBI = reinterpret_cast<const SMBIOS::SystemBootInformation_t*>(pStructure->arrData);

		constexpr const char* arrBootStatus[] =
		{
			"No errors detected",
			"No bootable media",
			"Normal operating system failed to load",
			"Firmware-detected hardware failure",
			"Operating system-detected hardware failure",
			"User-requested boot",
			"System security violation",
			"Previously requested image",
			"System watchdog timer expired"
		};
		std::printf("Boot Status: %s\n",
			pSBI->nBootStatus >= 192 ?
				"Product specific" :
				pSBI->nBootStatus >= 128 ?
					"Vendor/OEM specific" :
					pSBI->nBootStatus >= Q_ARRAYSIZE(arrBootStatus) ?
						"Reserved" :
						arrBootStatus[pSBI->nBootStatus]);
		break;
	}
	case SMBIOS::TYPE_MEMORY_64BIT_ERROR_INFORMATION:
	{
		const auto pMEI = reinterpret_cast<const SMBIOS::Memory64ErrorInformation_t*>(pStructure->arrData);
		std::printf("Type: %s\nGranularity: %s\nOperation: %s\n",
			arrMemoryErrorType[pMEI->nType - 1U],
			arrMemoryErrorGranularity[pMEI->nGranularity - 1U],
			arrMemoryErrorOperation[pMEI->nOperation - 1U]);

		if (pMEI->uVendorSyndrome == 0U)
			std::printf("Vendor Syndrome: Unknown\n");
		else
			std::printf("Vendor Syndrome: 0x%08X\n", pMEI->uVendorSyndrome);

		if (pMEI->ullArrayErrorAddress == 0x8000'0000'0000'0000)
			std::printf("Array Error Address: Unknown\n");
		else
			std::printf("Array Error Address: 0x%016" PRIX64 "\n", pMEI->ullArrayErrorAddress);

		if (pMEI->ullDeviceErrorAddress == 0x8000'0000'0000'0000)
			std::printf("Device Error Address: Unknown\n");
		else
			std::printf("Device Error Address: 0x%016" PRIX64 "\n", pMEI->ullDeviceErrorAddress);

		if (pMEI->uResolution == 0x80000000)
			std::printf("Resolution: Unknown\n");
		else
			std::printf("Resolution: 0x%08X\n", pMEI->uResolution);

		break;
	}
	case SMBIOS::TYPE_MANAGEMENT_DEVICE:
	{
		const auto pMD = reinterpret_cast<const SMBIOS::ManagementDevice_t*>(pStructure->arrData);

		constexpr const char* arrType[] =
		{
			"Other",
			"Unknown",
			"National Semiconductor LM75",
			"National Semiconductor LM78",
			"National Semiconductor LM79",
			"National Semiconductor LM80",
			"National Semiconductor LM81",
			"Analog Devices ADM9240",
			"Dallas Semiconductor DS1780",
			"Maxim 1617",
			"Genesys GL518SM",
			"Winbond W83781D",
			"Holtek HT82H791"
		};

		constexpr const char* arrAddressType[] =
		{
			"Other",
			"Unknown",
			"I/O Port",
			"Memory",
			"SMBus"
		};

		std::printf("Description: %s\nType: %s\nAddress: 0x%08X\nAddress Type: %s\n",
			arrStringMap[pMD->nDescription],
			arrType[pMD->nType - 1U],
			pMD->uAddress,
			arrAddressType[pMD->nAddressType - 1U]);
		break;
	}
	case SMBIOS::TYPE_MANAGEMENT_DEVICE_COMPONENT:
	{
		const auto pMDC = reinterpret_cast<const SMBIOS::ManagementDeviceComponent_t*>(pStructure->arrData);
		std::printf("Description: %s\nDevice Handle: 0x%04X\nComponent Handle: 0x%04X\nThreshold Handle: 0x%04X\n",
			arrStringMap[pMDC->nDescription],
			pMDC->uDeviceHandle,
			pMDC->uComponentHandle,
			pMDC->uThresholdHandle);
		break;
	}
	case SMBIOS::TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA:
	{
		const auto pMDTD = reinterpret_cast<const SMBIOS::ManagementDeviceThresholdData_t*>(pStructure->arrData);
		if (pMDTD->uLowerNonCritical != 0x8000)
			std::printf("Lower Non-Critical: %u\n", pMDTD->uLowerNonCritical);
		if (pMDTD->uUpperNonCritical != 0x8000)
			std::printf("Upper Non-Critical: %u\n", pMDTD->uUpperNonCritical);
		if (pMDTD->uLowerCritical != 0x8000)
			std::printf("Lower Critical: %u\n", pMDTD->uLowerCritical);
		if (pMDTD->uUpperCritical != 0x8000)
			std::printf("Upper Critical: %u\n", pMDTD->uUpperCritical);
		if (pMDTD->uLowerNonRecoverable != 0x8000)
			std::printf("Lower Non-Recoverable: %u\n", pMDTD->uLowerNonRecoverable);
		if (pMDTD->uUpperNonRecoverable != 0x8000)
			std::printf("Upper Non-Recoverable: %u\n", pMDTD->uUpperNonRecoverable);
		break;
	}
	case SMBIOS::TYPE_MEMORY_CHANNEL:
	{
		const auto pMC = reinterpret_cast<const SMBIOS::MemoryChannel_t*>(pStructure->arrData);
		
		constexpr const char* arrType[] =
		{
			"Other",
			"Unknown",
			"Rambus",
			"SyncLink",
		};
		std::printf("Type: %s\nMax Load: %u\n", arrType[pMC->nType - 1U], pMC->uMaxLoad);

		for (std::uint8_t i = 1U; i <= pMC->nDeviceCount; ++i)
		{
			const SMBIOS::MemoryChannelDevice_t* pDevice = &pMC->arrDevices[i];
			std::printf("%u. Load: %u\n   Handle: 0x%04X\n", i, pDevice->uLoad, pDevice->uHandle);
		}

		break;
	}
	case SMBIOS::TYPE_IPMI_DEVICE_INFORMATION:
	{
		const auto pIPMI = reinterpret_cast<const SMBIOS::IPMIDeviceInformation_t*>(pStructure->arrData);

		static const char* arrInterfaceType[] =
		{
			"Unknown",
			"KCS (Keyboard Control Style)",
			"SMIC (Server Management Interface Chip)",
			"BT (Block Transfer)",
			"SSIF (SMBus System Interface)"
		};
		std::printf("Interface Type: %s\nSpecification Revision: %d.%d\nI2C Target Address: 0x%02X\n",
			arrInterfaceType[pIPMI->nInterfaceType],
			pIPMI->uSpecificationRevision >> 4U, pIPMI->uSpecificationRevision & 0xF,
			pIPMI->uTargetAddressI2C);

		if (pIPMI->uStorageDeviceAddressNV == 0xFF)
			std::printf("NV Storage Device Address: None\n");
		else
			std::printf("NV Storage Device Address: 0x%02X\n", pIPMI->uStorageDeviceAddressNV);

		if (pIPMI->nInterfaceType == SMBIOS::BMC_INTERFACE_SSIF)
			std::printf("Base Address: 0x%016" PRIX64 " (%s)\n",
				pIPMI->ullBaseAddress,
				pIPMI->bBaseAddressIoSpace ? "I/O Space" : "Memory-Mapped");
		else
		{
			constexpr const char* arrRegisterSpacing[] =
			{
				"Successive Byte Boundaries",
				"32-bit Boundaries",
				"16-byte Boundaries"
			};

			std::printf("Base Address: 0x%016" PRIX64 " (%s)\nRegister Spacing: %s\n",
				(pIPMI->ullBaseAddress << 1ULL) | pIPMI->uBaseAddressLSB,
				pIPMI->bBaseAddressIoSpace ? "I/O Space" : "Memory-Mapped",
				arrRegisterSpacing[pIPMI->nBaseAddressRegisterSpacing]);
		}

		if (pIPMI->bInterruptInfoSpecified)
			std::printf("Interrupt Trigger Mode: %s\nInterrupt Polarity: %s\n",
				pIPMI->nInterruptTriggerMode ? "Level" : "Edge",
				pIPMI->nInterruptPolarity ? "Active High" : "Active Low");

		if (pIPMI->uInterruptNumber == 0U)
			std::printf("Interrupt Number: None\n");
		else
			std::printf("Interrupt Number: %u\n", pIPMI->uInterruptNumber);

		break;
	}
	case SMBIOS::TYPE_SYSTEM_POWER_SUPPLY:
	{
		const auto pSPS = reinterpret_cast<const SMBIOS::SystemPowerSupply_t*>(pStructure->arrData);
		if (pSPS->uPowerUnitGroup == 0U)
			std::printf("Power Unit Group: None\n");
		else
			std::printf("Power Unit Group: %u\n", pSPS->uPowerUnitGroup);

		std::printf("Location: %s\nDevice Name: %s\nManufacturer: %s\nSerial Number: %s\nAsset Tag Number: %s\nModel Part Number: %s\nRevision Level: %s\n",
			arrStringMap[pSPS->nLocation],
			arrStringMap[pSPS->nDeviceName],
			arrStringMap[pSPS->nManufacturer],
			arrStringMap[pSPS->nSerialNumber],
			arrStringMap[pSPS->nAssetTagNumber],
			arrStringMap[pSPS->nModelPartNumber],
			arrStringMap[pSPS->nRevisionLevel]);

		if (pSPS->uMaxPowerCapacity == 0x8000)
			std::printf("Max Power Capacity: Unknown\n");
		else
			std::printf("Max Power Capacity: %dW\n", pSPS->uMaxPowerCapacity / 1000);

		constexpr const char* arrRangeSwitching[] =
		{
			"Other",
			"Unknown",
			"Manual",
			"Auto-Switch",
			"Wide Range",
			"N/A"
		};

		constexpr const char* arrType[] =
		{
			"Other",
			"Unknown",
			"Linear",
			"Switching",
			"Battery",
			"UPS",
			"Converter",
			"Regulator"
		};

		std::printf("Present: %s\nHot Replaceable: %s\nUnplugged: %s\nInput Voltage Range Switching: %s\nStatus: %s\nType: %s\nInput Voltage Probe Handle: 0x%04X\nCooling Device Handle: 0x%04X\nInput Current Probe Handle: 0x%04X\n",
			pSPS->bIsPresent ? "true" : "false",
			pSPS->bHotReplaceable ? "true" : "false",
			pSPS->bUnplugged ? "true" : "false",
			arrRangeSwitching[pSPS->uInputVoltageRangeSwitching - 1U],
			arrStatus[pSPS->nStatus - 1U],
			arrType[pSPS->nType - 1U],
			pSPS->uInputVoltageProbeHandle,
			pSPS->uCoolingDeviceHandle,
			pSPS->uInputCurrentProbeHandle);
		break;
	}
	case SMBIOS::TYPE_ADDITIONAL_INFORMATION:
	{
		const auto pAI = reinterpret_cast<const SMBIOS::AdditionalInformation_t*>(pStructure->arrData);

		const SMBIOS::AdditionalInformationEntry_t* pEntry = &pAI->arrEntries[0];
		for (std::uint8_t i = 0U; i < pAI->nEntriesCount; ++i)
		{
			std::printf("Referenced Handle: 0x%04X\nReferenced Offset: 0x%02X\nString: %s\n",
				pEntry->uReferencedHandle,
				pEntry->uReferencedOffset,
				arrStringMap[pEntry->nString]);
			
			const std::uint8_t* arrValue = reinterpret_cast<const std::uint8_t*>(pEntry) + sizeof(SMBIOS::AdditionalInformationEntry_t);
			const std::uint8_t nValueSize = pEntry->nLength - sizeof(SMBIOS::AdditionalInformationEntry_t);
			std::printf("Value:");
			for (std::uint8_t j = 0U; j < nValueSize; ++j)
				std::printf(" %02X", arrValue[j]);
			std::printf("\n");

			pEntry = reinterpret_cast<const SMBIOS::AdditionalInformationEntry_t*>(reinterpret_cast<const std::uint8_t*>(pEntry) + pEntry->nLength);
		}

		break;
	}
	case SMBIOS::TYPE_ONBOARD_DEVICES_EXTENDED_INFORMATION:
	{
		const auto pODEI = reinterpret_cast<const SMBIOS::OnBoardDevicesExtendedInformation_t*>(pStructure->arrData);
		std::printf("Reference Designation: %s\nType: %s\nEnabled: %s\nType Instance: %u\n",
			arrStringMap[pODEI->nReferenceDesignation],
			arrOnBoardDeviceType[pODEI->nType - 1U],
			pODEI->bEnabled ? "true" : "false",
			pODEI->uTypeInstance);

		if (pODEI->uSegmentGroupNumber != 0xFF && pODEI->uBusNumber != 0xFF && (pODEI->uFunctionNumber | (pODEI->uDeviceNumber << 3U)) != 0xFF)
			std::printf("Group: S:%04X / B:%02X / F:%u / D:%u\n", pODEI->uSegmentGroupNumber, pODEI->uBusNumber, pODEI->uFunctionNumber, pODEI->uDeviceNumber);
		
		break;
	}
	case SMBIOS::TYPE_MANAGEMENT_CONTROLLER_HOST_INTERFACE:
	{
		const auto pMCHI = reinterpret_cast<const SMBIOS::ManagementControllerHostInterface_t*>(pStructure->arrData);
		
		using namespace SMBIOS;
		static struct { SMBIOS::HostInterfaceType_t nIndex; const char* szValue; } arrType[] =
		{
			// MCTP
			{ HOST_INTERFACE_KCS, "Keyboard Controller Style (KCS)" },
			{ HOST_INTERFACE_UART_8250, "8250 UART Register Compatible" },
			{ HOST_INTERFACE_UART_16450, "16450 UART Register Compatible" },
			{ HOST_INTERFACE_UART_16550, "16550/16550A UART Register Compatible" },
			{ HOST_INTERFACE_UART_16650, "16650/16650A UART Register Compatible" },
			{ HOST_INTERFACE_UART_16750, "16750/16750A UART Register Compatible" },
			{ HOST_INTERFACE_UART_16850, "16850/16850A UART Register Compatible" },
			{ HOST_INTERFACE_I2C_SMBUS, "I2C / SMBUS" },
			{ HOST_INTERFACE_I3C, "I3C" },
			{ HOST_INTERFACE_PCIE_VDM, "PCIe VDM" },
			{ HOST_INTERFACE_MMBI, "MMBI" },
			{ HOST_INTERFACE_PPC, "PPC" },
			{ HOST_INTERFACE_UCIE, "UCIe" },
			{ HOST_INTERFACE_USB, "USB" },
			// NETWORK
			{ HOST_INTERFACE_NETWORK, "Network Host Interface" }
		};

		const char* szType = "Reserved";
		for (const auto [nIndex, szValue] : arrType)
		{
			if (nIndex == pMCHI->nType)
			{
				szType = szValue;
				break;
			}
		}

		std::printf("Type: %s\nType Specific Data:", szType);
		for (std::uint8_t i = 0U; i < pMCHI->nTypeSpecificDataLength; ++i)
			std::printf(" %02X", pMCHI->arrTypeSpecificData[i]);
		std::printf("\n");

		constexpr struct { SMBIOS::HostInterfaceProtocolType_t nIndex; const char* szValue; } arrProtocolType[] =
		{
			{ HOST_INTERFACE_PROTOCOL_IPMI, "IPMI" },
			{ HOST_INTERFACE_PROTOCOL_MCTP, "MCTP" },
			{ HOST_INTERFACE_PROTOCOL_REDFISH, "Redfish-over-IP" },
			{ HOST_INTERFACE_PROTOCOL_OEM_DEFINED, "OEM Defined" }
		};

		const std::uint8_t nProtocolRecordCount = *(pMCHI->arrTypeSpecificData + pMCHI->nTypeSpecificDataLength);
		const ProtocolRecordData_t* pProtocolRecord = reinterpret_cast<const ProtocolRecordData_t*>(pMCHI->arrTypeSpecificData + pMCHI->nTypeSpecificDataLength + 1U);
		std::printf("Protocol Records: %u\n", nProtocolRecordCount);
		for (std::uint8_t i = 0U; i < nProtocolRecordCount; ++i)
		{
			const char* szProtocolType = "Reserved";
			for (const auto [nIndex, szValue] : arrProtocolType)
			{
				if (nIndex == pProtocolRecord->nType)
				{
					szProtocolType = szValue;
					break;
				}
			}

			// @todo: we dont parse protocol specific data
			std::printf("%u. Type: %s\n   Type Specific Data:", i + 1U, szProtocolType);
			for (std::uint8_t j = 0U; j < pProtocolRecord->nTypeSpecificDataLength; ++j)
				std::printf(" %02X", pProtocolRecord->arrTypeSpecificData[j]);
			std::printf("\n");

			pProtocolRecord = reinterpret_cast<const ProtocolRecordData_t*>(pProtocolRecord->arrTypeSpecificData + pProtocolRecord->nTypeSpecificDataLength);
		}

		break;
	}
	case SMBIOS::TYPE_TPM_DEVICE:
	{
		const auto pTPM = reinterpret_cast<const SMBIOS::TPMDevice_t*>(pStructure->arrData);
		
		std::printf("Vendor ID: 0x%08X\nVersion: %d.%d\nFirmware Version: 0x%08X%08X\nDescription: %s\n",
			*reinterpret_cast<const std::uint32_t*>(pTPM->arrVendorID),
			pTPM->uVersionMajor,
			pTPM->uVersionMinor,
			pTPM->uFirmwareVersionHigh,
			pTPM->uFirmwareVersionLow,
			arrStringMap[pTPM->nDescription]);

		if (!pTPM->bCharacteristicsNotSupported)
		{
			std::printf("Characteristics:\n");
			if (pTPM->bFamilyConfigurableViaFirmwareUpdate)
				std::printf("\tFamily configurable via firmware update\n");
			if (pTPM->bFamilyConfigurableViaPlatformSoftwareSupport)
				std::printf("\tFamily configurable via platform software support\n");
			if (pTPM->bFamilyConfigurableViaOemProprietaryMechanism)
				std::printf("\tFamily configurable via OEM proprietary mechanism\n");
		}

		std::printf("OEM Specific: 0x%08X\n", pTPM->uOemDefined);
		break;
	}
	case SMBIOS::TYPE_PROCESSOR_ADDITIONAL_INFORMATION:
	{
		const auto pPAI = reinterpret_cast<const SMBIOS::ProcessorAdditionalInformation_t*>(pStructure->arrData);
		std::printf("Referenced Handle: 0x%04X\nSpecific Block:\n", pPAI->uReferencedHandle);

		constexpr const char* arrArchitectureType[] =
		{
			"IA32 (x86)",
			"x64 (x86-64, Intel64, AMD64, EM64T)",
			"Intel Itanium",
			"32-bit ARM (Aarch32)",
			"64-bit ARM (Aarch64)",
			"32-bit RISC-V (RV32)",
			"64-bit RISC-V (RV64)",
			"128-bit RISC-V (RV128)",
			"32-bit LoongArch (LoongArch32)",
			"64-bit LoongArch (LoongArch64)",
		};

		std::uint8_t nProcessorSpecificBlockLength = pStructure->nLength - (sizeof(SMBIOS::StructureHeader_t) + sizeof(SMBIOS::ProcessorAdditionalInformation_t));
		const SMBIOS::ProcessorSpecificBlock_t* pBlock = pPAI->arrBlocks;

		// @test: it's unclear if it's possible there to be multiple blocks, tho i've added support for that if so
		std::uint8_t nIndex = 0U;
		while (nProcessorSpecificBlockLength != 0U)
		{
			std::printf("%u. Architecture Type: %s\n   Specific Data:", ++nIndex, arrArchitectureType[pBlock->nArchitectureType - 1U]);

			// @todo: we dont parse arch specific data
			const std::uint8_t* arrSpecificData = reinterpret_cast<const std::uint8_t*>(pBlock + 1);
			for (std::uint8_t i = 0U; i < pBlock->nDataLength; ++i)
				std::printf(" %02X", arrSpecificData[i]);
			std::printf("\n");

			nProcessorSpecificBlockLength -= sizeof(SMBIOS::ProcessorSpecificBlock_t) + pBlock->nDataLength;
			pBlock = reinterpret_cast<const SMBIOS::ProcessorSpecificBlock_t*>(arrSpecificData + pBlock->nDataLength);
		}

		break;
	}
	case SMBIOS::TYPE_FIRMWARE_INVENTORY_INFORMATION:
	{
		const auto pFII = reinterpret_cast<const SMBIOS::FirmwareInventoryInformation_t*>(pStructure->arrData);

		std::printf("Firmware Component Name: %s\nFirmware Version: %s\nFirmware ID: %s\nRelease Date: %s\nManufacturer: %s\nLowest Supported Firmware Version: %s\n",
			arrStringMap[pFII->nFirmwareComponentName],
			arrStringMap[pFII->nFirmwareVersion],
			arrStringMap[pFII->nFirmwareID],
			arrStringMap[pFII->nReleaseDate],
			arrStringMap[pFII->nManufacturer],
			arrStringMap[pFII->nLowestSupportedFirmwareVersion]);

		if (pFII->ullImageSize == ~0ULL)
			std::printf("Image Size: Unknown\n");
		else
			std::printf("Image Size: %" PRIu64 "%s\n",
				pFII->ullImageSize >= 0x100'000 ? (pFII->ullImageSize / 0x100'000) : (pFII->ullImageSize >= 0x400 ? (pFII->ullImageSize / 0x400) : pFII->ullImageSize),
				arrSizeUnit[pFII->ullImageSize >= 0x10'0000 ? 2 : (pFII->ullImageSize >= 0x400 ? 1 : 0)]);

		if (pFII->uCharacteristics == 0ULL)
			std::printf("Characteristics: None\n");
		else
		{
			std::printf("Characteristics:\n");
			if (pFII->bUpdateable)
				std::printf("\tUpdateable\n");
			if (pFII->bWriteProtect)
				std::printf("\tWrite-Protect\n");
		}

		constexpr const char* arrState[] =
		{
			"Other",
			"Unknown",
			"Disabled",
			"Enabled",
			"Absent",
			"Standby Offline",
			"Standby Spare",
			"Unavailable Offline",
		};

		std::printf("State: %s\nAssociated Components: %u\n", arrState[pFII->nState - 1U], pFII->nAssociatedComponentCount);
		for (std::uint8_t i = 0U; i < pFII->nAssociatedComponentCount; ++i)
			std::printf("%u. Handle: 0x%04X\n", i + 1U, pFII->arrAssociatedComponentHandles[i]);

		break;
	}
	case SMBIOS::TYPE_STRING_PROPERTY:
	{
		const auto pSP = reinterpret_cast<const SMBIOS::StringProperty_t*>(pStructure->arrData);
		std::printf("ID: %s\nValue: %s\nParent Handle: 0x%04X\n", pSP->uIdentifier == 1U ? "UEFI Device Path" : "Reserved", arrStringMap[pSP->nValue], pSP->uParentHandle);
		break;
	}
	default:
		break;
	}
}

int main()
{
	std::uint32_t uVersion = 0U;
	std::uint32_t nLength = 0U;
	SMBIOS::StructureHeader_t* pFirstStructure = nullptr;

#if defined(Q_OS_WINDOWS)
	const std::uint32_t nSmBiosDataSize = ::GetSystemFirmwareTable('RSMB', 0UL, nullptr, 0UL);
	if (nSmBiosDataSize == 0U)
		return EXIT_FAILURE;

	std::uint8_t* pSmBiosData = new std::uint8_t[nSmBiosDataSize];
	if (::GetSystemFirmwareTable('RSMB', 0UL, pSmBiosData, nSmBiosDataSize) == 0UL)
		return EXIT_FAILURE;

	const auto pRawSmBiosData = reinterpret_cast<RawSMBIOSData_t*>(pSmBiosData);
	// store the SMBIOS version
	uVersion = (pRawSmBiosData->SMBIOSMajorVersion << 16U) | (pRawSmBiosData->SMBIOSMinorVersion << 8U) | pRawSmBiosData->DmiRevision;
	// store the structure table length
	nLength = pRawSmBiosData->Length;
	// store the structure table address
	pFirstStructure = reinterpret_cast<SMBIOS::StructureHeader_t*>(pRawSmBiosData->SMBIOSTableData);
#elif defined(Q_OS_LINUX)
	struct stat info;

	// get the SMBIOS structures size
	constexpr const char* szTableFilePath = "/sys/firmware/dmi/tables/DMI";
	if (::stat(szTableFilePath, &info) != 0)
	{
		std::printf("[error] failed to get info about structure tables: %s\n", szTableFilePath);
		return EXIT_FAILURE;
	}
	
	// read SMBIOS structure table
	FILE* hFile = ::fopen(szTableFilePath, "rb");
	if (hFile == nullptr)
	{
		std::printf("[error] failed to open structure tables: %s\n", szTableFilePath);
		return EXIT_FAILURE;
	}

	std::uint8_t* pSmBiosData = new std::uint8_t[info.st_size];
	::fread(reinterpret_cast<char*>(pSmBiosData), static_cast<std::size_t>(info.st_size), 1U, hFile);
	::fclose(hFile);

	// read SMBIOS entry point
	constexpr const char* szEntryPointFilePath = "/sys/firmware/dmi/tables/smbios_entry_point";
	if (::stat(szEntryPointFilePath, &info) != 0)
	{
		std::printf("[error] failed to get info about entry point: %s\n", szEntryPointFilePath);
		return EXIT_FAILURE;
	}

	hFile = ::fopen(szEntryPointFilePath, "rb");
	if (hFile == nullptr)
	{
		std::printf("[error] failed to open entry point: %s\n", szEntryPointFilePath);
		return EXIT_FAILURE;
	}

	std::uint8_t* pSmBiosEntryPoint = new std::uint8_t[info.st_size];
	::fread(reinterpret_cast<char*>(pSmBiosEntryPoint), static_cast<std::size_t>(info.st_size), 1U, hFile);
	::fclose(hFile);

	// check for 2.X version magic
	if (::memcmp(pSmBiosEntryPoint, "_SM_", 4U) == 0)
	{
		const std::uint8_t nEntryPointLength = pSmBiosEntryPoint[0x5];
		if (nEntryPointLength != 0x1F) // @test: also 0x1E
		{
			std::printf("[error] unexpected entry point length: 0x%02X\n", nEntryPointLength);
			return EXIT_FAILURE;
		}

		const std::uint8_t* pIntermediateAnchorString = &pSmBiosEntryPoint[0x10];
		if (::memcmp(pIntermediateAnchorString, "_DMI_", 5U) != 0)
		{
			std::printf("[error] unknown entry point intermediate anchor string\n");
			return EXIT_FAILURE;
		}

		// store the SMBIOS version
		uVersion = (pSmBiosEntryPoint[0x6] << 16U) | (pSmBiosEntryPoint[0x7] << 8U);
		// store the structure table length
		nLength = pSmBiosEntryPoint[0x16] | (pSmBiosEntryPoint[0x17] << 8U);
		// store the structure table address
		pFirstStructure = reinterpret_cast<SMBIOS::StructureHeader_t*>(pSmBiosData);
	}
	// otherwise check for 3.X version magic
	else if (::memcmp(pSmBiosEntryPoint, "_SM3_", 5U) == 0)
	{
		const std::uint8_t nEntryPointLength = pSmBiosEntryPoint[0x6];
		if (nEntryPointLength != 0x18)
		{
			std::printf("[error] unexpected entry point length: 0x%02X\n", nEntryPointLength);
			return EXIT_FAILURE;
		}

		const std::uint8_t uEntryPointRevision = pSmBiosEntryPoint[0xA];
		if (uEntryPointRevision != 0x1)
		{
			std::printf("[error] unexpected entry point revision: 0x%02X\n", uEntryPointRevision);
			return EXIT_FAILURE;
		}

		// store the SMBIOS version
		uVersion = (pSmBiosEntryPoint[0x7] << 16U) | (pSmBiosEntryPoint[0x8] << 8U) | pSmBiosEntryPoint[0x9];
		// store the structure table length
		nLength = pSmBiosEntryPoint[0xC] | (pSmBiosEntryPoint[0xD] << 8U) | (pSmBiosEntryPoint[0xE] << 16U) | (pSmBiosEntryPoint[0xF] << 24U);
		// store the structure table address
		pFirstStructure = reinterpret_cast<SMBIOS::StructureHeader_t*>(pSmBiosData);
	}
	else
	{
		std::printf("[error] unknown entry point\n");
		return EXIT_FAILURE;
	}

	delete[] pSmBiosEntryPoint;
#else
#error "target platform is not supported!"
#endif

	// output the current version
	std::printf("SMBIOS - %u.%u.%u\n", (uVersion & 0xFF0000) >> 16U, (uVersion & 0x00FF00) >> 8U, (uVersion & 0x0000FF));

	// strings of the current structure
	const char* arrStringMap[256];
	// count of the strings present in the current structure
	std::size_t nStringCount;
	const SMBIOS::StructureHeader_t* pNextStructure = pFirstStructure;
	do
	{
		const SMBIOS::StructureHeader_t* pCurrentStructure = pNextStructure;

		// advance to the next structure
		pNextStructure = SMBIOS::ReadStructure(pCurrentStructure, arrStringMap, &nStringCount);

		// process the current structure
		HandleStructure(pCurrentStructure, arrStringMap, uVersion);
	} while (pNextStructure != nullptr);

	delete[] pSmBiosData;
	return EXIT_SUCCESS;
}
