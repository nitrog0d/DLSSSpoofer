// This is VERY based on MelonLoader Proxy (more like 99% copypasted), thank you LavaGang.
// https://github.com/LavaGang/MelonLoader/blob/master/Proxy

#include "Core.h"
#include "../Exports/Exports.h"
#include "../Detours/detours.h"
#include <vector>
#include <iostream>

typedef struct {
	unsigned long version;
	unsigned long architecture;
	unsigned long implementation;
	unsigned long revision;
} NV_GPU_ARCH_INFO;

typedef HMODULE(WINAPI* LoadLibraryExW_t)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef void* (WINAPI* nvapi_QueryInterface_t)(unsigned long function);
typedef int(WINAPI* NvAPI_GPU_GetArchInfo_t)(int hPhysicalGpu, NV_GPU_ARCH_INFO* pGpuArchInfo);
typedef int(WINAPI* NvAPI_Initialize_t)();
typedef int(WINAPI* NvAPI_EnumPhysicalGPUs_t)(int nvGPUHandle[64], unsigned long* pGpuCount);
typedef int(WINAPI* NvAPI_SYS_GetDriverAndBranchVersion_t)(unsigned long* pDriverVersion, char szBuildBranchString[64]);
typedef int(WINAPI* NvAPI_EnumLogicalGPUs_t)(int nvGPUHandle[64], unsigned long* pGpuCount);

static GetProcAddress_t OriginalGetProcAddress = GetProcAddress;
static LoadLibraryExW_t OriginalLoadLibraryExW = LoadLibraryExW;
static nvapi_QueryInterface_t OriginalNvAPI_QueryInterface;
static NvAPI_GPU_GetArchInfo_t OriginalNvAPI_GPU_GetArchInfo;

bool HookedNvAPI = false;
bool HookedGetArchInfo = false;

int DetourNvAPI_GPU_GetArchInfo(int hPhysicalGpu, NV_GPU_ARCH_INFO* pGpuArchInfo) {
	auto result = OriginalNvAPI_GPU_GetArchInfo(hPhysicalGpu, pGpuArchInfo);
	pGpuArchInfo->architecture = 0x160;
	OutputDebugStringA("[DLSSSpoofer] Spoofed architecture to 0x160");
	return result;
}

void* DetourNvAPI_QueryInterface(unsigned long function) {
	auto result = OriginalNvAPI_QueryInterface(function);
	if (function == 0xD8265D24UL && !HookedGetArchInfo) {
		HookedGetArchInfo = true;

		OriginalNvAPI_GPU_GetArchInfo = (NvAPI_GPU_GetArchInfo_t)result;

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)OriginalNvAPI_GPU_GetArchInfo, DetourNvAPI_GPU_GetArchInfo);
		DetourTransactionCommit();
	}
	return result;
}

HMODULE WINAPI DetourLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	auto result = OriginalLoadLibraryExW(lpLibFileName, hFile, dwFlags);
	if (wcscmp(lpLibFileName, L"nvapi64.dll") == 0) {
		if (!result) {
			return (HMODULE)0x1337;
		}
		else {
			if (!HookedNvAPI) {
				HookedNvAPI = true;
				OriginalNvAPI_QueryInterface = (nvapi_QueryInterface_t)GetProcAddress(result, "nvapi_QueryInterface");

				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach(&(PVOID&)OriginalNvAPI_QueryInterface, DetourNvAPI_QueryInterface);
				DetourTransactionCommit();
			}
		}
	}
	return result;
}

int NvAPI_Initialize() {
	OutputDebugStringA("[DLSSSpoofer] Called NvAPI_Initialize");
	return 0;
}

int NvAPI_EnumPhysicalGPUs(int nvGPUHandle[64], unsigned long* pGpuCount) {
	OutputDebugStringA("[DLSSSpoofer] Called NvAPI_EnumPhysicalGPUs");
	*pGpuCount = 1;
	nvGPUHandle[0] = 0x1337;
	return 0;
}

int NvAPI_SYS_GetDriverAndBranchVersion(unsigned long* pDriverVersion, char szBuildBranchString[64]) {
	OutputDebugStringA("[DLSSSpoofer] Called NvAPI_SYS_GetDriverAndBranchVersion");
	*pDriverVersion = 51748;
	return 0;
}

int NvAPI_GPU_GetArchInfo(int hPhysicalGpu, NV_GPU_ARCH_INFO* pGpuArchInfo) {
	OutputDebugStringA("[DLSSSpoofer] Called NvAPI_GPU_GetArchInfo");
	pGpuArchInfo->architecture = 0x160;
	return 0;
}

int NvAPI_EnumLogicalGPUs(int nvGPUHandle[64], unsigned long* pGpuCount) {
	OutputDebugStringA("[DLSSSpoofer] Called NvAPI_EnumLogicalGPUs");
	*pGpuCount = 0;
	return 0;
}

void* Fake_NvAPI_QueryInterface(unsigned long function) {
	// Calls in order:
	// 0xAD298D3FUL - NvAPI_InitializeEx
	// NvAPI_Initialize
	// NvAPI_CallStart
	// NvAPI_CallReturn
	// NvAPI_EnumPhysicalGPUs
	// NvAPI_SYS_GetDriverAndBranchVersion
	// NvAPI_GPU_GetArchInfo
	
	switch (function) {
	case 0x150E828UL: // NvAPI_Initialize
		return (NvAPI_Initialize_t)NvAPI_Initialize;
	case 0xE5AC921FUL: // NvAPI_EnumPhysicalGPUs
		return (NvAPI_EnumPhysicalGPUs_t)NvAPI_EnumPhysicalGPUs;
	case 0x2926AAADUL: // NvAPI_SYS_GetDriverAndBranchVersion
		return (NvAPI_SYS_GetDriverAndBranchVersion_t)NvAPI_SYS_GetDriverAndBranchVersion;
	case 0xD8265D24UL: // NvAPI_GPU_GetArchInfo
		return (NvAPI_GPU_GetArchInfo_t)NvAPI_GPU_GetArchInfo;
	case 0x48B3EA59UL: // NvAPI_EnumLogicalGPUs
		return (NvAPI_EnumLogicalGPUs_t)NvAPI_EnumLogicalGPUs;
	/*case 0xAD298D3FUL: // ??? called before NvAPI_Initialize, might be NvAPI_InitializeEx
		OutputDebugStringA(std::string("[DLSSSpoofer] Handler for 0x" + std::format("{:X}", function) + " not implemented").c_str());
		return nullptr;
	case 0x33C7358CUL: // NvAPI_CallStart
		OutputDebugStringA(std::string("[DLSSSpoofer] Handler for NvAPI_CallStart implemented").c_str());
		return nullptr;
	case 0x593E8644UL: // NvAPI_CallReturn
		OutputDebugStringA(std::string("[DLSSSpoofer] Handler for NvAPI_CallReturn implemented").c_str());
		return nullptr;
	case 0x26322BC3UL: // NvAPI_D3D12_QueryCpuVisibleVidmem
		OutputDebugStringA(std::string("[DLSSSpoofer] Handler for NvAPI_D3D12_QueryCpuVisibleVidmem implemented").c_str());
		return nullptr;
	case 0xD7C61344UL: // ??? Inside NvAPI_Unload, might be NvApi_UnloadEx
		OutputDebugStringA(std::string("[DLSSSpoofer] Handler for 0x" + std::format("{:X}", function) + " not implemented").c_str());
		return nullptr;
	case 0xD22BDD7EUL: // NvAPI_Unload
		OutputDebugStringA(std::string("[DLSSSpoofer] Handler for NvAPI_Unload implemented").c_str());
		return nullptr;*/
	default:
		OutputDebugStringA(std::string("[DLSSSpoofer] Handler for 0x" + std::format("{:X}", function) + " not found").c_str());
		return nullptr;
	}
}

static nvapi_QueryInterface_t FakeNvAPI_QueryInterface = Fake_NvAPI_QueryInterface;

FARPROC WINAPI DetourGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	if (hModule == (HMODULE)0x1337) {
		OutputDebugStringA("[DLSSSpoofer] DetourGetProcAddress called with fake module");
		if (strcmp(lpProcName, "nvapi_QueryInterface") == 0) {
			OutputDebugStringA("[DLSSSpoofer] nvapi_QueryInterface called");
			return (FARPROC)FakeNvAPI_QueryInterface;
		}
	}
	return OriginalGetProcAddress(hModule, lpProcName);
}

void Core::Initialize(HINSTANCE hModule) {
	// Get execution path
	std::vector<char> pathBuf;
	DWORD copied = 0;
	do {
		pathBuf.resize(pathBuf.size() + MAX_PATH);
		copied = GetModuleFileNameA(nullptr, pathBuf.data(), static_cast<DWORD>(pathBuf.size()));
	} while (copied >= pathBuf.size());

	pathBuf.resize(copied);

	const std::filesystem::path filepath(pathBuf.begin(), pathBuf.end());

	// Get file path of proxy, tolowercase the file name
	const auto proxyFilepath = GetModuleFilePath(hModule);
	auto ProxyFilename = proxyFilepath.filename().wstring();
	std::transform(ProxyFilename.begin(), ProxyFilename.end(), ProxyFilename.begin(), towlower);

	// Make proxy name list
	std::wstring names;
	bool _1 = true;
	for (auto name : Exports::CompatibleFileNames) {
		if (_1) {
			_1 = false;
			names += name;
		}
		else {
			names += L", ";
			names += name;
		}
	}

	// Check if is compatible proxy
	std::size_t index = -1;
	if (!Exports::IsFileNameCompatible(ProxyFilename, &index)) {
		Error(L"Proxy has an incompatible file name!\nValid names are: " + names + L"\n", true);
		return;
	}

	// Load original libs
	const HMODULE originalDll = LoadOriginalProxy(proxyFilepath, proxyFilepath.filename().stem().wstring());
	if (!originalDll) {
		Error(L"Failed to Load original " + proxyFilepath.wstring() + L"!", true);
		return;
	}

	// Load original lib exports
	Exports::Load(index, originalDll);

	if (strstr(GetCommandLineA(), "--no-dlssspoofer") != nullptr)
		return;

	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OriginalLoadLibraryExW, DetourLoadLibraryExW);
	DetourAttach(&(PVOID&)OriginalGetProcAddress, DetourGetProcAddress);
	DetourTransactionCommit();
}

HMODULE Core::LoadOriginalProxy(const std::filesystem::path& proxyFilepath, const std::wstring& proxyFilepathNoExt) {
	HMODULE originalDll = LoadLibraryW((proxyFilepathNoExt + L"_original.dll").c_str());

	if (!originalDll) {
		wchar_t system32_path[MAX_PATH];

		if (GetSystemDirectoryW(system32_path, MAX_PATH) == NULL) {
			Error("Failed to get System32 directory!");
			Core::KillProcess();
			return nullptr;
		}

		const auto path = std::filesystem::path(system32_path);
		originalDll = LoadLibraryW((path / proxyFilepath.filename()).c_str());
	}

	return originalDll;
}

std::filesystem::path Core::GetModuleFilePath(HMODULE moduleHandle) {
	wchar_t path[MAX_PATH];
	GetModuleFileNameW(moduleHandle, path, MAX_PATH);
	return path;
}

void Core::Error(const std::string& reason, const bool shouldKill) {
	MessageBoxA(nullptr, (reason + " " + (shouldKill ? "Preventing Startup" : "Continuing without DLSSSpoofer") + "...").c_str(), "DLSSSpoofer", MB_ICONERROR | MB_OK);
	if (shouldKill) Core::KillProcess();
}

void Core::Error(const std::wstring& reason, const bool shouldKill) {
	MessageBoxW(nullptr, (reason + L" " + (shouldKill ? L"Preventing Startup" : L"Continuing without DLSSSpoofer") + L"...").c_str(), L"DLSSSpoofer", MB_ICONERROR | MB_OK);
	if (shouldKill) KillProcess();
}

void Core::KillProcess() {
	const HANDLE current_process = GetCurrentProcess();
	TerminateProcess(current_process, NULL);
	CloseHandle(current_process);
}