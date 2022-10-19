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
typedef void* (WINAPI* nvapi_QueryInterface_t)(unsigned int function);
typedef int(WINAPI* NvAPI_GPU_GetArchInfo_t)(int hPhysicalGpu, NV_GPU_ARCH_INFO* pGpuArchInfo);

static LoadLibraryExW_t OriginalLoadLibraryExW = LoadLibraryExW;
static nvapi_QueryInterface_t OriginalNvAPI_QueryInterface;
static NvAPI_GPU_GetArchInfo_t OriginalNvAPI_GPU_GetArchInfo;

bool HookedNvAPI = false;
bool HookedGetArchInfo = false;

int DetourNvAPI_GPU_GetArchInfo(int hPhysicalGpu, NV_GPU_ARCH_INFO* pGpuArchInfo) {
	auto result = OriginalNvAPI_GPU_GetArchInfo(hPhysicalGpu, pGpuArchInfo);
	pGpuArchInfo->architecture = 0x160;
	OutputDebugStringA("[ArchSpoofer] Spoofed architecture to 0x160");
	return result;
}

void* DetourNvAPI_QueryInterface(unsigned int function) {
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
		if (!HookedNvAPI) {
			HookedNvAPI = true;
			OriginalNvAPI_QueryInterface = (nvapi_QueryInterface_t)GetProcAddress(result, "nvapi_QueryInterface");

			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)OriginalNvAPI_QueryInterface, DetourNvAPI_QueryInterface);
			DetourTransactionCommit();
		}
	}
	return result;
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

	if (strstr(GetCommandLineA(), "--no-archspoofer") != nullptr)
		return;

	// Do our detour code now
	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OriginalLoadLibraryExW, DetourLoadLibraryExW);
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
	MessageBoxA(nullptr, (reason + " " + (shouldKill ? "Preventing Startup" : "Continuing without ArchSpoofer") + "...").c_str(), "ArchSpoofer", MB_ICONERROR | MB_OK);
	if (shouldKill) Core::KillProcess();
}

void Core::Error(const std::wstring& reason, const bool shouldKill) {
	MessageBoxW(nullptr, (reason + L" " + (shouldKill ? L"Preventing Startup" : L"Continuing without ArchSpoofer") + L"...").c_str(), L"ArchSpoofer", MB_ICONERROR | MB_OK);
	if (shouldKill) KillProcess();
}

void Core::KillProcess() {
	const HANDLE current_process = GetCurrentProcess();
	TerminateProcess(current_process, NULL);
	CloseHandle(current_process);
}