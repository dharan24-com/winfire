#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>

constexpr std::uint32_t kPocContextMagic = 0x46545043;
constexpr std::size_t kPocArgumentsLength = 2048;
constexpr std::size_t kPocTaskNameLength = 512;
constexpr std::size_t kPocAumidLength = 512;
constexpr std::size_t kPocPackageNameLength = 256;
constexpr std::size_t kPocImagePathLength = 1024;
constexpr std::size_t kPocCommandLineLength = 4096;

struct TokenSnapshot {
  DWORD pid;
  DWORD integrity_rid;
  BOOL is_restricted;
  BOOL is_app_container;
  BOOL is_in_job;
  BOOL is_elevated;
  wchar_t package_family[kPocPackageNameLength];
  wchar_t package_full_name[kPocPackageNameLength];
  wchar_t image_path[kPocImagePathLength];
  wchar_t command_line[kPocCommandLineLength];
};

struct LaunchContext {
  std::uint32_t magic;
  wchar_t launch_arguments[kPocArgumentsLength];
  wchar_t shell_execute_arguments[kPocArgumentsLength];
  wchar_t shell_dispatch_arguments[kPocArgumentsLength];
  wchar_t notification_profile[kPocArgumentsLength];
  wchar_t background_task_name[kPocTaskNameLength];
  wchar_t application_user_model_id[kPocAumidLength];
  LONG call_hresult;
  LONG extended_error;
  std::int32_t launch_result;
  LONG activation_hresult;
  DWORD activation_pid;
  DWORD shell_execute_error;
  DWORD shell_execute_pid;
  BOOL shell_execute_succeeded;
  LONG shell_dispatch_hresult;
  LONG notification_activation_hresult;
  DWORD parent_pid;
  DWORD parent_injection_open_error;
  BOOL parent_injection_access;
  DWORD sibling_injection_pid;
  DWORD sibling_injection_open_error;
  BOOL sibling_injection_access;
  LONG background_register_hresult;
  BOOL background_registered;
  TokenSnapshot caller;
};
