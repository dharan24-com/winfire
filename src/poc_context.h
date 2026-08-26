#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>

constexpr std::uint32_t kPocContextMagic = 0x46545043;
constexpr std::size_t kPocArgumentsLength = 2048;
constexpr std::size_t kPocTaskNameLength = 512;
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
  wchar_t background_task_name[kPocTaskNameLength];
  LONG call_hresult;
  LONG extended_error;
  std::int32_t launch_result;
  LONG background_register_hresult;
  BOOL background_registered;
  TokenSnapshot caller;
};
