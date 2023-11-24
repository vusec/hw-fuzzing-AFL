#pragma once

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/CFG.h"

#include <cassert>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <random>

namespace {
enum class CoverageMode {
#define COVERAGE_MODE(VAL) VAL,
#include "CoverageModes.def"
};

// C++ still has no string splitting...
static std::vector<std::string> split(std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back (token);
    }

    res.push_back (s.substr (pos_start));
    return res;
}

static bool isModeOn(CoverageMode mode) {
  // Those two modes should not be used. Just set by the user to disable half
  // of the existing coverage points.
  assert(mode != CoverageMode::Half1);
  assert(mode != CoverageMode::Half2);

  std::string envVarName = "HWFUZZ_COVERAGE";
  const char *baseline_string = std::getenv(envVarName.c_str());
  if (baseline_string == nullptr) {
    llvm::errs() << envVarName << " is not set!O\n";
    abort();
  }
  // Map from env var parts to specific modes.
  const std::map<std::string, CoverageMode> modeMap = {
#define COVERAGE_MODE(VAL) {#VAL, CoverageMode:: VAL },
#include "CoverageModes.def"
  };

  // Split the env var value into different modes.
  std::string value = baseline_string;
  std::vector<std::string> valueParts = split(value, ",");
  std::set<CoverageMode> enabledModes;

  // Map each mode string to an enum value.
  for (const std::string &modeStr : valueParts) {
    if (modeMap.count(modeStr) == 0) {
      llvm::errs() << modeStr << " is not valid mode string!\n";
      llvm::errs() << "Valid values are:\n";
      for (auto &pair : modeMap)
        llvm::errs() << " * " << pair.first << "\n";
      abort();
    }
    enabledModes.insert(modeMap.at(modeStr));
  }

  static std::mt19937 gen(123);
  // A distribution that flips a coin and returns 0 or 1.
  // This is used to disable a random subset of the instrumentation for the
  // Half1/Half2 modes.
  std::uniform_int_distribution<> flipCoin(0, 1);

  bool enabled = enabledModes.count(mode) != 0;
  // If the mode is enabled, then the special mode that disabled half the
  // coverage might still overwrite that.
  if (enabled) {
    // First half is disabled for whenever our coin flip is a 0.
    if (enabledModes.count(CoverageMode::Half1)) {
      if (flipCoin(gen) == 0)
        return false;
    }
    // Second half is disabled for whenever our coin flip is a 1.
    if (enabledModes.count(CoverageMode::Half2)) {
      if (flipCoin(gen) == 1)
        return false;
    }
  }

  return enabled;
}
}