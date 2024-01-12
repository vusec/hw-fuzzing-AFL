#include <set>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
namespace fs = std::filesystem;

static std::set<std::string> readLines(std::string path) {
  std::set<std::string> result;
  std::ifstream         input(path);
  for (std::string line; std::getline(input, line);) {
    while (!line.empty() && line.back() == '\n')
      line.pop_back();
    if (line.empty()) continue;
    result.insert(line);
  }
  return result;
}

static std::string extractCause(std::string filename) {
  std::string result;
  for (char c : filename) {
    // Once we reach a % sign, we found the random suffix.
    if (c == '%') break;
    if (c == '_') result.push_back(' ');
    result.push_back(c);
  }
  return result;
}

static std::set<std::string> getFoundBugs(std::string outDir) {
  const std::string causesDir = outDir + "/../causes";

  std::set<std::string> result;
  for (const auto &entry : fs::directory_iterator(outDir)) {
    if (!entry.is_regular_file()) continue;

    std::string filename = entry.path().filename();
    std::string cause = extractCause(filename);
    if (cause.empty()) continue;
    result.insert(cause);
  }
  return result;
}

extern "C" {
// Stops all fuzzing processes if we found all the bugs we needed for the eval.
void checkIfAllBugsFound(const char *outDirCstr) {
  const std::string outDir = outDirCstr;
  const std::string expectedListVar = "FUZZING_EXPECTED_LIST";

  const char *expectedPath = std::getenv(expectedListVar.c_str());
  if (expectedPath == nullptr) {
    std::cerr << expectedListVar << " not set, exiting";
    abort();
  }

  const std::set<std::string> expected = readLines(expectedPath);
  const std::set<std::string> found = getFoundBugs(outDir);
  for (std::string bug : expected) {
    // Check if we found the expected bug. If not, return as we are not
    // done yet with fuzzing.
    if (found.count(bug) == 0) return;
  }

  std::cerr << "Found all bugs, exiting...\n";
  std::exit(0);
}
}