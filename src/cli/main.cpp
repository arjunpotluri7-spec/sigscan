#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "cli.hpp"

int main(int argc, char** argv) {
  std::vector<std::string> args;
  const std::span<char*> raw(argv, static_cast<std::size_t>(argc));
  for (std::size_t i = 1; i < raw.size(); ++i) {
    args.emplace_back(raw[i]);
  }
  return sigscan::cli::run(args, std::cout, std::cerr);
}
