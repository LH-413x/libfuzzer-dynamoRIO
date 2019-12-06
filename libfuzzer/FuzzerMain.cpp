//===- FuzzerMain.cpp - main() function and flags -------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// main() and flags.
//===----------------------------------------------------------------------===//

#include "FuzzerDefs.h"
#include <iostream>

ATTRIBUTE_INTERFACE int main(int argc, char **argv) {
  if(argc<2){
    std::cout << "usage: fuzzer shell_command ..." << std::endl;
    return 0;
  }
  char* shell_command=argv[1];
  argv[1]=argv[0];
  argc=argc-1;
  argv=argv+1;
  return fuzzer::FuzzerDriver(&argc, &argv, shell_command);
}
