//
// Created by alex on 2019/11/25.
//
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/wait.h>
int main() {
  if(fork()==0){
    char* argv[6]= {"/home/alex/tools/fuzzer/dynamorio/7.1.0-1-build/bin64/drrun",
                    "-c",
                    "/home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/dynamoRIO/libdrtrace.so",
                    "--",
                    "/home/alex/workstation/compare-fuzzers/test",
                    nullptr
    };
    execve(argv[0],argv,NULL);
    perror("");
  }
  wait(nullptr);
}
