# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug

# Include any dependencies generated for this target.
include test/CMakeFiles/test_execve.dir/depend.make

# Include the progress variables for this target.
include test/CMakeFiles/test_execve.dir/progress.make

# Include the compile flags for this target's objects.
include test/CMakeFiles/test_execve.dir/flags.make

test/CMakeFiles/test_execve.dir/test_execve.o: test/CMakeFiles/test_execve.dir/flags.make
test/CMakeFiles/test_execve.dir/test_execve.o: ../test/test_execve.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object test/CMakeFiles/test_execve.dir/test_execve.o"
	cd /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/test && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_execve.dir/test_execve.o -c /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/test/test_execve.cpp

test/CMakeFiles/test_execve.dir/test_execve.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_execve.dir/test_execve.i"
	cd /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/test/test_execve.cpp > CMakeFiles/test_execve.dir/test_execve.i

test/CMakeFiles/test_execve.dir/test_execve.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_execve.dir/test_execve.s"
	cd /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/test/test_execve.cpp -o CMakeFiles/test_execve.dir/test_execve.s

test/CMakeFiles/test_execve.dir/test_execve.o.requires:

.PHONY : test/CMakeFiles/test_execve.dir/test_execve.o.requires

test/CMakeFiles/test_execve.dir/test_execve.o.provides: test/CMakeFiles/test_execve.dir/test_execve.o.requires
	$(MAKE) -f test/CMakeFiles/test_execve.dir/build.make test/CMakeFiles/test_execve.dir/test_execve.o.provides.build
.PHONY : test/CMakeFiles/test_execve.dir/test_execve.o.provides

test/CMakeFiles/test_execve.dir/test_execve.o.provides.build: test/CMakeFiles/test_execve.dir/test_execve.o


# Object files for target test_execve
test_execve_OBJECTS = \
"CMakeFiles/test_execve.dir/test_execve.o"

# External object files for target test_execve
test_execve_EXTERNAL_OBJECTS =

test/test_execve: test/CMakeFiles/test_execve.dir/test_execve.o
test/test_execve: test/CMakeFiles/test_execve.dir/build.make
test/test_execve: test/CMakeFiles/test_execve.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_execve"
	cd /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_execve.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
test/CMakeFiles/test_execve.dir/build: test/test_execve

.PHONY : test/CMakeFiles/test_execve.dir/build

test/CMakeFiles/test_execve.dir/requires: test/CMakeFiles/test_execve.dir/test_execve.o.requires

.PHONY : test/CMakeFiles/test_execve.dir/requires

test/CMakeFiles/test_execve.dir/clean:
	cd /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/test && $(CMAKE_COMMAND) -P CMakeFiles/test_execve.dir/cmake_clean.cmake
.PHONY : test/CMakeFiles/test_execve.dir/clean

test/CMakeFiles/test_execve.dir/depend:
	cd /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/test /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/test /home/alex/CLionProjects/black-box-fuzzers/libfuzzer-fuzz-subprocess/cmake-build-debug/test/CMakeFiles/test_execve.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : test/CMakeFiles/test_execve.dir/depend
