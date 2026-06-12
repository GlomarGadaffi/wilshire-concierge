# GloSSH example project (ESP-IDF)
#
# Builds the `main` example, which brings up the TinySSH server component.
# Dropbear ships as an alternate SSH backend (both define ssh_task(); only the
# component listed in main's REQUIRES is linked). To use Dropbear instead, add
# "dropbear" to COMPONENTS below and swap the REQUIRES in main/CMakeLists.txt.
cmake_minimum_required(VERSION 3.16)

set(COMPONENTS "main" "tinyssh" "esptool_py")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(glossh-example)
