cmake_minimum_required(VERSION 3.0)

# Define the project and library
project(allium C)
add_library(allium allium.c)

# Link LibTomCrypt
target_link_libraries(allium tomcrypt)
