cmake_minimum_required(VERSION 3.0)

# Define the project and library
project(allium C)
add_library(allium allium.c)

# Link LibTomCrypt
if (NOT $ENV{SKIP_CRYPT})
	find_library(tomcrypt tomcrypt)
	if(tomcrypt)
		message(STATUS "Found LibTomCrypt")
		add_compile_definitions("FOUND_CRYPT")
		target_link_libraries(allium "${tomcrypt}")
	else()
		message(NOTICE "LibTomCrypt not found, hash generation will be unavailable")
	endif()
endif()
