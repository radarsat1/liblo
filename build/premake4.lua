----------------------------------------------------------------------
-- Premake4 configuration script for LibLo
-- Adapted from ODE's build script by Jason Perkins.
-- For more information on Premake: http://industriousone.com/premake
----------------------------------------------------------------------

----------------------------------------------------------------------
-- Configuration options
----------------------------------------------------------------------

  -- always clean all of the optional components and toolsets
  if _ACTION == "clean" then
    for action in pairs(premake.actions) do
      os.rmdir(action)
    end
  end
  
  

----------------------------------------------------------------------
-- The solution, and solution-wide settings
----------------------------------------------------------------------

  solution "liblo"

    language "C"
    location ( _OPTIONS["to"] or _ACTION )

    newoption {
        trigger     = "without-threads",
        description = "Disable lo_server_thread functions, no need for pthread."
}

    newoption {
        trigger     = "pthreads",
	description = "Specify the location of the pthreads-w32 library."
    }

    includedirs {
      "../lo",
      "../src"
    }
      
    -- define all the possible build configurations
    configurations {
      "DebugDLL", "ReleaseDLL", 
      "DebugLib", "ReleaseLib", 
    }
    
    configuration { "Debug*" }
      defines { "_DEBUG" }
      flags   { "Symbols" }
      
    configuration { "Release*" }
      flags   { "OptimizeSpeed", "NoFramePointer" }

    configuration { "Windows" }
      defines { "WIN32" }

    -- give each configuration a unique output directory
    for _, name in ipairs(configurations()) do
      configuration { name }
        targetdir ( "../lib/" .. name )
    end
      
    -- disable Visual Studio security warnings
    configuration { "vs*" }
      defines { "_CRT_SECURE_NO_DEPRECATE" }

    -- tell source to use config.h
    configuration { "vs*" }
      defines { "HAVE_CONFIG_H" }

    -- don't remember why we had to do this	(from ODE)
    configuration { "vs2002 or vs2003", "*Lib" }
      flags  { "StaticRuntime" }

----------------------------------------------------------------------
-- Write a custom <config.h> to .., based on the supplied flags
----------------------------------------------------------------------

-- First get the version number from "configure.ac" --

  io.input("../configure.ac")
  text = io.read("*all")
  io.close()

  version = string.match(text, "AC_INIT%(%[liblo%],%[(%d+%.%d+%w+)%]")

  ltcurrent = string.match(text, "m4_define%(%[lt_current%], (%d+)")
  ltrev = string.match(text, "m4_define%(%[lt_revision%], (%d+)")
  ltage = string.match(text, "m4_define%(%[lt_age%], (%d+)")

  ltversion = '{' .. ltcurrent .. ', ' .. ltrev .. ', ' .. ltage .. '}'

-- Replace it in "config.h" --

  io.input("config-msvc.h")
  local text = io.read("*all")

  text = string.gsub(text, '/%*VERSION%*/', '"'..version..'"')

  if _OPTIONS["without-threads"] then
    text = string.gsub(text, '@DEFTHREADS@', '// ')
  else
    text = string.gsub(text, '@DEFTHREADS@', '')
  end

  text = string.gsub(text, '@LO_SO_VERSION@', ltversion)

  io.output("../config.h")
  io.write(text)
  io.close()

----------------------------------------------------------------------
-- Write a custom <liblo.def> to ../src/
----------------------------------------------------------------------

  io.input("../src/liblo.def.in")
  local text = io.read("*all")

  if _OPTIONS["without-threads"] then
    text = string.gsub(text, '@DEFTHREADS@', ';;')
  else
    text = string.gsub(text, '@DEFTHREADS@', '')
  end

  text = string.gsub(text, ' @DLL_NAME@', '')

  io.output("../src/liblo.def")
  io.write(text)
  io.close()

----------------------------------------------------------------------
-- Write a custom <lo.h> to ../lo/
----------------------------------------------------------------------

  io.input("../lo/lo.h.in")
  local text = io.read("*all")

  if _OPTIONS["without-threads"] then
    text = string.gsub(text, '@ENABLE_THREADS@', '0')
  else
    text = string.gsub(text, '@ENABLE_THREADS@', '1')
  end

  io.output("../lo/lo.h")
  io.write(text)
  io.close()

----------------------------------------------------------------------
-- Copy <lo_endian.h> to ../lo
----------------------------------------------------------------------

  io.input("lo_endian-msvc.h")
  io.output("../lo/lo_endian.h")
  local text = io.read("*all")
  io.write(text)
  io.close()

----------------------------------------------------------------------
-- The LibLo library project
----------------------------------------------------------------------

  project "liblo"

    kind     "StaticLib"
    location ( _OPTIONS["to"] or _ACTION )

    includedirs {
      "..",
    }

    files {
      "../src/*.c",
      "../src/*.h",
      "../lo/*.h",
      "../src/liblo.def",
    }

    excludes {
      "../src/testlo.c",
      "../src/subtest.c",
      "../src/test_bidirectional_tcp.c",
      "../src/tools",
    }

    configuration { "windows" }
      links   { "user32",
                "wsock32",
                "ws2_32",
                "iphlpapi",
              }

    configuration { "without-threads" }
      excludes { "../src/server_thread.c" }

    configuration { "not without-threads" }
      links { "pthreadVC2" }
      if (_OPTIONS["pthreads"]) then
        includedirs { _OPTIONS["pthreads"] }
      end

    configuration { "*Lib" }
      kind    "StaticLib"
      defines "LIBLO_LIB"
      
    configuration { "*DLL" }
      kind    "SharedLib"
      defines "LIBLO_DLL"

    configuration { "Debug*" }
      targetname "liblo_d"
      
    configuration { "Release*" }
      targetname "liblo"


----------------------------------------------------------------------
-- The automated test application
----------------------------------------------------------------------


  project "testlo"
  
    kind     "ConsoleApp"
    location ( _OPTIONS["to"] or _ACTION )
    links   { "user32",
              "wsock32",
              "ws2_32",
              "iphlpapi",
              "pthreadVC2",
            }

    includedirs { 
      "..",
    }
    
    files { 
      "../src/testlo.c",
    }

    configuration { "DebugDLL" }
      links { "liblo_d" }
      libdirs { "../lib/debugdll" }

    configuration { "DebugLib" }
      links { "liblo_d" }
      libdirs { "../lib/debuglib" }
      
    configuration { "Release*" }
      links { "liblo" }

    configuration { "not without-threads" }
      links { "pthreadVC2" }
      if (_OPTIONS["pthreads"]) then
        includedirs { _OPTIONS["pthreads"] }
      end

  project "subtest"
  
    kind     "ConsoleApp"
    location ( _OPTIONS["to"] or _ACTION )
    links   { "user32",
              "wsock32",
              "ws2_32",
              "iphlpapi",
              "pthreadVC2",
            }

    includedirs { 
      "..",
    }

    files { 
      "../src/subtest.c",
    }

    configuration { "DebugDLL" }
      links { "liblo_d" }
      libdirs { "../lib/debugdll" }

    configuration { "DebugLib" }
      links { "liblo_d" }
      libdirs { "../lib/debuglib" }
      
    configuration { "Release*" }
      links { "liblo" }
