file(REMOVE_RECURSE
  "../../../../lib/libevmone-standalone.a"
  "../../../../lib/libevmone-standalone.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/evmone-standalone.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
