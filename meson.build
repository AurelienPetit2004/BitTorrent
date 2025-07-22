project(
  'bittorent',
  'c',
  meson_version : '>= 1.1.0',
  version : '1.1.0',
  default_options : [
    'c_args=-D_GNU_SOURCE',
    'c_std=c99',
    'debug=true',
    'optimization=0',
    'warning_level=2',
    'werror=true',
    'b_sanitize=address,undefined',
  ],
)

subdir('libs/mbtutils/')
subdir('libs/mbtbe/')
subdir('libs/mbtfile')
subdir('libs/mbtnet')

exp = executable(
  'mbt',
  sources : [ 'src/main.c' ],
  include_directories : [ include_directories('src') ],
  dependencies : [ mbtutils_dep, mbtbe_dep, mbtfile_dep, mbtnet_dep ],
)
