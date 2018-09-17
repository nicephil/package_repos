from setuptools import setup, Extension

extension = Extension(
    'ubus',
    ['/home/llwang/repos/x86/osdk_repos/build_dir/target-i386_pentium4_musl-1.1.16/ubus-2017-02-18-34c6e818/python/ubus_python.c'],
    libraries=['ubus', 'blobmsg_json', 'ubox'],
    include_dirs=['/home/llwang/repos/x86/osdk_repos/build_dir/target-i386_pentium4_musl-1.1.16/ubus-2017-02-18-34c6e818'],
    library_dirs=['/home/llwang/repos/x86/osdk_repos/build_dir/target-i386_pentium4_musl-1.1.16/ubus-2017-02-18-34c6e818'],
)

setup(
    name='ubus',
    version='2017-02-18-34c6e818',
    description="Python bindings for libubus",
    ext_modules=[extension],
    provides=['ubus'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
)
