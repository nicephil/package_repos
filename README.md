# Add new module
must select it in menuconfig before compile it
1. ./scripts/feeds uninstall -a
2. ./scripts/feeds update -a
3. ./scripts/feeds install -a
4. cp .defconfig .config
5. make menuconfig and select it
6. make package/app_example/compile V=s
7. commit .config and .defconfig, in order to add it as default

# Module Descripts
* app_example
An application example
* kmod_example
A kernel module example
* capwapc_sim
A capwap simulator
* capwapc
main capwap client on AP
* libcfg
main config management library
* libok_util
oakridge's util APIs, e.g. list
* libif
interface library
* libnmsc
nmsc json parser
* libservices
each services implementation

