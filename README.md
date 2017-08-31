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
* capwapc
main capwap client on AP
* libnmsc
nmsc json parser
* libservices
each services implementation

