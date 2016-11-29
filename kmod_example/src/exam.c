#include <linux/init.h>
#include <linux/module.h>

static int __init hello_init(void)
{
    printk("I bear a charmed life.\n");
    return 0;
}

static void __exit hello_exit(void)
{
    printk("Out, out, brief candle\n");
}
module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
