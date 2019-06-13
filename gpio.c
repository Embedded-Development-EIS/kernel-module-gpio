/*
 * AXI GPIO v2.0 - Linux driver
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>    		/* Needed for copy_from_user */
#include <asm/io.h>         		/* Needed for IO Read/Write Functions */
#include <linux/proc_fs.h> 		/* Needed for Proc File System Functions */
#include <linux/seq_file.h> 		/* Needed for Sequence File Operations */
#include <linux/platform_device.h>  	/* Needed for Platform Driver Functions */
#include <asm/uaccess.h>

#include <linux/ctype.h>
#include <linux/fs.h>         
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/fcntl.h>

#define KERNEL_MODULE
#include "iodef.hpp"
#include "deviceid.hpp"

/* Define Driver Name */
#define DRIVER_NAME "gpio"

#define SUCCESS     0


static unsigned long *   base_addr   = NULL;
static struct resource * res         = NULL;
static unsigned long     remap_size  = 0;
static DeviceID          device_ID   = 0;
static u32               output_data = 0;

static int major;       /* major number we get from the kernel */

static void outport(u32 data, u32 offset)
{
    static u32 current_data = 0;

    if (current_data != data)
    {
        wmb();
        iowrite32(data, base_addr + offset);
        current_data = data;
    }
}

static u32 inport(u32 offset)
{
    wmb();
    return ioread32(base_addr + offset);
}

#define SET_SLICE_32(register, value, offset, mask) (register) = (((register) & ~((mask) << (offset))) | (((value) & (mask)) << (offset)))
#define GET_SLICE_32(register, offset, mask) (((register) & ((mask) << (offset))) >> (offset))

/* Write operation for /proc/driver
* -----------------------------------
*/
static ssize_t proc_driver_write(struct file *file,
                                 const char __user * buffer,
                                 size_t buffer_size,
                                 loff_t * position)
{
    ssize_t written_size = 0;

    if (buffer != NULL)
    {
        if (buffer_size == sizeof(device_ID))
        {
            written_size = buffer_size - copy_from_user((void *) &device_ID, buffer, sizeof(device_ID));
        }
        else if (buffer_size == sizeof(IOPacket))
        {
            IOPacket packet;
            written_size = buffer_size - copy_from_user((void *) &packet, buffer, sizeof(IOPacket));

            if (written_size == buffer_size )
            {
                device_ID = packet.device_ID;
                switch (packet.device_ID)
                {
                   	case DRAIN_LOCAL_GND_IN:
                       		break;
                   	case DRAIN_CMD_28V_IN:
                       		break;
                    	case FLV_IND_OP:
                        	break;
                    	case FLV_IND_CL:
                        	break;
                    	case PINPGM:
                        	break;
                   	case WT_28V_IN:
                       		break;
                   	case SW_SOV:
                       		break;
                    	case IR_ANA_INPUT:
                        	break;
                    	case SOV_IND_CL:
                        	break;
                    	case SOV_IND_OP:
                        	break;
                    	case SW_ID:
                        	break;
                	case DRAIN_LOCAL_28V_IN:
                		break;
                	case DRAIN_CMD_GND_IN:
                		break;
			case WT_GND_IN:
				break;
                    	case FLV_ALT_IND_CL:
                        	break;
                    	case FLV_ALT_IND_OP:
                        	break;
                   	case LED3:
                        	SET_SLICE_32(output_data, packet.data, 0, 0x1);
				break;
                    	case LED4:
                        	SET_SLICE_32(output_data, packet.data, 1, 0x1);
				break;
                    	case LED5:
                        	SET_SLICE_32(output_data, packet.data, 2, 0x1);
				break;
                    	case LED6:
                        	SET_SLICE_32(output_data, packet.data, 3, 0x1);
				break;
                   	case VG_28V_OUT:
                        	SET_SLICE_32(output_data, packet.data, 4, 0x1);
                        	break;
                   	case VG_GND_OUT:
                        	SET_SLICE_32(output_data, packet.data, 5, 0x1);
                        	break;
                    	case FLV_ALT_DRV_CL:
                        	SET_SLICE_32(output_data, packet.data, 6, 0x1);
                        	break;
                    	case FLV_ALT_DRV_OP:
                        	SET_SLICE_32(output_data, packet.data, 7, 0x1);
                        	break;
                    	case FLV_NRESET:
                        	SET_SLICE_32(output_data, packet.data, 8, 0x1);
				break;
                    	case FLV_DECAY:
                        	SET_SLICE_32(output_data, packet.data, 9, 0x1);
				break;
                    	case FLV_NSLEEP:
                        	SET_SLICE_32(output_data, packet.data, 10, 0x1);
				break;
                    	case FLV_DIR:
                        	SET_SLICE_32(output_data, packet.data, 11, 0x1);
				break;
                    	case EN_28VV:
                        	SET_SLICE_32(output_data, packet.data, 12, 0x1);
				break;
                    	case FLV_ENABLE:
                        	SET_SLICE_32(output_data, packet.data, 13, 0x1);
				break;
                    	case RGB_PWR_RED:
                        	SET_SLICE_32(output_data, packet.data, 14, 0x1);
                        	break;
                    	case RGB_PWR_GREEN:
                        	SET_SLICE_32(output_data, packet.data, 15, 0x1);
                        	break;
                    	case RGB_PWR_BLUE:
                        	SET_SLICE_32(output_data, packet.data, 16, 0x1);
                        	break;
                    	case RGB_SW_RED:
                        	SET_SLICE_32(output_data, packet.data, 17, 0x1);
                        	break;
                    	case RGB_SW_GREEN:
                        	SET_SLICE_32(output_data, packet.data, 18, 0x1);
                        	break;
                    	case RGB_SW_BLUE:
                        	SET_SLICE_32(output_data, packet.data, 19, 0x1);
                        	break;
                    	case SOV_DRV_CL:
                        	SET_SLICE_32(output_data, packet.data, 20, 0x1);
                        	break;
                    	case SOV_DRV_OP:
                        	SET_SLICE_32(output_data, packet.data, 21, 0x1);
                        	break;
                    	case LEA1_28V_DOUT:
                        	SET_SLICE_32(output_data, packet.data, 22, 0x1);
                        	break;
                    	case LEA2_28V_DOUT:
                        	SET_SLICE_32(output_data, packet.data, 23, 0x1);
                        	break;
                    	case LEA1_GND_OUT:
                        	SET_SLICE_32(output_data, packet.data, 24, 0x1);
                        	break;
                    	case LEA2_GND_OUT:
                        	SET_SLICE_32(output_data, packet.data, 25, 0x1);
                        	break;
                    	case OPERATION_FAIL_GND_OUT:
                        	SET_SLICE_32(output_data, packet.data, 26, 0x1);
                        	break;
                    	case SOV_CL_GND_OUT:
                        	SET_SLICE_32(output_data, packet.data, 27, 0x1);
                        	break;
                    	case LVL_FAIL_GND_OUT:
                        	SET_SLICE_32(output_data, packet.data, 28, 0x1);
                        	break;
                    	case EN_485:
                        	SET_SLICE_32(output_data, packet.data, 29, 0x1);
                        	break;
                    	case FLV_I:
                        	SET_SLICE_32(output_data, packet.data, 30, 0x1);
                        	break;

                    	default:;
                }
                outport(output_data, 2);
                * position += written_size;
            }
        }
    }
    return written_size;
}

/* Read operation for /proc/driver
* -----------------------------------
*/
static ssize_t proc_driver_read(struct file *file,
                                 char __user * buffer,
                                 size_t buffer_size,
                                 loff_t * position)
{
    ssize_t read_size = 0;

    if ((buffer != NULL) && (sizeof(IOPacket) <= buffer_size))
    {
        IOPacket packet;
        u32 input_data = inport(0);
        packet.device_ID = device_ID;

        switch (device_ID)
        {
                case DRAIN_LOCAL_GND_IN:
                	packet.data = GET_SLICE_32(input_data, 0, 1);
                	break;
                case DRAIN_CMD_28V_IN:
                	packet.data = GET_SLICE_32(input_data, 1, 1);
                	break;
                case DRAIN_LOCAL_28V_IN:
                	packet.data = GET_SLICE_32(input_data, 2, 1);
                	break;
                case DRAIN_CMD_GND_IN:
                	packet.data = GET_SLICE_32(input_data, 3, 1);
                	break;
                case PINPGM:
                	packet.data = GET_SLICE_32(input_data, 4, 0xFF);
                	break;
                case SW_ID:
                	packet.data = GET_SLICE_32(input_data, 12, 0x3);
                	break;
                case FLV_IND_OP:
                	packet.data = GET_SLICE_32(input_data, 14, 1);
                	break;
                case FLV_IND_CL:
                	packet.data = GET_SLICE_32(input_data, 15, 1);
                	break;
                case WT_28V_IN:
                	packet.data = GET_SLICE_32(input_data, 16, 1);
                	break;
		case WT_GND_IN:
                	packet.data = GET_SLICE_32(input_data, 17, 1);
			break;
                case SW_SOV:
                	packet.data = GET_SLICE_32(input_data, 18, 0x3);
                	break;
                case IR_ANA_INPUT:
                	packet.data = GET_SLICE_32(input_data, 20, 1);
                	break;
                case SOV_IND_CL:
                	packet.data = GET_SLICE_32(input_data, 21, 1);
                	break;
                case SOV_IND_OP:
                	packet.data = GET_SLICE_32(input_data, 22, 1);
                	break;
                case FLV_ALT_IND_CL:
			packet.data = GET_SLICE_32(input_data, 23, 1);
                       	break;
               	case FLV_ALT_IND_OP:
			packet.data = GET_SLICE_32(input_data, 24, 1);
                       	break;
            	default:;
        }
        read_size = buffer_size - copy_to_user(buffer, (void *) &packet, sizeof(IOPacket));
    }
    return read_size;
}


/* Callback function when opening file /proc/driver
* ------------------------------------------------------
*  Read the register value of driver file controller, print the value to
*  the sequence file struct seq_file *p. In file open operation for /proc/driver
*  this callback function will be called first to fill up the seq_file,
*  and seq_read function will print whatever in seq_file to the terminal.
*/
static int proc_driver_show(struct seq_file *p, void *v)
{
    seq_printf(p, "\nController kernel module\n");
    return SUCCESS;
}

/* Open function for /proc/driver
* ------------------------------------
*  When user want to read /proc/driver (i.e. cat /proc/driver), the open function 
*  will be called first. In the open function, a seq_file will be prepared and the 
*  status of driver will be filled into the seq_file by proc_driver_show function.
*/
static int driver_open(struct inode *inode, struct file *file)
{
    unsigned int size = 16;
    char * buf;
    struct seq_file * m;
    int rc = SUCCESS;

    buf = (char *)kmalloc(size * sizeof(char), GFP_KERNEL);
    if (buf != NULL)
    {
        rc = single_open(file, proc_driver_show, NULL);

        if (rc == SUCCESS)
        {
            m = file->private_data;
            m->buf = buf;
            m->size = size;
        }
        else
        {
            kfree(buf);
        }
    }
    else
    {
        printk(KERN_ALERT DRIVER_NAME "%s No memory resource\n", __FUNCTION__);
        rc = -ENOMEM;
    }

    return rc;
}

/* File Operations for /proc/driver */
static const struct file_operations proc_driver_operations =
{
    .open           = driver_open,
    .write          = proc_driver_write,
    .read           = proc_driver_read,
    .llseek         = seq_lseek,
    .release        = single_release
};

/* Shutdown function for driver
* -----------------------------------
*  Before driver shutdown, turn-off all the stuff
*/
static void driver_shutdown(struct platform_device *pdev)
{
	output_data = 0;
    	outport(output_data, 2);
}

/* Remove function for driver
* ----------------------------------
*  When driver module is removed, turn off all the stuff first,
*  release virtual address and the memory region requested.
*/
static int driver_remove(struct platform_device *pdev)
{
    driver_shutdown(pdev);

    /* Remove /proc/driver entry */
    remove_proc_entry(DRIVER_NAME, NULL);

    unregister_chrdev(major, DRIVER_NAME);

    /* Release mapped virtual address */
    iounmap(base_addr);

    /* Release the region */
    release_mem_region(res->start, remap_size);

    return SUCCESS;
}

/* Device Probe function for driver
* ------------------------------------
*  Get the resource structure from the information in device tree.
*  request the memory regioon needed for the controller, and map it into
*  kernel virtual memory space. Create an entry under /proc file system
*  and register file operations for that entry.
*/
static int driver_probe(struct platform_device *pdev)
{
    struct proc_dir_entry * driver_proc_entry;
    int rc = SUCCESS;

    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if (!res)
    {
        dev_err(&pdev->dev, "No memory resource\n");
        rc = -ENODEV;
    }

    if (rc == SUCCESS)
    {
        remap_size = res->end - res->start + 1;
        if (!request_mem_region(res->start, remap_size, pdev->name))
        {
            dev_err(&pdev->dev, "Cannot request IO\n");
            rc = -ENXIO;
        }
    }

    if (rc == SUCCESS)
    {
        base_addr = ioremap(res->start, remap_size);
        if (base_addr == NULL)
        {
            dev_err(&pdev->dev, "Couldn't ioremap memory at 0x%08lx\n", (unsigned long)res->start);
            release_mem_region(res->start, remap_size);
            rc = -ENOMEM;
        }
    }

    if (rc == SUCCESS)
    {
        driver_proc_entry = proc_create(DRIVER_NAME, 0, NULL, &proc_driver_operations);
        if (driver_proc_entry == NULL)
        {
            dev_err(&pdev->dev, "Couldn't create proc entry\n");
            iounmap(base_addr);
            release_mem_region(res->start, remap_size);
            rc = -ENOMEM;
        }
    }

    if (rc == SUCCESS)
    {
        printk(KERN_INFO DRIVER_NAME " Mapped at virtual address 0x%08lx\n", (unsigned long) base_addr);

        major = register_chrdev(0, DRIVER_NAME, &proc_driver_operations);

	output_data = 0;
    	outport(output_data, 2);

    }

    return rc;
}

/* device match table to match with device node in device tree */
static const struct of_device_id zynq_pmod_match[] =
{
    {.compatible = "ccc-gpio_mod-1.00.a"},
    { },
};

MODULE_DEVICE_TABLE(of, zynq_pmod_match);

/* platform driver structure for device driver */
static struct platform_driver zynq_pmod_driver =
{
    .driver =
    {
        .name = DRIVER_NAME,
        .owner = THIS_MODULE,
        .of_match_table = zynq_pmod_match
    },
    .probe = driver_probe,
    .remove = driver_remove,
    .shutdown = driver_shutdown
};

/* Register device platform driver */
module_platform_driver(zynq_pmod_driver);

/* Module Informations */
MODULE_AUTHOR("E.I.S.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRIVER_NAME ": GPIO module");
MODULE_ALIAS(DRIVER_NAME);
