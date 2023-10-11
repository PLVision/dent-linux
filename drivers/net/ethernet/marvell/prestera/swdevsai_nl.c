/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/completion.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_fw.h"

#define	SWDEVSAI_VER_MAJOR	4
#define SWDEVSAI_VER_MINOR	0
#define SWDEVSAI_VER_SUB	1

#define SWDEVSAI_VER \
(SWDEVSAI_VER_MAJOR*1000000+SWDEVSAI_VER_MINOR*1000+SWDEVSAI_VER_SUB)

#define SADEVSAI_NL_SYNC_TIMEOUT	500000
#define SADEVSAI_NL_MCGRP_NAME		"swdevsai_grp_nl"
#define SADEVSAI_NL_MCGRP_ID		0
#define SADEVSAI_NL_NAME		"swdevsai_nl"
#define SADEVSAI_NL_VERSION		0x1

#define LOG_INFO(fmt, ...) \
	pr_info("%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
	pr_err("%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

enum {
	SADEVSAI_NL_TYPE_NEW_MSG,
	SADEVSAI_NL_TYPE_DRV_INIT,
	SADEVSAI_NL_TYPE_REPLY,
	SADEVSAI_NL_TYPE_EVENT,

	SADEVSAI_NL_TYPE_MAX,
};

enum {
	SADEVSAI_NL_ATTR_UNSPEC,
	SADEVSAI_NL_ATTR_DRV_INIT_ACK,
	SADEVSAI_NL_ATTR_TLV,

	__SADEVSAI_NL_ATTR_MAX,
	SADEVSAI_NL_ATTR_MAX = __SADEVSAI_NL_ATTR_MAX - 1
};

struct swdevsai_nl_event {
	struct work_struct work;
	struct prestera_device *dev;
	size_t len;
	char data[];
};

struct swdevsai_nl_device {
	struct prestera_fw *fw;
	bool is_registered;
};

static DEFINE_MUTEX(swdevsai_nl_send_mtx);
static DECLARE_COMPLETION(swdevsai_nl_reply_completion);
static struct pci_dev *g_pdev;
static struct prestera_device *sw_dev;
static struct workqueue_struct *swdevsai_nl_owq;
static struct work_struct swdevsai_nl_dev_register_work;

static struct {
	u8 buf[PRESTERA_MSG_MAX_SIZE];
	int size;
	int err;
} reply_msg;

static const struct genl_multicast_group swdevsai_genl_mcgrps[] = {
	[SADEVSAI_NL_MCGRP_ID] = {.name = SADEVSAI_NL_MCGRP_NAME}
};

static const struct nla_policy swdevsai_nl_policy[__SADEVSAI_NL_ATTR_MAX] = {
	[SADEVSAI_NL_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
	[SADEVSAI_NL_ATTR_TLV] = {.type = NLA_UNSPEC},
};

static int swdevsai_nl_handle_drv_init(struct sk_buff *skb, struct genl_info *info);
static int swdevsai_nl_handle_reply(struct sk_buff *skb, struct genl_info *info);
static int swdevsai_nl_handle_event(struct sk_buff *skb, struct genl_info *info);

static const struct genl_ops swdevsai_genl_ops[] = {
	{
	 .cmd = SADEVSAI_NL_TYPE_DRV_INIT,
	 .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	 .doit = swdevsai_nl_handle_drv_init},
	{
	 .cmd = SADEVSAI_NL_TYPE_REPLY,
	 .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	 .doit = swdevsai_nl_handle_reply},
	{
	 .cmd = SADEVSAI_NL_TYPE_EVENT,
	 .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	 .doit = swdevsai_nl_handle_event},
};

static struct genl_family swdevsai_genl_family = {
	.name = SADEVSAI_NL_NAME,
	.version = SADEVSAI_NL_VERSION,
	.maxattr = SADEVSAI_NL_ATTR_MAX,
	.module = THIS_MODULE,
	.ops = swdevsai_genl_ops,
	.n_ops = ARRAY_SIZE(swdevsai_genl_ops),
	.netnsok = true,
	.mcgrps = swdevsai_genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(swdevsai_genl_mcgrps),
	.policy = swdevsai_nl_policy,
};

static int swdevsai_nl_handle_reply(struct sk_buff *skb, struct genl_info *info)
{
	size_t size;

	if (!info->attrs[SADEVSAI_NL_ATTR_TLV]) {
		LOG_ERROR("Unknown netlink attribute received");
		reply_msg.err = -EINVAL;
		goto handler_reply_unlock;
	}

	size = nla_len(info->attrs[SADEVSAI_NL_ATTR_TLV]);
	if (size >= PRESTERA_MSG_MAX_SIZE) {
		LOG_ERROR("Netlink buffer overflow");
		reply_msg.err = -EMSGSIZE;
		goto handler_reply_unlock;
	}

	nla_memcpy(reply_msg.buf, info->attrs[SADEVSAI_NL_ATTR_TLV], size);
	reply_msg.size = size;
	reply_msg.err = 0;

handler_reply_unlock:
	complete(&swdevsai_nl_reply_completion);
	return 0;
}

static int swdevsai_nl_get_reply(unsigned int timeout, u8 *msg, size_t size,
			     size_t *recv_bytes)
{
	int err = 0;

	err = wait_for_completion_timeout(&swdevsai_nl_reply_completion,
					  usecs_to_jiffies(timeout));
	if (!err) {
		LOG_ERROR("No reply netlink message");
		return err;
	}

	if (reply_msg.size > size) {
		LOG_ERROR("Netlink messaeg overflow");
		return -EMSGSIZE;
	}

	memcpy(msg, reply_msg.buf, reply_msg.size);
	*recv_bytes = reply_msg.size;
	err = reply_msg.err;

	return err;
}

static int swdevsai_nl_send_sync(unsigned int wait, u8 *in_msg, size_t in_size,
			     u8 *out_msg, size_t out_size)
{
	size_t out_data_size;
	int err = 0;
	struct sk_buff *nl_msg;
	void *hdr;

	if (!wait)
		wait = SADEVSAI_NL_SYNC_TIMEOUT;

	nl_msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!nl_msg) {
		LOG_ERROR("nlmsg_new() error");
		return -ENOMEM;
	}

	hdr = genlmsg_put(nl_msg, 0, 0, &swdevsai_genl_family, 0,
			  SADEVSAI_NL_TYPE_NEW_MSG);
	if (!hdr) {
		LOG_ERROR("genlmsg_put() error");
		err = -EMSGSIZE;
		goto nl_send_err;
	}

	err = nla_put(nl_msg, SADEVSAI_NL_ATTR_TLV, in_size, in_msg);
	if (err) {
		LOG_ERROR("nla_put() error");
		goto nl_send_err;
	}

	mutex_lock(&swdevsai_nl_send_mtx);

	genlmsg_end(nl_msg, hdr);

	err = genlmsg_multicast(&swdevsai_genl_family, nl_msg, 0,
				SADEVSAI_NL_MCGRP_ID, GFP_ATOMIC);
	if (err) {
		mutex_unlock(&swdevsai_nl_send_mtx);
		LOG_ERROR("genlmsg_multicast() error");
		return err;
	}

	err = swdevsai_nl_get_reply(wait, out_msg, out_size, &out_data_size);
	if (err)
		LOG_ERROR("swdevsai_nl_get_reply() failed");

	mutex_unlock(&swdevsai_nl_send_mtx);
	return err;

nl_send_err:
	genlmsg_cancel(nl_msg, hdr);
	nlmsg_free(nl_msg);
	return err;
}

static int swdevsai_nl_send_req(struct prestera_device *dev, int qid,
			    u8 *in_msg, size_t in_size,
			    u8 *out_msg, size_t out_size,
			    unsigned int wait)
{
	return swdevsai_nl_send_sync(wait, in_msg, in_size, out_msg, out_size);
}

static void swdevsai_nl_dev_register_work_fn(struct work_struct *work)
{
	struct swdevsai_nl_device *nl_dev;
	struct prestera_fw *fw;
	int err;

	g_pdev = pci_alloc_dev(NULL);
	if (!g_pdev)
		return;

	fw = kzalloc(sizeof(*fw), GFP_KERNEL);
	if (!fw)
		goto err_fw_alloc;

	fw->dev.send_req = swdevsai_nl_send_req;
	fw->dev.dev = &g_pdev->dev;

	nl_dev = kzalloc(sizeof(*nl_dev), GFP_KERNEL);
	if (!nl_dev)
		goto err_nl_dev_alloc;

	pci_set_drvdata(g_pdev, nl_dev);
	nl_dev->is_registered = false;
	nl_dev->fw = fw;

	prestera_fw_rev_parse_int(SWDEVSAI_VER, &fw->dev.fw_rev);
	if (prestera_fw_rev_check(fw))
		goto err_nl_dev_alloc;

	err = prestera_device_register(&fw->dev);
	if (err) {
		dev_err(&g_pdev->dev, "prestera_device_register() error\n");
		goto err_pr_dev_register;
	};

	nl_dev->is_registered = true;

	/* sync sw_dev assign */
	wmb();
	WRITE_ONCE(sw_dev, &fw->dev);

	dev_info(&g_pdev->dev, "registered new device\n");
	fw->dev.running = true;
	return;

err_pr_dev_register:
err_nl_dev_alloc:
	nl_dev->fw = NULL;
	kfree(fw);
err_fw_alloc:
	g_pdev = NULL;
	kfree(g_pdev);
}

static int swdevsai_nl_handle_drv_init(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	struct sk_buff *nl_msg;
	void *hdr;

	nl_msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!nl_msg) {
		LOG_ERROR("nlmsg_new() faled");
		return -ENOMEM;
	}

	hdr = genlmsg_put_reply(nl_msg, info, &swdevsai_genl_family, 0,
				SADEVSAI_NL_TYPE_DRV_INIT);
	if (!hdr) {
		LOG_ERROR("genlmsg_put_reply() failed");
		err = -EMSGSIZE;
		goto drv_init_reply_err;
	}

	err = nla_put_flag(nl_msg, SADEVSAI_NL_ATTR_DRV_INIT_ACK);
	if (err) {
		LOG_ERROR("nla_put_flag() failed");
		goto drv_init_reply_err;
	}

	genlmsg_end(nl_msg, hdr);

	err = genlmsg_reply(nl_msg, info);
	if (err) {
		LOG_ERROR("genlmsg_reply() error");
		return 0;
	}

	INIT_WORK(&swdevsai_nl_dev_register_work, swdevsai_nl_dev_register_work_fn);
	schedule_work(&swdevsai_nl_dev_register_work);

	return 0;

drv_init_reply_err:
	genlmsg_cancel(nl_msg, hdr);
	nlmsg_free(nl_msg);
	return 0;
}

static void swdevsai_nl_event_process(struct work_struct *work)
{
	int err;
	struct swdevsai_nl_event *ev = container_of(work,
						  struct swdevsai_nl_event, work);

	err = ev->dev->recv_msg(ev->dev, ev->data, ev->len);
	if (err && err != -ENOENT)
		pr_err("recv_msg failed (errno %d)", err);

	kfree(ev);
}

static int swdevsai_nl_handle_event(struct sk_buff *skb, struct genl_info *info)
{
	struct swdevsai_nl_event *ev;
	size_t len;

	if (!sw_dev || !sw_dev->recv_msg)
		return 0;

	if (!info->attrs[SADEVSAI_NL_ATTR_TLV]) {
		LOG_ERROR("No SADEVSAI_NL_ATTR_TLV attr");
		return -EINVAL;
	}

	len = nla_len(info->attrs[SADEVSAI_NL_ATTR_TLV]);
	ev = kmalloc(sizeof(*ev) + len, GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	memcpy(ev->data, nla_data(info->attrs[SADEVSAI_NL_ATTR_TLV]), len);
	ev->dev = sw_dev;
	ev->len = len;

	INIT_WORK(&ev->work, swdevsai_nl_event_process);
	queue_work(swdevsai_nl_owq, &ev->work);

	return 0;
}

static int __init swdevsai_pr_nl_init(void)
{
	int err;

	pr_info("Loading Switchdev SAI Netlink Driver\n");

	swdevsai_nl_owq = alloc_ordered_workqueue("%s_ordered", 0, SADEVSAI_NL_NAME);
	if (!swdevsai_nl_owq) {
		err = -ENOMEM;
		goto err_alloc_wq;
	}

	err = genl_register_family(&swdevsai_genl_family);
	if (err) {
		pr_err("Failed to initialize netlink driver\n");
		goto err_nl_register;
	}

	return 0;

err_nl_register:
	destroy_workqueue(swdevsai_nl_owq);
err_alloc_wq:
	return err;
}

static void __exit swdevsai_pr_nl_exit(void)
{
	struct swdevsai_nl_device *nl_dev;

	pr_info("Unloading Switchdev SAI Netlink Driver\n");

	if (g_pdev) {
		nl_dev = pci_get_drvdata(g_pdev);
		if (nl_dev->is_registered) {
			prestera_device_unregister(&nl_dev->fw->dev);
			nl_dev->is_registered = false;
			sw_dev = NULL;
		}
		kfree(nl_dev->fw);
		kfree(nl_dev);
	}

	flush_workqueue(swdevsai_nl_owq);
	destroy_workqueue(swdevsai_nl_owq);
	genl_unregister_family(&swdevsai_genl_family);
}

module_init(swdevsai_pr_nl_init);
module_exit(swdevsai_pr_nl_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Switchdev SAI Netlink driver");
