// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include "xdp_sample_user.h"
#include <linux/types.h>
#include "qat_xdp_acceldata.h"
#include <sys/ioctl.h>
#include <fcntl.h>

#define ACCELDATA_LIST_SIZE (1)
#define ACCELDATA_LIST_SIZE_MAX (ACCELDATA_LIST_SIZE * 10)

#define DEBUG_LOG_ENABLED (0)

#define PRINT_ACCELDEV_LOG(...) fprintf(stdout, __VA_ARGS__)

#if DEBUG_LOG_ENABLED
#define PRINT_ACCELDEV_LOG_DEBUG(...) fprintf(stdout, __VA_ARGS__)
#else
#define PRINT_ACCELDEV_LOG_DEBUG(...)
#endif

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "filename", required_argument, NULL, 'f' },
	{ "ifin", required_argument, NULL, 'i' },
	{ "ifout", required_argument, NULL, 'o' },
	{ "proto", required_argument, NULL, 'p' },
	{ "spi", required_argument, NULL, 's' },
	{ "ipversion", required_argument, NULL, 'v' },
	{ "ipversiondst", required_argument, NULL, 'D' },
	{ "cipherkey", required_argument, NULL, 'k' },
	{ "cipheralgo", required_argument, NULL, 'a' },
	{ "authkey", required_argument, NULL, 'K' },
	{ "authalgo", required_argument, NULL, 'A' },
	{ "icvlen", required_argument, NULL, 'V' },
	{ "detach", no_argument, NULL, 'd' },
	{ "showelem", required_argument, NULL, 'S' },
	{ "rmelem", required_argument, NULL, 'r' },
	{}
};

static int str_to_int (__u8 *array, char *str, unsigned int len, int swap)
{
	char c[3];
	int  i, idx;
	/* PRINT_ACCELDEV_LOG("str_to_int: input len = %u\n", len); */

	for (i = 0; i < len; i = i + 2) {
		c[0] = str[i];
		c[1] = str[i + 1];
		c[2] = 0;

		idx = swap ? ((i / 2) - (i / 2) % 4 + 3 - (i / 2) % 4) : (i / 2);
		array[idx] = strtol((const char *)&c, 0, 16);
		/* PRINT_ACCELDEV_LOG("array[%u] = %x\n", idx, array[idx]); */
	}

	return len / 2;
}

int main(int argc, char **argv)
{
	/* struct bpf_link *link = NULL; */
	struct bpf_program *preprocess, *postprocess;
	int map_fd, post_action_fd;
	struct bpf_object *obj = NULL;
	struct qat_xdp_acceldata *acceldata;
	struct bpf_acceldevmap_val *acceldata_list[ACCELDATA_LIST_SIZE_MAX] = {0};
	struct bpf_acceldevmap_val value;
	int i, ret;
	int ioctl_fd = 0;
	__u64 key = 0;
	__u64 next_key = 0;
	__u64 tmp;
	__u32 bdfn;
	int ifindex_in, ifindex_out;
	int opt;
	int para_counter = 0;
	int bdfn_num = 0;
	bool only_detach = false;
	bool show_elem = false;
	bool remove_elem = false;
	int size;

	/* Default parameter */
	char *filename = "xdp_redirect_map_acceldev.bpf.o";
	char *ifin = "ens802f1np1";
	char *ifout = "ens802f0np0";
	__u8 proto = 0x32;/* IPPROTO_ESP */
	__u32 spi = 0xcf18f8f8;
	int ip_version = 4; /*ipv4*/
	__u32 ipv4_dst = 0xc0a86e02; /* 192.168.110.2 */
	char *pcipher_key = "ea750622fa18dc3b3aa96bd7654dbda9";
	int cipher_alg = 4;	/* CPA_CY_SYM_CIPHER_AES_CBC */
	char *pauth_key = "7b3c717f1270c0cc6249b5a4ed6f413de27c7a12";
	int auth_alg = 2;	/* CPA_CY_SYM_HASH_SHA1 */
	int icv_length = 12;

	while ((opt = getopt_long(argc, argv, "hf:i:o:p:s:v:D:k:a:K:A:V:dS:r:",
				  long_options, NULL)) != -1) {
		para_counter++;
		switch (opt) {
		case 'h':
			PRINT_ACCELDEV_LOG("Option for ./xdp_redirect_map_acceldev:\n"
			" --help                  short-option: -h\n"
			" --filename              short-option: -f\n"
			" --ifin                  short-option: -i\n"
			" --ifout                 short-option: -o\n"
			" --proto                 short-option: -p\n"
			" --spi                   short-option: -s\n"
			" --ipversion             short-option: -v\n"
			" --ipversiondst          short-option: -D\n"
			" --cipherkey             short-option: -k\n"
			" --cipheralgo            short-option: -a\n"
			" --authkey               short-option: -K\n"
			" --authalgo              short-option: -A\n"
			" --icvlen                short-option: -V\n"
			" --detach                short-option: -d\n"
			" --showelem              short-option: -S\n"
			" --rmelem                short-option: -r\n");
			return 0;
		case 'f':
			filename = optarg;
			break;
		case 'i':
			ifin = optarg;
			break;
		case 'o':
			ifout = optarg;
			break;
		case 'p':
			proto = strtoul(optarg, NULL, 0);
			break;
		case 's':
			spi = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			ip_version = strtoul(optarg, NULL, 0);
			break;
		case 'D':
			ipv4_dst = strtoul(optarg, NULL, 0);
			break;
		case 'k':
			pcipher_key = optarg;
			break;
		case 'a':
			cipher_alg = strtoul(optarg, NULL, 0);
			break;
		case 'K':
			pauth_key = optarg;
			break;
		case 'A':
			auth_alg = strtoul(optarg, NULL, 0);
			break;
		case 'V':
			icv_length = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			para_counter--;
			only_detach = true;
			break;
		case 'S':
			show_elem = true;
			key = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			remove_elem = true;
			key = strtoul(optarg, NULL, 0);
			break;
		default:
			para_counter--;
			break;
		}
	}

	if (only_detach || show_elem || remove_elem) {
		if ((only_detach && show_elem) ||
		    (only_detach && remove_elem) ||
			 (show_elem && remove_elem)) {
			PRINT_ACCELDEV_LOG("only_detach & show_elem & remove_elem conflict.\n");
			goto cleanup;
		}
		PRINT_ACCELDEV_LOG("Options:\n");
		PRINT_ACCELDEV_LOG("    filename: %s\n", filename);
		if (only_detach) {
			PRINT_ACCELDEV_LOG("    ifin: %s\n", ifin);
			PRINT_ACCELDEV_LOG("    ifout: %s\n", ifout);
		} else if (remove_elem) {
			PRINT_ACCELDEV_LOG("    key: %llx\n", key);
		}
	} else {
		if (para_counter == 0)
			PRINT_ACCELDEV_LOG("Using default options:\n");
		else
			PRINT_ACCELDEV_LOG("Options(options:%d):\n", para_counter);
		PRINT_ACCELDEV_LOG("    filename: %s\n", filename);
		PRINT_ACCELDEV_LOG("    ifin: %s\n", ifin);
		PRINT_ACCELDEV_LOG("    ifout: %s\n", ifout);
		PRINT_ACCELDEV_LOG("    proto: 0x%02x\n", proto);
		PRINT_ACCELDEV_LOG("    spi: 0x%08x\n", spi);
		PRINT_ACCELDEV_LOG("    ip_version: %d\n", ip_version);
		PRINT_ACCELDEV_LOG("    ipv4_dst: 0x%08x\n", ipv4_dst);
		PRINT_ACCELDEV_LOG("    pcipher_key: %s\n", pcipher_key);
		PRINT_ACCELDEV_LOG("    cipher_alg: 0x%08x\n", cipher_alg);
		PRINT_ACCELDEV_LOG("    pauth_key: %s\n", pauth_key);
		PRINT_ACCELDEV_LOG("    auth_alg: 0x%08x\n", auth_alg);
		PRINT_ACCELDEV_LOG("    icv_length: %d\n", icv_length);
		PRINT_ACCELDEV_LOG("    only_detach: %d\n", only_detach);
	}
	PRINT_ACCELDEV_LOG("\n");

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		PRINT_ACCELDEV_LOG("ERROR: opening BPF object file failed\n");
		goto cleanup;
	}
	PRINT_ACCELDEV_LOG_DEBUG("bpf_object__open_file success\n");

	preprocess = bpf_object__find_program_by_name(obj, "xdp_acceldev_preprocess");
	bpf_program__set_type(preprocess, BPF_PROG_TYPE_XDP);
	if (!preprocess) {
		PRINT_ACCELDEV_LOG("ERROR: finding prog xdp_acceldev_preprocess failed\n");
		goto cleanup;
	}
	PRINT_ACCELDEV_LOG_DEBUG("find xdp_acceldev_preprocess success\n");

	/* postprocess = bpf_object__find_program_by_name(obj, "xdp_acceldev_postprocess"); */
	postprocess = bpf_object__find_program_by_name(obj, "xdp_sock_for_acceldev_prog");

	bpf_program__set_type(postprocess, BPF_PROG_TYPE_XDP);
	if (!postprocess) {
		PRINT_ACCELDEV_LOG("ERROR: finding prog xdp_acceldev_postprocess failed\n");
		goto cleanup;
	}
	PRINT_ACCELDEV_LOG_DEBUG("find xdp_acceldev_postprocess success\n");

	if (bpf_object__load(obj)) {
		PRINT_ACCELDEV_LOG("ERROR: loading BPF object file failed\n");
		goto cleanup;
	}
	PRINT_ACCELDEV_LOG_DEBUG("bpf_object__load success\n");

	map_fd = bpf_object__find_map_fd_by_name(obj, "acceldev_redirect_map");
	if (map_fd < 0) {
		PRINT_ACCELDEV_LOG("ERROR: finding map acceldev_redirect_map in obj file failed\n");
		goto cleanup;
	}
	PRINT_ACCELDEV_LOG_DEBUG("bpf_object__find_map_fd_by_name success map_fd = %d\n", map_fd);

	if (show_elem) {
		i = 0;
		PRINT_ACCELDEV_LOG("Show elements: map_fd = 0x%x\n", map_fd);
		while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
			ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
			if (ret < 0)
				break;

			PRINT_ACCELDEV_LOG("=======================================\n");
			PRINT_ACCELDEV_LOG("No.%d\n", i);
			PRINT_ACCELDEV_LOG("key = 0x%016llx\n", key);
			PRINT_ACCELDEV_LOG("value.acceldev_type = %d\n", value.acceldev_type);
			PRINT_ACCELDEV_LOG("value.bdfn = 0x%x\n", value.bdfn);
			PRINT_ACCELDEV_LOG("value.bpf_prog.fd = 0x%x\n", value.bpf_prog.fd);
			PRINT_ACCELDEV_LOG("value.acceldata_sz = %d\n", value.acceldata_sz);
			key = next_key;
			i++;
		}

		if (i > 0)
			PRINT_ACCELDEV_LOG("=======================================\n");

		PRINT_ACCELDEV_LOG("Total elements: %d\n", i);
		PRINT_ACCELDEV_LOG("Show elements success\n\n");
		goto cleanup;
	}

	if (remove_elem) {
		PRINT_ACCELDEV_LOG("Remove element: map_fd = 0x%x, key = %016llx\n", map_fd, key);
		ret = bpf_map_lookup_elem(map_fd, &key, &value);
		if (ret > 0) {
			ret = bpf_map_delete_elem(map_fd, &key);
			if (ret < 0)
				PRINT_ACCELDEV_LOG("Error : Remove element ret = %d\n", ret);

			PRINT_ACCELDEV_LOG("Remove element success\n\n");
		} else {
			PRINT_ACCELDEV_LOG("Element not found\n\n");
		}
		goto cleanup;
	}

	ifindex_in = if_nametoindex(ifin);
	ifindex_out = if_nametoindex(ifout);
	PRINT_ACCELDEV_LOG("map_fd = 0x%x\n", map_fd);
	PRINT_ACCELDEV_LOG("if_indexin = %d, if_index_out = %d\n", ifindex_in, ifindex_out);

	if (only_detach) {
		bpf_xdp_detach(ifindex_in, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE, NULL);
		PRINT_ACCELDEV_LOG("ifindex_in(%d) prog detach only success\n\n", ifindex_in);
		goto cleanup;
	}

	bpf_xdp_detach(ifindex_in, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE, NULL);
	PRINT_ACCELDEV_LOG_DEBUG("ifindex_in prog detach success\n");

	ret = bpf_xdp_attach(ifindex_in,
			     bpf_program__fd(preprocess),
			XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE, NULL);
	if (ret < 0)
		PRINT_ACCELDEV_LOG("Error : ifindex_in prog attach failed\n");

	PRINT_ACCELDEV_LOG("ifindex_in prog attach success\n");

	/* Create accel data for test */
	ioctl_fd = open("/dev/qat_xdp", O_RDWR);
	if (ioctl_fd < 0) {
		PRINT_ACCELDEV_LOG("ERROR: ioctl open failed\n");
		goto cleanup;
	}
	PRINT_ACCELDEV_LOG_DEBUG("ioctl open qat_xdp success\n");

	post_action_fd = bpf_program__fd(postprocess);
	PRINT_ACCELDEV_LOG("Get post_action_fd = 0x%x\n", post_action_fd);

	/* Get bdfn num*/
	ret = ioctl(ioctl_fd, IOCTL_QAT_XDP_GET_PCI_DEV_NUM, &bdfn_num);
	if (ret < 0) {
		PRINT_ACCELDEV_LOG("Error : bdfn num total = %d\n", bdfn_num);
		goto cleanup;
	}
	PRINT_ACCELDEV_LOG("Get bdfn num = %d\n\n", bdfn_num);

	if (ACCELDATA_LIST_SIZE * bdfn_num > ACCELDATA_LIST_SIZE_MAX) {
		PRINT_ACCELDEV_LOG("Error : ACCELDATA_LIST_SIZE * bdfn_num too big\n");
		goto cleanup;
	}

	for (i = 0; i < ACCELDATA_LIST_SIZE * bdfn_num; ++i) {
		PRINT_ACCELDEV_LOG("=======================================\n");
		PRINT_ACCELDEV_LOG("Start to set acceldata_list[%d]\n", i);

		size = sizeof(struct bpf_acceldevmap_val) + sizeof(struct qat_xdp_acceldata);
		acceldata_list[i] = malloc(size);
		size = sizeof(struct bpf_acceldevmap_val);
		acceldata = (struct qat_xdp_acceldata *)((void *)acceldata_list[i] + size);

		/* Set acceldata */
		acceldata->proto = proto;
		acceldata->spi = spi;
		acceldata->ip_version = ip_version;
		acceldata->ipv4_dst = ipv4_dst;
		acceldata->cipher.key.length = str_to_int(acceldata->cipher.key.data,
							  pcipher_key, strlen(pcipher_key), 0);
		acceldata->cipher.algo = cipher_alg;

		acceldata->auth.key.length = str_to_int(acceldata->auth.key.data,
							pauth_key, strlen(pauth_key), 0);
		acceldata->auth.icv_length = icv_length;
		acceldata->auth.algo = auth_alg;

		acceldata_list[i]->acceldev_type = BPF_ACCELDEV_CRYPTO;
		acceldata_list[i]->bpf_prog.fd = post_action_fd;
		acceldata_list[i]->acceldata_sz = sizeof(struct qat_xdp_acceldata);

		/* Get bdfn (key_instance + key_ctx) */
		bdfn = (i % bdfn_num) + 1;
		PRINT_ACCELDEV_LOG("Get bdfn from bdfn No.%d\n", bdfn);
		ret = ioctl(ioctl_fd, IOCTL_QAT_XDP_GET_PCI_DEV_BDF, &bdfn);
		if (ret < 0) {
			PRINT_ACCELDEV_LOG("Error : Get bdfn failed, bdfn = %x\n", bdfn);
			goto cleanup;
		}
		acceldata_list[i]->bdfn = bdfn;
		PRINT_ACCELDEV_LOG("Get bdfn by ioctl success : bdfn = %x\n", bdfn);

		/* Get key */
		memcpy(&tmp, (__u64 *)acceldata_list[i], sizeof(tmp));
		ret = ioctl(ioctl_fd, IOCTL_QAT_XDP_GET_KEY, acceldata_list[i]);
		if (ret < 0) {
			PRINT_ACCELDEV_LOG("ERROR: ioctl failed at [%d]\n", i);
			goto cleanup;
		}
		memcpy(&key, (__u64 *)acceldata_list[i], sizeof(tmp));
		memcpy((__u64 *)acceldata_list[i], &tmp, sizeof(tmp));
		PRINT_ACCELDEV_LOG("Get key by ioctl success, key = 0x%016llx\n", key);

		/* Create acceldev & acceldev_ctx */
		ret = bpf_map_update_elem(map_fd, &key, acceldata_list[i], BPF_ANY);
		if (ret < 0)
			PRINT_ACCELDEV_LOG("Error : bpf_map_update_elem failed, ret = %d\n", ret);

		PRINT_ACCELDEV_LOG("bpf_map_update_elem success, ret = %d\n", ret);
	}
	PRINT_ACCELDEV_LOG("=======================================\n");
	PRINT_ACCELDEV_LOG("Acceldata in acceldata_list are all set\n\n");

cleanup:
	PRINT_ACCELDEV_LOG_DEBUG("Cleanup:\n");
	for (i = 0; i < ACCELDATA_LIST_SIZE; ++i) {
		if (acceldata_list[i]) {
			PRINT_ACCELDEV_LOG_DEBUG("free(acceldata_list[%d])\n", i);
			free(acceldata_list[i]);
		}
	}

	/* bpf_link__destroy(link); */
	bpf_object__close(obj);
	PRINT_ACCELDEV_LOG("User program exit\n");

	if (ioctl_fd > 0) {
		ret = close(ioctl_fd);
		if (ret < 0)
			PRINT_ACCELDEV_LOG("ERROR: ioctl close failed ret = %d\n", ret);
	}

	return 0;
}
