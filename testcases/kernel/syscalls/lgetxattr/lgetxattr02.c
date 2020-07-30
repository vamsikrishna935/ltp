// SPDX-License-Identifier: GPL-2.0-or-later
/*
* Copyright (c) 2016 Fujitsu Ltd.
* Author: Jinbao Huang <huangjb.jy@cn.fujitsu.com>
*/

/*
* Test Name: lgetxattr02
*
* Description:
* 1) lgetxattr(2) fails if the named attribute does not exist.
* 2) lgetxattr(2) fails if the size of the value buffer is too small
*    to hold the result.
* 3) lgetxattr(2) fails when attemptes to read from a invalid address.
*
* Expected Result:
* 1) lgetxattr(2) should return -1 and set errno to ENODATA.
* 2) lgetxattr(2) should return -1 and set errno to ERANGE.
* 3) lgetxattr(2) should return -1 and set errno to EFAULT.
*/

/*
 * Patch Description:
 * Test failure reason in SGX-LKL:
 * [[  SGX-LKL ]] libc_start_main_stage2(): Calling app main: /ltp/testcases/kernel/syscalls/lgetxattr/lgetxattr02
 * tst_test.c:1106: INFO: Timeout per run is 0h 05m 00s
 * tst_test.c:1125: INFO: No fork support
 * lgetxattr02.c:78: CONF: no xattr support in fs or mounted without user_xattr option
 *
 * Workaround to fix the issue:
 * Modified the tests to use root filesystem.
 * Commented a test, which needs to be enabled once git issue 297 is fixed
 * Issue 297: [Tests] lkl_access_ok() should return -1 on invalid access
 * https://github.com/lsds/sgx-lkl/issues/297
 */

#include "config.h"
#include <errno.h>
#include <sys/types.h>
#include <string.h>

#ifdef HAVE_SYS_XATTR_H
# include <sys/xattr.h>
#endif

#include "tst_test.h"

#ifdef HAVE_SYS_XATTR_H

#define SECURITY_KEY	"security.ltptest"
#define VALUE	"this is a test value"
#define tmpdir  "/tmplgetxattr"
static struct test_case {
	const char *path;
	size_t size;
	int exp_err;
} tcase[] = {
	{"testfile", sizeof(VALUE), ENODATA},
	{"symlink", 1, ERANGE},
//	{(char *)-1, sizeof(VALUE), EFAULT} TODO: Enable once git issue 297 is fixed
};

static void verify_lgetxattr(unsigned int n)
{
	struct test_case *tc = tcase + n;
	char buf[tc->size];

	TEST(lgetxattr(tc->path, SECURITY_KEY, buf, sizeof(buf)));
	if (TST_RET != -1) {
		tst_res(TFAIL, "lgetxattr() succeeded unexpectedly");
		return;
	}

	if (TST_ERR != tc->exp_err) {
		tst_res(TFAIL | TTERRNO, "lgetxattr() failed unexpectedlly, "
			"expected %s", tst_strerrno(tc->exp_err));
	} else {
		tst_res(TPASS | TTERRNO, "lgetxattr() failed as expected");
	}
}

static void setup(void)
{
	int res;
	SAFE_MKDIR(tmpdir, 0644);
	SAFE_TOUCH("testfile", 0644, NULL);
	SAFE_SYMLINK("testfile", "symlink");

	res = lsetxattr("symlink", SECURITY_KEY, VALUE, strlen(VALUE), XATTR_CREATE);
	if (res == -1) {
		if (errno == ENOTSUP) {
			tst_brk(TCONF, "no xattr support in fs or "
				"mounted without user_xattr option");
		} else {
			tst_brk(TBROK | TERRNO, "lsetxattr(%s) failed",
				SECURITY_KEY);
		}
	}
}

void cleanup(void)
{
        remove("testfile");
        remove("symlink");
        SAFE_RMDIR(tmpdir);
}

static struct tst_test test = {
	.needs_root = 1,
	.test = verify_lgetxattr,
	.tcnt = ARRAY_SIZE(tcase),
	.setup = setup,
	.cleanup = cleanup
};

#else /* HAVE_SYS_XATTR_H */
	TST_TEST_TCONF("<sys/xattr.h> does not exist.");
#endif
