#!/bin/bash
#
# t0003-get-maintainer.sh -- check scripts/get_maintainer.pl
#
# Copyright (C) 2026  Jeff Layton <jlayton@kernel.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

command -v perl >/dev/null 2>&1 || {
	echo "SKIP: perl is not installed"
	exit 77
}

BASEDIR=`dirname "$0"`
TOPDIR=`realpath "$BASEDIR/.."`
GETMAINT="$TOPDIR/scripts/get_maintainer.pl"

[ -x "$GETMAINT" ] || {
	echo "SKIP: $GETMAINT is not executable"
	exit 77
}

# The exact flag sets b4 prep --auto-to-cc uses for To: and Cc:
TO_FLAGS="--nogit --nogit-fallback --nogit-chief-penguins --norolestats --nol"
CC_FLAGS="--nogit --nogit-fallback --nogit-chief-penguins --norolestats --nom"

# A synthetic patch touching a nested file and a top-level file
PATCH=`mktemp`
trap "rm -f $PATCH" EXIT
cat > "$PATCH" <<'EOF'
diff --git a/utils/mountd/mountd.c b/utils/mountd/mountd.c
--- a/utils/mountd/mountd.c
+++ b/utils/mountd/mountd.c
@@ -1 +1 @@
-old();
+new();
diff --git a/README b/README
--- a/README
+++ b/README
@@ -1 +1 @@
-old
+new
EOF

TCOUNT=0
TPASS=0

check() {
	local name="$1"; shift
	TCOUNT=$((TCOUNT + 1))
	if "$@" >/dev/null 2>&1; then
		echo "PASS $name"
		TPASS=$((TPASS + 1))
	else
		echo "FAIL $name"
	fi
}

to_lists_maintainer() {
	$GETMAINT $TO_FLAGS < "$PATCH" | grep -q steved@redhat.com
}

to_excludes_list() {
	! $GETMAINT $TO_FLAGS < "$PATCH" | grep -q vger.kernel.org
}

cc_lists_list() {
	$GETMAINT $CC_FLAGS < "$PATCH" | grep -q linux-nfs@vger.kernel.org
}

cc_excludes_maintainer() {
	! $GETMAINT $CC_FLAGS < "$PATCH" | grep -q steved@redhat.com
}

default_lists_both() {
	[ $($GETMAINT < "$PATCH" | wc -l) -eq 2 ]
}

file_top_level() {
	$GETMAINT -f README | grep -q steved@redhat.com
}

file_nested() {
	$GETMAINT -f utils/mountd/mountd.c | grep -q steved@redhat.com
}

check self-test $GETMAINT --self-test
check b4-To-lists-maintainer to_lists_maintainer
check b4-To-excludes-list to_excludes_list
check b4-Cc-lists-list cc_lists_list
check b4-Cc-excludes-maintainer cc_excludes_maintainer
check default-lists-both default_lists_both
check file-top-level file_top_level
check file-nested file_nested

echo "$TPASS/$TCOUNT tests passed"
[ "$TPASS" -eq "$TCOUNT" ]
