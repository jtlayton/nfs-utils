#!/usr/bin/perl
#
# scripts/get_maintainer.pl -- report whom to Cc on an nfs-utils patch
#
# Copyright (C) 2026  Jeff Layton <jlayton@kernel.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 0211-1301 USA
#
# Reads the MAINTAINERS file at the top of the tree (same section format
# as the Linux kernel MAINTAINERS file) and prints the matching M:, R:
# and L: entries for the files in a patch.  This is a deliberately small
# subset of the kernel scripts/get_maintainer.pl: the F:, X:, N: and K:
# match types are supported, but there is no git history fallback and no
# interactive mode.  It understands the option subset that "b4 prep
# --auto-to-cc" passes, so that command works out of the box:
#
#	scripts/get_maintainer.pl <patch>
#	scripts/get_maintainer.pl -f <file>...
#	scripts/get_maintainer.pl --self-test

use strict;
use warnings;
use Getopt::Long qw(:config no_auto_abbrev);
use File::Basename qw(basename dirname);
use Cwd qw(abs_path);

my $P = basename($0);

my $email_maintainer = 1;
my $email_reviewer = 1;
my $email_list = 1;
my $output_roles = 1;
my $output_rolestats = 0;
my $output_separator;
my $output_multiline = 1;
my $do_keywords = 1;
my $from_filename = 0;
my $maintainer_path;
my $self_test;
my $show_help = 0;

# Accepted and ignored: this implementation never mines git history,
# so the git options (and the informational ones below) are no-ops.
my %ignored;

if (!GetOptions(
	'm!' => \$email_maintainer,
	'r!' => \$email_reviewer,
	'l!' => \$email_list,
	'roles!' => \$output_roles,
	'rolestats!' => \$output_rolestats,
	'separator=s' => \$output_separator,
	'multiline!' => \$output_multiline,
	'remove-duplicates!' => \$ignored{remove_duplicates},
	'f|file' => \$from_filename,
	'mpath|maintainer-path=s' => \$maintainer_path,
	'k|keywords!' => \$do_keywords,
	'self-test:s' => \$self_test,
	'help|h|?' => \$show_help,
	'email!' => \$ignored{email},
	'git!' => \$ignored{git},
	'git-all-signature-types!' => \$ignored{git_all_signature_types},
	'git-blame!' => \$ignored{git_blame},
	'git-blame-signatures!' => \$ignored{git_blame_signatures},
	'git-fallback!' => \$ignored{git_fallback},
	'git-chief-penguins!' => \$ignored{git_chief_penguins},
	'git-min-signatures=i' => \$ignored{git_min_signatures},
	'git-max-maintainers=i' => \$ignored{git_max_maintainers},
	'git-min-percent=i' => \$ignored{git_min_percent},
	'git-since=s' => \$ignored{git_since},
	'hg-since=s' => \$ignored{hg_since},
	'mailmap!' => \$ignored{mailmap},
	'n!' => \$ignored{n},
	's!' => \$ignored{s},
	'fixes!' => \$ignored{fixes},
	'moderated!' => \$ignored{moderated},
	'pattern-depth=i' => \$ignored{pattern_depth},
	'fe|file-emails!' => \$ignored{file_emails},
    )) {
    die "usage: $P [options] patchfile\n";
}

if ($show_help) {
    usage();
    exit 0;
}

$output_roles = 1 if ($output_rolestats);
$output_multiline = 0
    if (defined $output_separator && $output_separator ne ", ");

if (-t STDIN && !@ARGV && !defined $self_test) {
    die "$P: missing patchfile or -f file - use --help if necessary\n";
}

my $topdir = find_toplevel();
my $maint_file = $maintainer_path // "$topdir/MAINTAINERS";
die "$P: MAINTAINER file not found '$maint_file'\n" if (!-f $maint_file);

my @sections = read_maintainer_file($maint_file);

if (defined $self_test) {
    exit(self_test($maint_file, \@sections) ? 1 : 0);
}

my (@files, @content);
if ($from_filename) {
    # Accept absolute paths by trimming the tree prefix, like the kernel script
    @files = map { my $f = $_; $f =~ s@^\Q$topdir\E/@@; $f } @ARGV;
} elsif (@ARGV) {
    foreach my $patch (@ARGV) {
	open(my $fh, '<', $patch)
	    or die "$P: Can't open $patch: $!\n";
	push(@content, <$fh>);
	close($fh);
    }
    @files = patch_files(\@content);
} else {
    @content = <STDIN>;
    @files = patch_files(\@content);
}

# In -f mode with keyword matching, scan the named files themselves.
if ($from_filename && $do_keywords) {
    foreach my $file (@files) {
	next if ($file =~ m@\bMAINTAINERS$@);
	my $path = $file =~ m@^/@ ? $file : "$topdir/$file";
	next if (!-f $path);
	open(my $fh, '<', $path) or next;
	push(@content, <$fh>);
	close($fh);
    }
}

my @matches = match_sections(\@sections, \@files, \@content);

my @out;
my %seen;
foreach my $m (@matches) {
    my ($section, $type, $addr) = @$m;
    next if ($type eq 'M' && !$email_maintainer);
    next if ($type eq 'R' && !$email_reviewer);
    next if ($type eq 'L' && !$email_list);
    my $key = $addr =~ /<([^>]+)>/ ? $1 : $addr;
    next if ($seen{$key}++);
    if ($output_roles) {
	my $role = $type eq 'M' ? maintainer_role($section->{S})
	    : $type eq 'R' ? 'reviewer'
	    : 'open list';
	$addr .= " ($role:$section->{name})";
    }
    push(@out, $addr);
}

if ($output_multiline) {
    print "$_\n" foreach (@out);
} elsif (@out) {
    print join($output_separator // ", ", @out) . "\n";
}

exit 0;

sub usage {
    print <<EOT;
usage: $P [options] patchfile
       $P [options] -f file...
       $P --self-test

Print the MAINTAINERS entries (maintainers, reviewers, lists) for the
files changed by a patch.  With no patchfile argument, the patch is
read from standard input.

  --m, --r, --l	    include maintainers, reviewers, lists
		    (prefix with "no" to exclude, e.g. --nom)
  --roles	    show roles (default)
  --rolestats	    show roles (no statistics in this implementation)
  --separator=X	    join addresses with X instead of newlines
  -f, --file	    arguments are file names, not patches
  --mpath=PATH	    use PATH as the MAINTAINERS file
  -k, --keywords    match K: content patterns (default)
  --self-test	    validate the MAINTAINERS file

The --git* options are accepted for compatibility with the kernel
scripts/get_maintainer.pl and b4, but ignored: this implementation
only matches MAINTAINERS patterns, it never mines git history.
EOT
}

sub find_toplevel {
    my $dir = qx(git rev-parse --show-toplevel 2>/dev/null);
    chomp $dir if (defined $dir);
    if (!defined $dir || $dir eq '' || !-d $dir) {
	# Not in a git checkout (e.g. a release tarball): the tree top
	# is the parent of the directory holding this script.
	$dir = dirname(abs_path($0)) . '/..';
    }
    return $dir;
}

sub read_maintainer_file {
    my ($file) = @_;

    open(my $maint, '<', $file)
	or die "$P: Can't open MAINTAINERS file '$file': $!\n";
    my @sections;
    my $cur;
    while (<$maint>) {
	chomp;
	if (/^([A-Z]):\s*(.*)/) {
	    my ($type, $raw) = ($1, $2);
	    my $value = $raw;
	    next if (!defined $cur);
	    # The first field line promotes a pending header to a real
	    # section, so preamble text never becomes a section.
	    if (!$cur->{_kept}++) {
		push(@sections, $cur);
	    }
	    if ($type eq 'F' || $type eq 'X') {
		$value =~ s@\.@\\.@g;	## Convert . to \.
		$value =~ s/\*/.*/g;	## Convert * to .*
		$value =~ s/\?/./g;	## Convert ? to .
		# A pattern naming a real directory matches everything below it
		if ($raw !~ m@/$@ && -d "$topdir/$raw") {
		    $value .= '/';
		}
	    }
	    if ($type eq 'S') {
		$cur->{S} = $value;
	    } else {
		push(@{$cur->{$type}}, $value);
	    }
	} elsif (!/^\s*$/ && !/^\s*#/) {
	    $cur = { name => $_, S => 'Maintained', _kept => 0 };
	}
    }
    close($maint);
    return @sections;
}

sub patch_files {
    my ($lines) = @_;
    my @files;
    foreach (@$lines) {
	if (/^diff --git a\/(\S+) b\/(\S+)\s*$/) {
	    push(@files, $1, $2);
	} elsif (/^rename (?:from|to) (\S+)\s*$/) {
	    push(@files, $1);
	} elsif (/^ mode change [0-7]+ => [0-7]+ (\S+)\s*$/) {
	    push(@files, $1);
	} elsif (/^\+\+\+\s+(\S+)/ || /^---\s+(\S+)/) {
	    my $filename = $1;
	    next if ($filename eq '/dev/null');
	    $filename =~ s@^[^/]*/@@;
	    push(@files, $filename);
	}
    }
    return @files;
}

# Same matching rules as the kernel file_match_pattern(): a pattern with
# a trailing slash is a directory prefix; anything else must match from
# the start with the same number of path components.
sub file_match_pattern {
    my ($file, $pattern) = @_;
    if (substr($pattern, -1) eq '/') {
	return 1 if ($file =~ m@^$pattern@);
    } else {
	if ($file =~ m@^$pattern@) {
	    my $s1 = ($file =~ tr@/@/@);
	    my $s2 = ($pattern =~ tr@/@/@);
	    return 1 if ($s1 == $s2);
	}
    }
    return 0;
}

sub match_sections {
    my ($sections, $files, $content) = @_;
    my (@matches, %added);
    foreach my $file (@$files) {
	foreach my $section (@$sections) {
	    my $matched = 0;
	    if (grep { file_match_pattern($file, $_) } @{$section->{X} // []}) {
		next;
	    }
	    $matched = 1
		if (grep { file_match_pattern($file, $_) } @{$section->{F} // []});
	    if (!$matched) {
		foreach my $re (@{$section->{N} // []}) {
		    if ($file =~ m/$re/) {
			$matched = 1;
			last;
		    }
		}
	    }
	    if ($matched && !$added{$section->{name}}++) {
		push_section_addrs(\@matches, $section);
	    }
	}
    }
    if ($do_keywords) {
	foreach my $section (@$sections) {
	    next if ($added{$section->{name}});
	    next if (!@{$section->{K} // []});
	    foreach my $line (@$content) {
		foreach my $re (@{$section->{K}}) {
		    if ($line =~ m/$re/) {
			push_section_addrs(\@matches, $section);
			$added{$section->{name}} = 1;
			last;
		    }
		}
		last if ($added{$section->{name}});
	    }
	}
    }
    return @matches;
}

sub push_section_addrs {
    my ($matches, $section) = @_;
    foreach my $type (qw(M R L)) {
	foreach my $addr (@{$section->{$type} // []}) {
	    push(@$matches, [$section, $type, $addr]);
	}
    }
}

sub maintainer_role {
    my ($status) = @_;
    my $role = lc($status // '');
    return 'supporter' if ($role eq 'supported');
    return 'maintainer' if ($role eq 'maintained');
    return 'odd fixer' if ($role eq 'odd fixes');
    return 'orphan minder' if ($role eq 'orphan');
    return 'obsolete minder' if ($role eq 'obsolete');
    return 'chief penguin' if ($role eq 'buried alive in reporters');
    return $role ne '' ? $role : 'maintainer';
}

sub self_test {
    my ($file, $sections) = @_;
    my $errors = 0;
    foreach my $section (@$sections) {
	my $has_addr = (@{$section->{M} // []} ||
			@{$section->{R} // []} ||
			@{$section->{L} // []});
	if (!$has_addr && $section->{S} !~ /orphan|obsolete/i) {
	    print "$file: section without email address: $section->{name}\n";
	    $errors++;
	}
	if (!@{$section->{F} // []} && !@{$section->{N} // []} &&
	    !@{$section->{K} // []}) {
	    print "$file: section without file match: $section->{name}\n";
	    $errors++;
	}
    }
    if (!$errors) {
	print "$file: self-test passed (" . scalar(@$sections) .
	    " section(s))\n";
    }
    return $errors;
}
