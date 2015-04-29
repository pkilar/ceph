// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2015 Red Hat
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */


#include "MDSUtility.h"
#include "include/rados/librados.hpp"

class InodeStore;

class DataScan : public MDSUtility
{
  protected:
    // IoCtx for metadata pool (where we inject inodes to)
    librados::IoCtx metadata_io;
    // IoCtx for data pool (where we scrap backtraces from)
    librados::IoCtx data_io;

    uint32_t n;
    uint32_t m;

    /**
     * Pre-injection check that all the roots are present in
     * the metadata pool.  Used to avoid parallel workers interfering
     * with one another, by cueing the user to go run 'init' on a
     * single node before running a parallel scan.
     *
     * @param result: set to true if roots are present, else set to false
     * @returns 0 on no unexpected errors, else error code.  Missing objects
     *          are not considered an unexpected error: check *result for
     *          this case.
     */
    int check_roots(bool *result);

    /**
     * Create any missing roots (i.e. mydir, strays, root inode)
     */
    int init_metadata();

    /**
     * Scan data pool for backtraces, and inject inodes to metadata pool
     */
    int recover();

    /**
     */
    int inject_unlinked_inode(inodeno_t inono, int mode);
    int root_exists(inodeno_t ino, bool *result);

    int read_fnode(inodeno_t ino, frag_t frag, fnode_t *fnode);
    int read_dentry(inodeno_t parent_ino, frag_t frag,
                    const std::string &key, InodeStore *inode);
  public:
    void usage();
    int main(const std::vector<const char *> &args);
};

