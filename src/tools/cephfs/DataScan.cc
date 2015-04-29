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

#include "common/errno.h"
#include "common/ceph_argparse.h"
#include "include/util.h"

#include "mds/CInode.h"

#include "DataScan.h"

#define dout_subsys ceph_subsys_mds
#undef dout_prefix
#define dout_prefix *_dout << __func__ << ": "

void DataScan::usage()
{
  std::cout << "Usage: \n"
    << "  cephfs-data-scan scan <data pool name>\n"
    << "  cephfs-data-scan init\n"
    << std::endl;

  generic_client_usage();
}

int DataScan::main(const std::vector<const char*> &args)
{
  // Parse args
  // ==========
  if (args.size() < 1) {
    usage();
    return -EINVAL;
  }

  // Common RADOS init: open metadata pool
  // =====================================
  librados::Rados rados;
  int r = rados.init_with_context(g_ceph_context);
  if (r < 0) {
    derr << "RADOS unavailable" << dendl;
    return r;
  }

  dout(4) << "connecting to RADOS..." << dendl;
  rados.connect();

#if 0
  // TODO parse args
  n = 0;
  m = 1;
#else
  n = 0;
  m = 256;
#endif
 
  {
    int const metadata_pool_id = mdsmap->get_metadata_pool();
    dout(4) << "resolving metadata pool " << metadata_pool_id << dendl;
    std::string metadata_pool_name;
    r = rados.pool_reverse_lookup(metadata_pool_id, &metadata_pool_name);
    if (r < 0) {
      derr << "Pool " << metadata_pool_id
        << " identified in MDS map not found in RADOS!" << dendl;
      return r;
    }
    dout(4) << "found metadata pool '" << metadata_pool_name << "'" << dendl;
    r = rados.ioctx_create(metadata_pool_name.c_str(), metadata_io);
    if (r != 0) {
      return r;
    }
  }

  std::string const &command = args[0];
  if (command == "scan") {
    if (args.size() < 2) {
      usage();
      return -EINVAL;
    }
    const std::string data_pool_name = args[1];
    {
      int64_t data_pool_id = rados.pool_lookup(data_pool_name.c_str());
      if (data_pool_id < 0) {
        std::cerr << "Data pool '" << data_pool_name << "' not found!" << std::endl;
        return -ENOENT;
      } else {
        dout(4) << "data pool '" << data_pool_name
          << "' has ID " << data_pool_id << dendl;
      }

      if (!mdsmap->is_data_pool(data_pool_id)) {
        std::cerr << "Warning: pool '" << data_pool_name << "' is not a "
          "CephFS data pool!" << std::endl;
      }

      dout(4) << "opening data pool '" << data_pool_name << "'" << dendl;
      r = rados.ioctx_create(data_pool_name.c_str(), data_io);
      if (r != 0) {
        return r;
      }
    }
    return recover();
  } else if (command == "init") {
    return init_metadata();
  } else {
    std::cerr << "Unknown command '" << command << "'" << std::endl;
    return -EINVAL;
  }

  return recover();
}

int DataScan::inject_unlinked_inode(inodeno_t inono, int mode)
{
  // Compose
  object_t oid = InodeStore::get_object_name(inono, frag_t(), ".inode");
  InodeStore inode;
  inode.inode.ino = inono;
  inode.inode.version = 1;
  inode.inode.xattr_version = 1;
  inode.inode.mode = 0500 | mode;
  // Fake size to 1, so that the directory doesn't appear to be empty
  // (we won't actually give the *correct* size here though)
  inode.inode.size = 1;
  inode.inode.dirstat.nfiles = 1;

  inode.inode.ctime = 
    inode.inode.mtime = ceph_clock_now(g_ceph_context);
  inode.inode.nlink = 1;
  inode.inode.truncate_size = -1ull;

  // Serialize
  bufferlist inode_bl;
  ::encode(std::string(CEPH_FS_ONDISK_MAGIC), inode_bl);
  inode.encode(inode_bl);

  // Write
  int r = metadata_io.write_full(oid.name, inode_bl);
  if (r != 0) {
    derr << "Error writing '" << oid.name << "': " << cpp_strerror(r) << dendl;
    return r;
  }

  return r;
}

int DataScan::root_exists(inodeno_t ino, bool *result)
{
  object_t oid = InodeStore::get_object_name(ino, frag_t(), ".inode");
  uint64_t size;
  time_t mtime;
  int r = metadata_io.stat(oid.name, &size, &mtime);
  if (r == -ENOENT) {
    *result = false;
    return 0;
  } else if (r < 0) {
    return r;
  }

  *result = true;
  return 0;
}

int DataScan::init_metadata()
{
  int r = 0;
  r = inject_unlinked_inode(MDS_INO_ROOT, S_IFDIR|0755);
  if (r != 0) {
    return r;
  }
  r = inject_unlinked_inode(MDS_INO_MDSDIR(0), S_IFDIR);
  if (r != 0) {
    return r;
  }

  return 0;
}

int DataScan::check_roots(bool *result)
{
  int r;
  r = root_exists(MDS_INO_ROOT, result);
  if (r != 0) {
    return r;
  }
  if (!*result) {
    return 0;
  }

  r = root_exists(MDS_INO_MDSDIR(0), result);
  if (r != 0) {
    return r;
  }
  if (!*result) {
    return 0;
  }

  for (int i = 0; i < NUM_STRAY; ++i) {
    //r = linked_dirfrag_exists(
    // TODO
  }

  return 0;
}

int DataScan::recover()
{
  float progress = 0.0;
  librados::NObjectIterator i = data_io.nobjects_begin(n, m);
  librados::NObjectIterator i_end = data_io.nobjects_end();

  bool roots_present;
  int r = check_roots(&roots_present);
  if (r != 0) {
    derr << "Unexpected error checking roots: '"
      << cpp_strerror(r) << "'" << dendl;
    return r;
  }

  if (!roots_present) {
    std::cerr << "Some or all system inodes are absent.  Run 'init' from "
      "one node before running 'recover'" << std::endl;
    return -EIO;
  }

  for (; i != i_end; ++i) {
    const std::string oid = i->get_oid();
    if (i.get_progress() != progress) {
      if (int(i.get_progress() * 100) / 5 != int(progress * 100) / 5) {
        std::cerr << percentify(i.get_progress()) << "%" << std::endl;
      }
      progress = i.get_progress();
    }

    // Read backtrace
    bufferlist parent_bl;
    int r = data_io.getxattr(oid, "parent", parent_bl);
    if (r == -ENODATA) {
      dout(10) << "No backtrace on '" << oid << "'" << dendl;
      continue;
    } else if (r < 0) {
      dout(4) << "Unexpected error on '" << oid << "': " << cpp_strerror(r) << dendl;
      continue;
    }

    // Deserialize backtrace
    inode_backtrace_t backtrace;
    try {
      bufferlist::iterator q = parent_bl.begin();
      backtrace.decode(q);
    } catch (buffer::error &e) {
      dout(4) << "Corrupt backtrace on '" << oid << "': " << e << dendl;
      continue;
    }

    // TODO: validate backtrace ino number against object name
    // TODO: filter the object scan to only .00000 objects

    // Inject inode!
    
    // My immediate ancestry should be correct, so if we can find that
    // directory's dirfrag then go inject it there

    // There are various strategies here:
    //   - when a parent dentry doesn't exist, create it with a new inono (i.e.
    //     don't care about inode numbers for directories at all)
    //   - when a parent dentry doesn't exist, create it using the inodeno
    //     from the backtrace: assumes that nothing else in the hierarchy
    //     exists, so there won't be dupes
    //   - only insert inodes when their direct parent directory fragment
    //     already exists: this only risks multiple-linkage of files,
    //     rather than directories.

    // When creating linkage for a directory, *only* create it if we are
    // also creating the object.  That way, we might not manage to get the
    // *right* linkage for a directory, but at least we won't multiply link
    // it.  We assume that if a root dirfrag exists for a directory, then
    // it is linked somewhere (i.e. that the metadata pool is not already
    // inconsistent).
    // Making sure *that* is true is someone else's job!  Probably someone
    // who is not going to run in parallel, so that they can self-consistently
    // look at versions and move things around as they go.

    inodeno_t ino = backtrace.ino;
    dout(10) << "  inode: 0x" << std::hex << ino << std::dec << dendl;
    for (std::vector<inode_backpointer_t>::iterator i = backtrace.ancestors.begin();
         i != backtrace.ancestors.end(); ++i) {
      const inode_backpointer_t &backptr = *i;
      dout(10) << "  backptr: 0x" << std::hex << backptr.dirino << std::dec
        << "/" << backptr.dname << dendl;
      
      // TODO handle fragmented directories: if there is a root that
      // contains a valid fragtree, use it to decide where to inject.  Else (the simple
      // case) just always inject into the root.
      
      // Examine root dirfrag for parent
      const inodeno_t parent_ino = backptr.dirino;
      const std::string dname = backptr.dname;
      object_t frag_oid = InodeStore::get_object_name(parent_ino, frag_t(), "");

      // FIXME: in the places we interpret -EINVAL as corrupt, we should
      // special case the situation where the ::decode has found an
      // over-high version number, and definitely *avoid* overwriting
      // it in this case (although it's also possible (indeed likely)
      // that a corrupt entry might just happen to have high bits in
      // the version field, so hmmm...)
      
      // Find or create dirfrag
      // ======================
      fnode_t existing_fnode;
      bool created_dirfrag = false;
      r = read_fnode(parent_ino, frag_t(), &existing_fnode);
      if (r == -ENOENT || r == -EINVAL) {
        // Missing or corrupt fnode, create afresh
        bufferlist fnode_bl;
        fnode_t blank_fnode;
        blank_fnode.version = 1;
        blank_fnode.encode(fnode_bl);
        r = metadata_io.omap_set_header(frag_oid.name, fnode_bl);
        if (r < 0) {
          derr << "Failed to create dirfrag 0x" << std::hex
            << parent_ino << std::dec << " for dentry '"
            << dname << "'" << cpp_strerror(r) << dendl;
          break;
        } else {
          dout(10) << "Created dirfrag: 0x" << std::hex
            << parent_ino << std::dec << dendl;
          created_dirfrag = true;
        }
      } else if (r < 0) {
        derr << "Unexpected error reading dirfrag 0x" << std::hex
          << parent_ino << std::dec << " for dentry '"
          << dname << "': " << cpp_strerror(r) << dendl;
        break;
      } else {
        dout(20) << "Dirfrag already exists: 0x" << std::hex
          << parent_ino << std::dec << dendl;
      }

      // Check if dentry already exists
      // ==============================
      InodeStore existing_dentry;
      std::string key;
      // We have no information about snapshots, so everything goes
      // in as CEPH_NOSNAP
      dentry_key_t dn_key(CEPH_NOSNAP, dname.c_str());
      dn_key.encode(key);
      // TODO: look where the fragtree tells you, not just in the root.
      //       to get the fragtree we will have to read the backtrace
      //       on the dirfrag to learn who the immediate parent of
      //       it is.
      r = read_dentry(parent_ino, frag_t(), key, &existing_dentry);
      bool write_dentry = false;
      if (r == -ENOENT || r == -EINVAL) {
        // Missing or corrupt dentry
        write_dentry = true;
      } else if (r < 0) {
        derr << "Unexpected error reading dentry 0x" << std::hex
          << parent_ino << std::dec << "/"
          << dname << ": " << cpp_strerror(r) << dendl;
        break;
      } else {
        // Dentry already present, does it link to me?
        if (existing_dentry.inode.ino == ino) {
          dout(20) << "Dentry 0x" << std::hex
            << parent_ino << std::dec << "/"
            << dname << " already exists and points to me" << dendl;
        } else {
          // FIXME: at this point we should set a flag to recover
          // this inode in a /_recovery/<inodeno>.data file as we
          // can't recover it into its desired filesystem position.
          derr << "Dentry 0x" << std::hex
            << parent_ino << std::dec << "/"
            << dname << " already exists but points to 0x"
            << std::hex << existing_dentry.inode.ino << std::dec << dendl;
          break;
        }
      }

      // Inject linkage
      // ==============
      if (write_dentry) {
        InodeStore dentry;
        if (i == backtrace.ancestors.begin()) {
          // This is the linkage for a file
          dentry.inode.mode = 0500;
        } else {
          // This is the linkage for a directory
          dentry.inode.mode = 0755 | S_IFDIR;

          // Set nfiles to something non-zero, to fool any other code
          // that tries to ignore 'empty' directories.  This won't be
          // accurate, but it should avoid functional issues.
          dentry.inode.dirstat.nfiles = 1;
          dentry.inode.size = 1;
        }
        dentry.inode.nlink = 1;
        dentry.inode.ino = ino;
        dentry.inode.version = 1;

        // Serialize
        bufferlist dentry_bl;
        snapid_t snap = CEPH_NOSNAP;
        ::encode(snap, dentry_bl);
        ::encode('I', dentry_bl);
        dentry.encode_bare(dentry_bl);

        // Write out
        std::map<std::string, bufferlist> vals;
        vals[key] = dentry_bl;
        r = metadata_io.omap_set(frag_oid.name, vals);
        if (r != 0) {
          derr << "Error writing dentry 0x" << std::hex
            << parent_ino << std::dec << "/"
            << dname << ": " << cpp_strerror(r) << dendl;
          break;
        } else {
          dout(20) << "Injected dentry 0x" << std::hex
            << parent_ino << "/" << dname << " pointing to 0x"
            << dentry.inode.ino << std::dec << dendl;
        }
      }

      if (!created_dirfrag) {
        // If the parent dirfrag already existed, then stop traversing the
        // backtrace: assume that the other ancestors already exist too.  This
        // is an assumption rather than a truth, but it's a convenient way
        // to avoid the risk of creating multiply-linked directories while
        // injecting data.  If there are in fact missing ancestors, this
        // should be fixed up using a separate tool scanning the metadata
        // pool.
        break;
      } else {
        // Proceed up the backtrace, creating parents
        ino = parent_ino;
      }

      // TODO ensure that injected inode has layout pointing to this pool (if
      // none of its ancestor layouts does)
      
      // TODO handle backtraces pointing to stray dirs of MDS ranks that
      // don't exist

      // TODO handle strays in general: if something was stray but had
      // hard links, we can't know its linked name, but we can shove it
      // some recovery directory.
      
      // TODO for objects with no backtrace, OPTIONALLY (don't do it by
      // default) write them a /_recovered/<inodeno>.data backtrace and
      // link them in there.  In general backtrace-less objects are
      // just journalled metadata that hasn't landed yet, we should only
      // override that if we are explicitly told to, or if a full
      // forward scrub has failed to tag them.

      // TODO scan objects for size of recovered inode.  We can either
      // do this inline here, OR we can rely on a full scan also
      // touching all other objects, and updating max size of inode
      // every time we see it (but that gets complicated with multiple
      // workers).  Maybe also a fast path for <4MB objects that sets size
      // to the size of the 0000th object when that size is <4MB.  More generally,
      // we could do this in an initial pass that just looks at all objects,
      // and sets an xattr on the 0000th object (including creating it if necessary)
      // to the maximum seen (may need a special RADOS op to do a "set if greater"
      // xattr write)
    }
  }

  /*
   * Test workload notes:
   *  * Snapshots!
   *  * Moved subdirs (i.e. out of date backtraces)
   *  * Newly created files in moved subdirs (i.e. new files BTs will
   *    disagree with old files BTs about the full path to the subdir
   *    that got moved)
   *  * Sparse files (i.e. with missing objects)
   *  * Missing 0000th objects (i.e. only trailing data objects)
   *  * A dentry that points to B, while a backtrace for A claims that it
   *    belongs in the same dentry name.
   */

  return 0;
}

int DataScan::read_fnode(inodeno_t ino, frag_t frag, fnode_t *fnode)
{
  assert(fnode != NULL);

  object_t frag_oid = InodeStore::get_object_name(ino, frag, "");
  bufferlist old_fnode_bl;
  int r = metadata_io.omap_get_header(frag_oid.name, &old_fnode_bl);
  if (r < 0) {
    return r;
  }

  bufferlist::iterator old_fnode_iter = old_fnode_bl.begin();
  try {
    fnode_t old_fnode;
    old_fnode.decode(old_fnode_iter);
  } catch (const buffer::error &err) {
    return -EINVAL;
  }

  return 0;
}

int DataScan::read_dentry(inodeno_t parent_ino, frag_t frag,
                const std::string &key, InodeStore *inode)
{
  assert(inode != NULL);

  std::set<std::string> keys;
  keys.insert(key);
  std::map<std::string, bufferlist> vals;
  object_t frag_oid = InodeStore::get_object_name(parent_ino, frag, "");
  int r = metadata_io.omap_get_vals_by_keys(frag_oid.name, keys, &vals);  
  assert (r == 0);  // I assume success because I checked object existed
  if (vals.find(key) == vals.end()) {
    return -ENOENT;
  }

  try {
    bufferlist::iterator q = vals[key].begin();
    inode->decode_bare(q);
  } catch (const buffer::error &err) {
    return -EINVAL;
  }

  return 0;
}

