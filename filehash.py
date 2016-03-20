import binascii
import hashlib
import json
import os
import stat
import sys

def hash_file(path):
    """Return sha1 hash of the file at the given path"""
    print "hashing file:", path
    hash = hashlib.sha1()
    with open(path, "rb") as f:
        hash.update(f.read(1024))
    return hash.digest()

def map_file_tree(path, mapping = None):
    """Create hash and modify-time mapping for a file tree

    'mapping' is a dictionairy mapping file names to a tuple of
    last-modified-time and sha1 hash of the file. This function
    walks the tree at the given 'path' and inserts or updates
    mappings for all regular files in the tree."""
    for path, subdirs, files in os.walk(path):
        for f in files:
            filepath = os.path.abspath(os.path.join(path, f).decode("utf8"))
            statInfo = os.lstat(filepath)
            if not stat.S_ISREG(statInfo.st_mode):
                #print "Skipping non-regular file:", filepath
                continue
            timestamp = statInfo.st_mtime
            if mapping is None:
                hash = hash_file(filepath)
            elif (filepath in mapping) and mapping[filepath][0] == timestamp:
                # temporarily unhexlify the hash so it can be written
                hash = binascii.unhexlify(mapping[filepath][1])
            else:
                hash = hash_file(filepath)
                # temporarily hexlify the hash so it can be written
                mapping[filepath] = timestamp, binascii.hexlify(hash)
            #print binascii.hexlify(hash), timestamp, filepath

if __name__ == "__main__":
    mapping = dict()
    if len(sys.argv) > 1:
        try:
            with open(sys.argv[2], "rb") as indexFile:
                mapping = json.load(indexFile)
        except IOError:
            # Index file doesn't exist yet: we'll write one later
            pass

    # TODO: remove mappings for deleted files
    map_file_tree(sys.argv[1], mapping)

    if len(sys.argv) > 1:
        with open(sys.argv[2], "wb") as indexFile:
            json.dump(mapping, indexFile, indent = 4)
    #print "Hash: ", binascii.hexlify(filehash(sys.argv[1]))
