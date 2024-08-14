#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <source_directory> <destination_directory>"
    exit 1
fi


src_dir="$1"
dest_dir="$2"

echo "Jack Running rsync from $src_dir to $dest_dir"
rsync -av --delete --exclude '.git' --exclude 'node_modules' --exclude 'frontend/node_modules' "$src_dir/" "$dest_dir/"