#!/usr/bin/env bash
set -euo pipefail

err() {
    >&2 echo "$@"
}

usage() {
    err "usage: $1 ThePathOfYourOpenRestySrcDirectory"
    exit 1
}

failed_to_cd() {
    err "failed to cd $1"
    exit 1
}

apply_patch() {
    patch_dir="$1"
    root="$2"
    repo="$3"
    ver="$4"

    dir="$root/bundle/$repo-$ver"
    pushd "$dir" || failed_to_cd "$dir"
    for patch in "$patch_dir/$repo"-*.patch; do
        echo "Start to patch $patch to $dir..."
        patch -p0 --verbose < "$patch"
    done
    popd
}

if [[ $# != 1 ]]; then
    usage "$0"
fi

root="$1"
if [[ "$root" == *openresty-1.19.3.* ]]; then
    patch_dir="$PWD/1.19.3"
    apply_patch "$patch_dir" "$root" "nginx" "1.19.3"
    apply_patch "$patch_dir" "$root" "lua-resty-core" "0.1.21"
    apply_patch "$patch_dir" "$root" "ngx_lua" "0.10.19"
    apply_patch "$patch_dir" "$root" "ngx_stream_lua" "0.0.9"
elif [[ "$root" == *openresty-1.19.9.* ]]; then
    patch_dir="$PWD/1.19.9"
    apply_patch "$patch_dir" "$root" "nginx" "1.19.9"
    apply_patch "$patch_dir" "$root" "lua-resty-core" "0.1.22"
    apply_patch "$patch_dir" "$root" "ngx_lua" "0.10.20"
    apply_patch "$patch_dir" "$root" "ngx_stream_lua" "0.0.10"
    apply_patch "$patch_dir" "$root" "LuaJIT-2.1" "20210510"
elif [[ "$root" == *openresty-1.21.4.1 ]]; then
      patch_dir="$PWD/1.21.4.1"
      apply_patch "$patch_dir" "$root" "nginx" "1.21.4"
      apply_patch "$patch_dir" "$root" "lua-resty-core" "0.1.23"
      apply_patch "$patch_dir" "$root" "ngx_lua" "0.10.21"
      apply_patch "$patch_dir" "$root" "ngx_stream_lua" "0.0.11"
elif [[ "$root" == *openresty-1.21.4.* ]]; then
      patch_dir="$PWD/1.21.4"
      apply_patch "$patch_dir" "$root" "nginx" "1.21.4"
      apply_patch "$patch_dir" "$root" "lua-resty-core" "0.1.27"
      apply_patch "$patch_dir" "$root" "ngx_lua" "0.10.25"
      apply_patch "$patch_dir" "$root" "ngx_stream_lua" "0.0.13"
elif [[ "$root" == *openresty-1.25.3.1 ]]; then
      patch_dir="$PWD/1.25.3.1"
      apply_patch "$patch_dir" "$root" "nginx" "1.25.3"
      apply_patch "$patch_dir" "$root" "lua-resty-core" "0.1.28"
      apply_patch "$patch_dir" "$root" "ngx_lua" "0.10.26"
      apply_patch "$patch_dir" "$root" "ngx_stream_lua" "0.0.14"
else
    err "can't detect OpenResty version"
    exit 1
fi
