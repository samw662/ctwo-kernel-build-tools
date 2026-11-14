# ctwo kernel build tools

Build scripts for the motorola edge 50 ultra (ctwo) kernel. This handles the whole build, external modules and boot + vendor_boot + vendor_dlkm + system_dlkm packaging

## How to merge this?

- cd /path/to/kernel

- git remote add ctwo-tools <repo-url>
- git fetch ctwo-tools
- git merge --allow-unrelated-histories ctwo-tools/main
