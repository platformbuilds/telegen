set -euo pipefail
ver="$1" # 1-2-3
tag="mark-v${ver}"
git fetch --all --tags
git checkout "release/${tag}"
git pull --ff-only
git tag -a "${tag}" -m "Release ${tag}"
git push origin "${tag}"
echo "Tagged ${tag}"
