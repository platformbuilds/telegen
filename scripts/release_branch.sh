# scripts/release_branch.sh
set -euo pipefail
ver="$1"  # e.g. 1-2-3
branch="release/mark-v${ver}"
git checkout main
git pull --ff-only
git checkout -b "$branch"
# (Optionally bump a VERSION file or changelog here)
git commit --allow-empty -m "chore(release): start ${branch}"
git push -u origin "$branch"
echo "Opened ${branch}"
