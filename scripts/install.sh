#!/bin/sh
set -eu

usage() {
  echo "Usage: $0 claude|codex|all" >&2
  exit 2
}

repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

install_into() {
  destination=$1
  mkdir -p "$destination"
  for source in "$repository_dir"/skills/*; do
    skill_name=$(basename "$source")
    mkdir -p "$destination/$skill_name"
    cp -R "$source/." "$destination/$skill_name/"
    echo "Installed $skill_name into $destination"
  done
}

[ "$#" -eq 1 ] || usage
case "$1" in
  claude)
    install_into "${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
    ;;
  codex)
    install_into "${CODEX_SKILLS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills}"
    ;;
  all)
    install_into "${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
    install_into "${CODEX_SKILLS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills}"
    ;;
  *)
    usage
    ;;
esac
