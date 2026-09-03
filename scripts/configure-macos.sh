#!/bin/zsh
set -eu

config_file=${ARCHERY_CONFIG_FILE:-$HOME/.config/archery-sql-skills/config.json}
if [[ ! -f "$config_file" ]]; then
  print -u2 "Config file not found: $config_file"
  print -u2 "Create it from config.example.json before configuring credentials."
  exit 2
fi

set_secret() {
  local variable_name=$1
  local prompt=$2
  local secret_value
  read -r -s "secret_value?$prompt: "
  print
  if [[ -z "$secret_value" ]]; then
    print -u2 "$variable_name cannot be empty"
    exit 2
  fi
  launchctl setenv "$variable_name" "$secret_value"
  unset secret_value
  print "Configured $variable_name"
}

launchctl setenv ARCHERY_CONFIG_FILE "$config_file"
print "Configured ARCHERY_CONFIG_FILE"
set_secret ARCHERY_USERNAME "Query/submission username"
set_secret ARCHERY_PASSWORD "Query/submission password"
set_secret ARCHERY_REVIEW_USERNAME "Reviewer username"
set_secret ARCHERY_REVIEW_PASSWORD "Reviewer password"
set_secret ARCHERY_EXECUTE_USERNAME "Executor username"
set_secret ARCHERY_EXECUTE_PASSWORD "Executor password"
set_secret ARCHERY_EXECUTE_CONFIRM_TOKEN "Execution confirmation token"

print "Environment configured for the current macOS login session."
