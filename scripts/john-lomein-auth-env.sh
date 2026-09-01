#!/usr/bin/env bash
# Normalize john-lomein runtime auth for non-interactive cron/LaunchAgent jobs.
# Source this after john-lomein-instance.env. It must not print secrets.

# Make variables from the sourced instance env visible to child processes that run
# gh/git/python. Plain `KEY=value` assignments in a sourced file are not exported.
for _jl_key in \
  HERMES_HOME HERMES_MANAGED_DIR JOHN_LOMEIN_INSTANCE_HERMES_HOME JOHN_LOMEIN_HERMES_HOME MNEMOSYNE_DATA_DIR \
  HERMES_PYTHON VIRTUAL_ENV HERMES_REAL_HOME JOHN_LOMEIN_AUTH_AUTHORITY_HOME \
  BOT_HERMES_HOME BOT_HERMES_MANAGED_ROOT BOT_MODEL_MEMORY_ISOLATION BOT_STEWARD_PRIVATE_ROOT BOT_STEWARD_PROJECTION_ROOT \
  BOT_MAINTAINER_PROFILE BOT_FORGE_PROFILE BOT_GUIDE_PROFILE BOT_OVERWATCH_PROFILE \
  BOT_LEARNING_STEWARD_PROFILE BOT_MODEL_PROVIDER BOT_FALLBACK_PROVIDER \
  BOT_REPO BOT_DEFAULT_BRANCH BOT_LOCAL BOT_SLUG BOT_DISPLAY_NAME BOT_MUTATION_ENABLED \
  BOT_DISCORD_ENABLED BOT_NOTIFICATIONS_CHANNEL BOT_NOTIFICATION_TARGET GH_TOKEN GITHUB_TOKEN GLM_API_KEY GLM_BASE_URL; do
  if [ "${!_jl_key+x}" = "x" ]; then
    export "${_jl_key?}"
  fi
done

# Never let background jobs open interactive GitHub prompts.
export GH_PROMPT_DISABLED=1
export GH_NO_UPDATE_NOTIFIER=1
export GH_NO_EXTENSION_UPDATE_NOTIFIER=1

# Prefer the profile-local gh config that repair-profile-gh-auth.py writes. This
# contains the GitHub token in the instance profile's private config directory,
# so `gh` and `git` credential helper calls do not reach macOS Keychain.
if [ -n "${BOT_HERMES_HOME:-}" ] && [ -z "${GH_CONFIG_DIR:-}" ]; then
  _jl_gh_profile="${JOHN_LOMEIN_GH_PROFILE:-${BOT_MAINTAINER_PROFILE:-john-lomein-maintainer}}"
  _jl_gh_config="$BOT_HERMES_HOME/profiles/$_jl_gh_profile/home/.config/gh"
  if [ -d "$_jl_gh_config" ]; then
    export GH_CONFIG_DIR="$_jl_gh_config"
  fi
fi

# Prefer the Hermes venv Python for runtime scripts that use Hermes-adjacent
# dependencies such as Mnemosyne. This keeps cron/LaunchAgent jobs from falling
# back to macOS system Python, where PyYAML or Mnemosyne may be missing.
if [ -n "${HERMES_PYTHON:-}" ] && [ -x "$HERMES_PYTHON" ]; then
  _jl_python_dir="$(dirname "$HERMES_PYTHON")"
  export PATH="$_jl_python_dir:$PATH"
fi

# Avoid leaking helper-local variables to children.
unset _jl_key _jl_gh_profile _jl_gh_config _jl_python_dir
