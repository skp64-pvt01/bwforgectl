# bash completion for the Bitwarden CLI (bw)
#
# Install:
#   source bw-bash-completion.bash
# or copy/symlink into your bash completion directory, e.g.:
#   /etc/bash_completion.d/bw
#   ~/.local/share/bash-completion/completions/bw

_bw() {
  local cur prev words cword
  if declare -F _init_completion >/dev/null 2>&1; then
    _init_completion -n : || return
  else
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    words=("${COMP_WORDS[@]}")
    cword=$COMP_CWORD
  fi

  # Global options available everywhere.
  local global_opts="--pretty --raw --response --cleanexit --quiet \
    --nointeraction --session -v --version -h --help"

  # Top-level commands.
  local commands="sdk-version login logout lock unlock sync generate encode \
    config update completion status list get create edit delete restore move \
    confirm import export share archive send receive device-approval serve"

  # Locate the first non-option word (the command) after "bw".
  local i cmd="" cmd_index=-1
  for (( i=1; i < cword; i++ )); do
    case "${words[i]}" in
      -*) ;;
      *)
        cmd="${words[i]}"
        cmd_index=$i
        break
        ;;
    esac
  done

  # No command yet: complete top-level commands and global options.
  if [[ -z "$cmd" ]]; then
    if [[ "$cur" == -* ]]; then
      COMPREPLY=( $(compgen -W "$global_opts" -- "$cur") )
    else
      COMPREPLY=( $(compgen -W "$commands $global_opts" -- "$cur") )
    fi
    return 0
  fi

  # Per-command option sets.
  local opts=""
  case "$cmd" in
    login)
      opts="--method --code --sso --apikey --passwordenv --passwordfile --check"
      ;;
    unlock)
      opts="--check --passwordenv --passwordfile"
      ;;
    sync)
      opts="-f --force --last"
      ;;
    generate)
      opts="-u --uppercase -l --lowercase -n --number -s --special \
        -p --passphrase --length --words --minNumber --minSpecial --separator \
        -c --capitalize --includeNumber --ambiguous"
      ;;
    config)
      opts="--web-vault --api --identity --icons --notifications --events \
        --key-connector"
      ;;
    completion)
      opts="--shell"
      ;;
    list)
      opts="--search --url --folderid --collectionid --organizationid --trash \
        --archived"
      ;;
    get)
      opts="--itemid --output --organizationid"
      ;;
    create)
      opts="--file --itemid --organizationid"
      ;;
    edit)
      opts="--organizationid"
      ;;
    delete)
      opts="--itemid --organizationid -p --permanent"
      ;;
    confirm)
      opts="--organizationid"
      ;;
    import)
      opts="--formats --organizationid"
      ;;
    export)
      opts="--output --format --password --organizationid"
      ;;
    serve)
      opts="--hostname --port --disable-origin-protection"
      ;;
    send)
      opts="-f --file -d --deleteInDays --password --emails -a --maxAccessCount \
        --hidden -n --name --notes --fullObject"
      ;;
    receive)
      opts="--password --passwordenv --passwordfile --obj --output"
      ;;
    sdk-version|logout|lock|encode|update|status|restore|move|share|archive)
      opts=""
      ;;
  esac

  # Sub-commands for commands that have them.
  local subcommands=""
  case "$cmd" in
    send)
      subcommands="list template get receive create edit remove-password delete"
      ;;
    device-approval)
      subcommands="list approve approve-all deny deny-all"
      ;;
  esac

  # Handle commands with sub-commands (send, device-approval).
  if [[ -n "$subcommands" ]]; then
    # Find the sub-command after the command.
    local sub="" sub_index=-1
    for (( i=cmd_index+1; i < cword; i++ )); do
      case "${words[i]}" in
        -*) ;;
        *)
          sub="${words[i]}"
          sub_index=$i
          break
          ;;
      esac
    done

    if [[ -z "$sub" ]]; then
      # Complete sub-commands (and the command's own options for send).
      if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts $global_opts" -- "$cur") )
      else
        COMPREPLY=( $(compgen -W "$subcommands $opts $global_opts" -- "$cur") )
      fi
      return 0
    fi

    # We have a sub-command: complete its specific options.
    local subopts=""
    case "$cmd $sub" in
      "send get")
        subopts="--output --text"
        ;;
      "send receive")
        subopts="--password --passwordenv --passwordfile --obj --output"
        ;;
      "send create")
        subopts="--file --text --hidden"
        ;;
      "send edit")
        subopts="--itemid"
        ;;
      "send list"|"send template"|"send remove-password"|"send delete")
        subopts=""
        ;;
      "device-approval list"|"device-approval approve"|"device-approval approve-all"|"device-approval deny"|"device-approval deny-all")
        subopts="--organizationid"
        ;;
    esac

    COMPREPLY=( $(compgen -W "$subopts $global_opts" -- "$cur") )
    return 0
  fi

  # Regular command: complete its options plus global options.
  COMPREPLY=( $(compgen -W "$opts $global_opts" -- "$cur") )
  return 0
}

complete -F _bw bw
