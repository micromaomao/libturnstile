#!/usr/bin/env fish
#
# Turnstile shell integration for Fish.
#
# # Usage
#
# Add this to your ~/.config/fish/config.fish:
#
#   source (turnstile-sandbox --print-shell-hook | psub)
#
# Select the config used to sandbox commands in the current shell:
#
#   tscfg path/to/config.yaml
#
# Run `tscfg --clear` to stop sandboxing commands. Sandboxing is disabled
# until a config is selected.
#
# You can use $_CURRENT_TURNSTILE_CONFIG in your prompt to display the active
# Turnstile config, or just to indicate whether sandboxing is enabled. For
# example:
#
# functions --copy fish_prompt _orig_fish_prompt
# function fish_prompt
#     if test -n "$_CURRENT_TURNSTILE_CONFIG"
#         echo -sn (set_color blue) "turnstile: " \
#             "$_CURRENT_TURNSTILE_CONFIG" " "
#     end
#     _orig_fish_prompt
# end
#
# # Goal
#
# Transparently sandbox commands (e.g., `ls`, `make`) with the selected
# Turnstile config, without changing the user experience.
#
# # Features
# - Pipeline support (sandboxes `date` and `head` in `date | head`).
# - Command chaining support (sandboxes `ls` and `echo` in `ls && echo
#   done` and its variants).
# - Idempotency: This script is safe to source multiple times.
#
# # Limitations
#
# - No handling of command substitutions.
#
# - Since aliases are defined as functions in fish, they are not easy to
#   resolve automatically. For alias-like behavior, use `abbr` instead,
#   which will automatically expand before execution.
#
# - No support for functions. This includes things like the built-in `ls`
#   and `ll`, `man`, etc. (They will still work, but won't be sandboxed.)
#
# - fish functions does not support streaming output when inside a
#   pipeline (all outputs are buffered and printed at once at exit) [1][2].
#   This means that with this hook, a command like
#
#     base64 /dev/urandom | head
#
#   will show nothing and eventually run out of memory, since `base64`
#   (and `head`) is redefined to be a function. `nosandbox` does not help
#   here. To work around this, use `command` on either side:
#
#     command base64 /dev/urandom | head
#     base64 /dev/urandom | command head
#
#   Alternatively, to still sandbox both ends of the pipe, manually start
#   a one-off shell:
#
#     fish -c 'base64 /dev/urandom | head'
#
#  [1]: https://github.com/fish-shell/fish-shell/issues/1396
#  [2]: https://github.com/fish-shell/fish-shell/issues/5635
#
# # Note
# - Fish has no ${(z)BUFFER} equivalent (`commandline --tokens-expanded` /
#   `commandline -o` drops operators), and so this file implements a
#   best-effort parser to handle quoted strings, operators, etc.

# Ensure clean state if re-sourced.
if functions -q _turnstile_unhook
    _turnstile_unhook
end

set -g _CURRENT_TURNSTILE_CONFIG ""

function tscfg
    if test (count $argv) -eq 1; and test "$argv[1]" = "--clear"
        set -g _CURRENT_TURNSTILE_CONFIG ""
        return 0
    end
    if test (count $argv) -ne 1
        echo "usage: tscfg <file> | tscfg --clear" >&2
        return 2
    end
    set -l config (path resolve -- $argv[1]); or return
    set -g _CURRENT_TURNSTILE_CONFIG $config
end
complete -c tscfg -l clear -d "Stop sandboxing commands"

function nosandbox
    if test (count $argv) -eq 0
        return 0
    end
    command $argv
end
complete -c nosandbox -w command

function _turnstile_wrap_cmd --argument-names cmd
    if test -z "$cmd"; or test "$cmd" = "turnstile-sandbox"
        return
    end

    set -l cmd_type (type -t -- $cmd 2>/dev/null)
    if test "$cmd_type" = "function" -o "$cmd_type" = "builtin" -o "$cmd_type" = ""
        return
    end

    if set -q _TURNSTILE_WRAPPED_CMDS[1]
        if contains -- $cmd $_TURNSTILE_WRAPPED_CMDS
            return
        end
    end

    set -l escaped (string escape -- $cmd)
    eval "
    function $escaped --wraps $escaped
        command turnstile-sandbox \$_CURRENT_TURNSTILE_CONFIG --default-config --qt-prompter -- $escaped \$argv
    end
    "
    if test $status -ne 0
        return 1
    end

    set -g _TURNSTILE_WRAPPED_CMDS $cmd $_TURNSTILE_WRAPPED_CMDS
end

function _turnstile_accept_line
    commandline --is-valid
    if test $status -ne 0
        return
    end

    if test -z "$_CURRENT_TURNSTILE_CONFIG"
        return
    end

    if set -q _TURNSTILE_WRAPPED_CMDS[1]
        for cmd in $_TURNSTILE_WRAPPED_CMDS
            functions -e -- $cmd
        end
    end
    set -g _TURNSTILE_WRAPPED_CMDS

    set -l input_lines (commandline --current-buffer)

    for line in $input_lines
        if abbr --query "$line" >/dev/null 2>&1
            commandline --function expand-abbr repaint
            return 1
        end
    end

    if commandline --paging-mode
        return
    end

    set -l output_lines
    set -l curr_line_out ""
    set -l curr_token ""
    set -l expecting_cmd 1
    set -l in_squote 0
    set -l in_dquote 0
    set -l escaped 0
    set -l modified 0
    set -l curr_cmd_nosandbox 0
    set -l escaped_config (string escape -- $_CURRENT_TURNSTILE_CONFIG)

    function _turnstile_append_token_to_out --no-scope-shadowing
        set curr_line_out "$curr_line_out$curr_token"
        set curr_token ""
    end

    function _turnstile_process_curr_token --no-scope-shadowing
        if test -z "$curr_token"
            return
        end

        set -l unescaped (string unescape -- "$curr_token")

        if test $expecting_cmd -eq 1
            if test "$unescaped" = "nosandbox"
                set curr_cmd_nosandbox 1
                _turnstile_append_token_to_out
                return
            end

            if string match -qr '^[A-Za-z_][A-Za-z0-9_]*[+]?=.*' -- $curr_token
                _turnstile_append_token_to_out
                return
            end

            if test "$unescaped" = "and" -o "$unescaped" = "or"
                _turnstile_append_token_to_out
                return
            end

            set expecting_cmd 0

            if test $curr_cmd_nosandbox -eq 1
                _turnstile_append_token_to_out
                set curr_cmd_nosandbox 0
                return
            end

            if string match -qr '/' -- "$unescaped"
                set curr_line_out "$curr_line_out""turnstile-sandbox $escaped_config --default-config --qt-prompter -- $curr_token"
                set curr_token ""
                set modified 1
                return
            end

            _turnstile_wrap_cmd "$unescaped"
            if test $status -ne 0
                set curr_line_out "$curr_line_out""turnstile-sandbox $escaped_config --default-config --qt-prompter -- $curr_token"
                set curr_token ""
                set modified 1
                return
            end

            _turnstile_append_token_to_out
        else
            _turnstile_append_token_to_out
        end
    end

    for line in $input_lines
        set -l i 1
        set -l len (string length -- $line)
        while test $i -le $len
            set -l ch (string sub -s $i -l 1 -- $line)

            if test $escaped -eq 1
                set curr_token "$curr_token$ch"
                set escaped 0
                set i (math $i + 1)
                continue
            end

            if test "$ch" = "\\"
                set escaped 1
                set curr_token "$curr_token$ch"
                set i (math $i + 1)
                continue
            end

            if test $in_squote -eq 1
                if test "$ch" = "'"
                    set in_squote 0
                end
                set curr_token "$curr_token$ch"
                set i (math $i + 1)
                continue
            end

            if test $in_dquote -eq 1
                if test "$ch" = '"'
                    set in_dquote 0
                end
                set curr_token "$curr_token$ch"
                set i (math $i + 1)
                continue
            end

            if test "$ch" = "'"
                set in_squote 1
                set i (math $i + 1)
                set curr_token "$curr_token$ch"
                continue
            end

            if test "$ch" = '"'
                set in_dquote 1
                set i (math $i + 1)
                set curr_token "$curr_token$ch"
                continue
            end

            if test "$ch" = "#"
                _turnstile_process_curr_token
                set remaining (string sub -s $i -- $line)
                set curr_line_out "$curr_line_out$remaining"
                set i (math $len + 1)
                break
            end

            set -l remaining (string sub -s $i -- $line)
            set -l sep_len 0
            set -l sep_value ""
            set -l separator_specs \
                "^;" \
                "^&&" \
                "^&\\|" \
                "^&" \
                "^\\|\\|" \
                "^\\|" \
                "^\\d+>\\|"

            for spec in $separator_specs
                set -l m (string match -r -- $spec $remaining)
                if test (count $m) -gt 0
                    set sep_value $m[1]
                    set sep_len (string length -- $sep_value)
                    break
                end
            end

            if test $sep_len -gt 0
                _turnstile_process_curr_token
                set expecting_cmd 1
                set curr_cmd_nosandbox 0
                set curr_line_out "$curr_line_out$sep_value"
                set i (math $i + $sep_len)
                continue
            end

            set -l redir (string match -r -- "^(>>|<<|>|<)" $remaining)
            if test (count $redir) -gt 0
                _turnstile_process_curr_token
                set curr_line_out "$curr_line_out$redir[1]"
                set i (math $i + (string length -- $redir[1]))
                continue
            end

            if string match -qr '^[ \t]$' -- $ch
                _turnstile_process_curr_token
                set curr_line_out "$curr_line_out$ch"
                set i (math $i + 1)
                continue
            end

            set i (math $i + 1)
            set curr_token "$curr_token$ch"
        end

        _turnstile_process_curr_token
        set output_lines $output_lines $curr_line_out
        set curr_line_out ""
        set expecting_cmd 1
        set curr_cmd_nosandbox 0
    end

    if test $modified -eq 1
        commandline --replace -- $output_lines
    end
end

function _turnstile_accept_line_normal
    _turnstile_accept_line
    if test $status -ne 0
        return
    end
    if set -q _turnstile_orig_accept_line_normal
        eval "$_turnstile_orig_accept_line_normal"
    else
        commandline --function execute
    end
end

function _turnstile_accept_line_vi
    _turnstile_accept_line
    if test $status -ne 0
        return
    end
    if set -q _turnstile_orig_accept_line_vi
        eval "$_turnstile_orig_accept_line_vi"
    else
        commandline --function execute
    end
end

function _turnstile_precmd --on-event fish_prompt
    if not set -q _TURNSTILE_WRAPPED_CMDS[1]
        return 0
    end
    for cmd in $_TURNSTILE_WRAPPED_CMDS
        functions -e -- $cmd
    end
    set -e _TURNSTILE_WRAPPED_CMDS
end

function _turnstile_unhook
    bind --erase \r
    bind -M insert --erase \r
    if set -q _turnstile_orig_accept_line_normal
        bind \r $_turnstile_orig_accept_line_normal
        set -e _turnstile_orig_accept_line_normal
    end
    if set -q _turnstile_orig_accept_line_vi
        bind -M insert \r $_turnstile_orig_accept_line_vi
        set -e _turnstile_orig_accept_line_vi
    end

    if functions -q _turnstile_precmd
        _turnstile_precmd
    end

    functions -e _turnstile_accept_line
    functions -e _turnstile_accept_line_normal
    functions -e _turnstile_accept_line_vi
    functions -e _turnstile_precmd
    functions -e _turnstile_unhook
    functions -e _turnstile_wrap_cmd
    functions -e nosandbox
    functions -e tscfg

    set -e _CURRENT_TURNSTILE_CONFIG
    set -e _TURNSTILE_WRAPPED_CMDS
    complete -c nosandbox --erase
    complete -c tscfg --erase
end

if status is-interactive
    set -l old_bind (bind --user \r 2>/dev/null)
    set -l match (string match -r '^bind enter ([a-zA-Z0-9_-]+)$' -- $old_bind)
    if test (count $match) -eq 2
        set -g _turnstile_orig_accept_line_normal $match[2]
    else
        set -e _turnstile_orig_accept_line_normal
    end

    set -l old_bind (bind --user -M insert \r 2>/dev/null)
    set -l match (string match -r '^bind -M insert enter ([a-zA-Z0-9_-]+)$' -- $old_bind)
    if test (count $match) -eq 2
        set -g _turnstile_orig_accept_line_vi $match[2]
    else
        set -e _turnstile_orig_accept_line_vi
    end

    bind \r _turnstile_accept_line_normal
    bind -M insert \r _turnstile_accept_line_vi
end
