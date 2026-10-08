package main

import (
	"fmt"
	"os"
	"strings"
)

func runCompletion(args []string) int {
	shell := "powershell"
	if len(args) > 0 {
		shell = strings.ToLower(args[0])
	}

	switch shell {
	case "powershell", "ps1":
		fmt.Print(`
# PowerShell completion for Felix
Register-ArgumentCompleter -Native -CommandName felix -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $commands = @('scan', 'report', 'config', 'doctor', 'version', 'install', 'uninstall', 'completion', 'help')
    $flags = @('--html', '--json', '--out', '-c', '-t', '--max-size', '--scope', '--user-agent', '-v', '-l')
    
    if ($commandAst.ToString() -notmatch ' ') {
        $commands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    } else {
        $flags | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterName', $_)
        }
    }
}
`)
		return 0

	case "bash":
		fmt.Print(`
# Bash completion for Felix
_felix_completions() {
    local cur prev commands flags
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="scan report config doctor version install uninstall completion help"
    flags="--html --json --out -c -t --max-size --scope --user-agent -v -l"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${flags}" -- ${cur}) )
        return 0
    fi
}
complete -F _felix_completions felix
`)
		return 0

	case "zsh":
		fmt.Print(`
# Zsh completion for Felix
#compdef felix

_felix() {
    local -a commands
    commands=(
        'scan:Perform a web security audit against target'
        'report:Generate reports from an existing scan result without rescanning'
        'config:Manage Felix operational settings'
        'doctor:Diagnose Felix runtime and installation health'
        'version:Show Felix version and build details'
        'install:Install Felix binary to user environment'
        'uninstall:Remove Felix binary and user environment settings'
        'completion:Generate shell autocomplete script'
        'help:Show help information'
    )
    _arguments \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            _describe -t commands 'felix commands' commands
            ;;
        args)
            _arguments \
                '--html[Export HTML report]' \
                '--json[Export JSON report]' \
                '--out[Save scan result]' \
                '-c[Concurrency]' \
                '-t[Timeout seconds]' \
                '-v[Verbose output]'
            ;;
    esac
}
_felix "$@"
`)
		return 0

	case "fish":
		fmt.Print(`
# Fish completion for Felix
complete -c felix -f
complete -c felix -n "__fish_use_subcommand" -a "scan" -d "Perform web security audit"
complete -c felix -n "__fish_use_subcommand" -a "report" -d "Generate report from existing scan result"
complete -c felix -n "__fish_use_subcommand" -a "config" -d "Manage operational settings"
complete -c felix -n "__fish_use_subcommand" -a "doctor" -d "Diagnose runtime health"
complete -c felix -n "__fish_use_subcommand" -a "version" -d "Show version information"
complete -c felix -n "__fish_use_subcommand" -a "completion" -d "Generate shell completion"
complete -c felix -n "__fish_use_subcommand" -a "help" -d "Show help"
`)
		return 0

	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell %q. Available: powershell, bash, zsh, fish\n", shell)
		return 2
	}
}
