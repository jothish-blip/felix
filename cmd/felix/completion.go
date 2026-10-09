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
    $commands = @('scan', 'report', 'client', 'assessment', 'config', 'doctor', 'version', 'update', 'install', 'uninstall', 'completion', 'help')
    $flags = @('--export', '--json', '--timeout', '-t', '--concurrency', '-c', '--scope', '--max-assets', '--max-response-size', '--quiet', '-q', '--verbose', '-v', '-l', '--user-agent', '--check', '--force', '--dry-run', '--client', '--name', '--target', '--authorizer', '--role', '--reference', '--valid-days')
    
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
    commands="scan report client assessment config doctor version update install uninstall completion help"
    flags="--export --json --timeout -t --concurrency -c --scope --max-assets --max-response-size --quiet -q --verbose -v -l --user-agent --check --force --dry-run --client --name --target --authorizer --role --reference --valid-days"

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
        'client:Manage clients and organizations for structured assessments'
        'assessment:Manage authorized security assessment projects and runs'
        'config:Manage Felix operational settings'
        'doctor:Diagnose Felix runtime and installation health'
        'version:Show Felix version and build details'
        'update:Check for or install verified updates from official releases'
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
                '--export[Export assessment report]' \
                '--json[Save or output JSON result]' \
                '--timeout[Request timeout]' \
                '-t[Request timeout]' \
                '--concurrency[Worker count]' \
                '-c[Worker count]' \
                '--scope[Crawl scope]' \
                '--quiet[Suppress output]' \
                '-q[Suppress output]' \
                '--verbose[Detailed output]' \
                '-v[Detailed output]' \
                '--check[Check for updates only]' \
                '--force[Force installation]' \
                '--client[Client reference or ID]' \
                '--name[Assessment or client name]'
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
complete -c felix -n "__fish_use_subcommand" -a "client" -d "Manage clients and organizations"
complete -c felix -n "__fish_use_subcommand" -a "assessment" -d "Manage authorized assessments"
complete -c felix -n "__fish_use_subcommand" -a "config" -d "Manage operational settings"
complete -c felix -n "__fish_use_subcommand" -a "doctor" -d "Diagnose runtime health"
complete -c felix -n "__fish_use_subcommand" -a "version" -d "Show version information"
complete -c felix -n "__fish_use_subcommand" -a "update" -d "Check for or install updates"
complete -c felix -n "__fish_use_subcommand" -a "completion" -d "Generate shell completion"
complete -c felix -n "__fish_use_subcommand" -a "help" -d "Show help"
`)
		return 0

	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell %q. Available: powershell, bash, zsh, fish\n", shell)
		return 2
	}
}
