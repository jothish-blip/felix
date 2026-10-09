package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"felix/pkg/assessment"
	"github.com/google/uuid"
)

func runClient(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printClientHelp()
		return 0
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "add":
		return runClientAdd(subArgs)
	case "list":
		return runClientList(subArgs)
	case "show":
		return runClientShow(subArgs)
	case "archive":
		return runClientArchive(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown client subcommand: %s\n\n", sub)
		printClientHelp()
		return 2
	}
}

func printClientHelp() {
	fmt.Println("Usage: felix client <subcommand> [flags]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  add       Register a new client")
	fmt.Println("  list      List registered clients")
	fmt.Println("  show      Display detailed client profile and assessments")
	fmt.Println("  archive   Archive a client record")
	fmt.Println("\nFlags for 'add':")
	fmt.Println("  --name <string>           Client organization or entity name (required)")
	fmt.Println("  --org <string>            Formal organization title")
	fmt.Println("  --contact-name <string>   Primary security contact person")
	fmt.Println("  --contact-email <string>  Contact email address")
	fmt.Println("  --notes <string>          Internal operational notes")
	fmt.Println("  --json                    Output newly created record as JSON")
	fmt.Println("\nFlags for 'list':")
	fmt.Println("  --all                     Include archived clients")
	fmt.Println("  --json                    Output client list as JSON")
	fmt.Println("\nExamples:")
	fmt.Println("  felix client add --name \"Acme Corp\" --notes \"Enterprise Tier\"")
	fmt.Println("  felix client list")
	fmt.Println("  felix client show <client-id>")
	fmt.Println("  felix client archive <client-id>")
}

func runClientAdd(args []string) int {
	var (
		name         string
		org          string
		contactName  string
		contactEmail string
		notes        string
		jsonOutput   bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--name", "-n":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "--org", "--organization":
			if i+1 < len(args) {
				org = args[i+1]
				i++
			}
		case "--contact-name":
			if i+1 < len(args) {
				contactName = args[i+1]
				i++
			}
		case "--contact-email":
			if i+1 < len(args) {
				contactEmail = args[i+1]
				i++
			}
		case "--notes":
			if i+1 < len(args) {
				notes = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printClientHelp()
			return 0
		}
	}

	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: --name is required to create a client\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	c := &assessment.Client{
		ID:           uuid.New().String(),
		Name:         name,
		Organization: org,
		ContactName:  contactName,
		ContactEmail: contactEmail,
		Notes:        notes,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		Archived:     false,
	}

	if err := store.CreateClient(c); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create client: %v\n", err)
		return 1
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(c)
		return 0
	}

	fmt.Printf("[+] Client created successfully\n")
	fmt.Printf("    ID:           %s\n", c.ID)
	fmt.Printf("    Name:         %s\n", c.Name)
	if c.Organization != "" {
		fmt.Printf("    Organization: %s\n", c.Organization)
	}
	if c.ContactEmail != "" {
		fmt.Printf("    Contact:      %s <%s>\n", c.ContactName, c.ContactEmail)
	}
	fmt.Printf("    Created:      %s\n", c.CreatedAt.Format(time.RFC3339))
	return 0
}

func runClientList(args []string) int {
	var (
		all        bool
		jsonOutput bool
	)

	for _, arg := range args {
		switch arg {
		case "--all", "-a":
			all = true
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printClientHelp()
			return 0
		}
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	clients, err := store.ListClients(all)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to list clients: %v\n", err)
		return 1
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if clients == nil {
			clients = []assessment.Client{}
		}
		_ = enc.Encode(clients)
		return 0
	}

	if len(clients) == 0 {
		fmt.Println("No clients found. Register one with 'felix client add --name <name>'")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tORGANIZATION\tCONTACT\tSTATUS\tCREATED")
	for _, c := range clients {
		status := "ACTIVE"
		if c.Archived {
			status = "ARCHIVED"
		}
		contact := c.ContactEmail
		if contact == "" {
			contact = "-"
		}
		org := c.Organization
		if org == "" {
			org = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.ID, c.Name, org, contact, status, c.CreatedAt.Format("2006-01-02 15:04"))
	}
	_ = w.Flush()
	return 0
}

func runClientShow(args []string) int {
	var (
		clientID   string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--client", "--id":
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printClientHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && clientID == "" {
				clientID = arg
			}
		}
	}

	if clientID == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: client ID is required. Usage: felix client show <client-id>\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	c, err := store.GetClient(clientID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		return 1
	}

	assessments, _ := store.ListAssessments(c.ID)

	if jsonOutput {
		out := map[string]any{
			"client":      c,
			"assessments": assessments,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}

	fmt.Printf("Client Details:\n")
	fmt.Printf("  ID:           %s\n", c.ID)
	fmt.Printf("  Name:         %s\n", c.Name)
	if c.Organization != "" {
		fmt.Printf("  Organization: %s\n", c.Organization)
	}
	if c.ContactName != "" || c.ContactEmail != "" {
		fmt.Printf("  Contact:      %s <%s>\n", c.ContactName, c.ContactEmail)
	}
	if c.Notes != "" {
		fmt.Printf("  Notes:        %s\n", c.Notes)
	}
	status := "ACTIVE"
	if c.Archived {
		status = "ARCHIVED"
	}
	fmt.Printf("  Status:       %s\n", status)
	fmt.Printf("  Created:      %s\n", c.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  Updated:      %s\n", c.UpdatedAt.Format(time.RFC3339))

	fmt.Printf("\nAssessments (%d):\n", len(assessments))
	if len(assessments) == 0 {
		fmt.Println("  (No assessments registered for this client)")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "  REF\tNAME\tSTATUS\tFINDINGS\tCREATED")
		for _, a := range assessments {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%d\t%s\n",
				a.Ref, a.Name, a.Status, a.FindingCount, a.CreatedAt.Format("2006-01-02 15:04"))
		}
		_ = w.Flush()
	}

	return 0
}

func runClientArchive(args []string) int {
	var clientID string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--client", "--id":
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
		case "--help", "-h":
			printClientHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && clientID == "" {
				clientID = arg
			}
		}
	}

	if clientID == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: client ID is required. Usage: felix client archive <client-id>\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	if err := store.ArchiveClient(clientID); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to archive client: %v\n", err)
		return 1
	}

	fmt.Printf("[+] Client %s archived successfully\n", clientID)
	return 0
}

func getAssessmentStore() (assessment.Store, error) {
	dbPath, err := assessment.DefaultDBPath()
	if err != nil {
		return nil, err
	}
	return assessment.NewSQLiteStore(dbPath)
}
