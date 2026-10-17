package apk

import (
	"strconv"
	"strings"
)

// ComponentType enumerates the five core Android application component categories.
type ComponentType string

const (
	ComponentActivity      ComponentType = "activity"
	ComponentActivityAlias ComponentType = "activity-alias"
	ComponentService       ComponentType = "service"
	ComponentReceiver      ComponentType = "receiver"
	ComponentProvider      ComponentType = "provider"
)

const (
	// AndroidNamespace is the standard URI for Android manifest attributes.
	AndroidNamespace = "http://schemas.android.com/apk/res/android"
)

// RawAttribute represents an attribute parsed from either AXML or textual XML.
type RawAttribute struct {
	Namespace string
	Name      string
	Value     string
}

// RawElement represents a parsed element node in the manifest document tree.
type RawElement struct {
	Namespace string
	Name      string
	Attrs     []RawAttribute
	Children  []*RawElement
	Line      int
}

// GetAttr returns the attribute value matching ns and name, or empty string.
func (e *RawElement) GetAttr(ns, name string) string {
	if e == nil {
		return ""
	}
	for _, a := range e.Attrs {
		if a.Namespace == ns && a.Name == name {
			return a.Value
		}
	}
	return ""
}

// GetAndroidAttr looks up an Android attribute by name, handling namespace-scoped
// attributes, "android:" prefixed names, and unqualified fallback names.
func (e *RawElement) GetAndroidAttr(name string) (string, bool) {
	if e == nil {
		return "", false
	}
	for _, a := range e.Attrs {
		if (a.Namespace == AndroidNamespace && a.Name == name) ||
			a.Name == "android:"+name ||
			(a.Namespace == "" && a.Name == name) {
			return a.Value, true
		}
	}
	return "", false
}

// FindChildren returns all child elements matching the specified element name.
func (e *RawElement) FindChildren(name string) []*RawElement {
	if e == nil {
		return nil
	}
	var res []*RawElement
	for _, c := range e.Children {
		if c.Name == name {
			res = append(res, c)
		}
	}
	return res
}

// FindChild returns the first child element matching the specified name, or nil.
func (e *RawElement) FindChild(name string) *RawElement {
	if e == nil {
		return nil
	}
	for _, c := range e.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ManifestDocument encapsulates parsed and normalized security-relevant metadata from AndroidManifest.xml.
type ManifestDocument struct {
	Format       string
	PackageName  string
	VersionCode  string
	VersionName  string
	MinSDK       int
	TargetSDK    int
	CompileSDK   int
	Permissions  []ManifestPermission
	Application  ApplicationInfo
	RawElement   *RawElement
}

// ManifestPermission represents a custom <permission> declared in the manifest.
type ManifestPermission struct {
	Name            string
	ProtectionLevel string
	PermissionGroup string
}

// ApplicationInfo stores application-level security configuration and child components.
type ApplicationInfo struct {
	Name                  string
	Label                 string
	Debuggable            *bool
	AllowBackup           *bool
	UsesCleartextTraffic  *bool
	NetworkSecurityConfig string
	Permission            string
	DirectBootAware       *bool

	Activities      []ComponentInfo
	ActivityAliases []ActivityAliasInfo
	Services        []ComponentInfo
	Receivers       []ComponentInfo
	Providers       []ProviderInfo
}

// ComponentInfo stores metadata for Activity, Service, Receiver, or Provider.
type ComponentInfo struct {
	Type            ComponentType
	Name            string
	ResolvedName    string
	Exported        *bool
	Permission      string
	Enabled         *bool
	DirectBootAware *bool
	IntentFilters   []IntentFilterInfo
	Attributes      map[string]string
}

// ActivityAliasInfo represents <activity-alias>.
type ActivityAliasInfo struct {
	ComponentInfo
	TargetActivity         string
	ResolvedTargetActivity string
}

// ProviderInfo represents <provider>.
type ProviderInfo struct {
	ComponentInfo
	Authorities         string
	ReadPermission      string
	WritePermission     string
	GrantUriPermissions *bool
}

// IntentFilterInfo models an <intent-filter>.
type IntentFilterInfo struct {
	Actions    []string
	Categories []string
	Data       []IntentFilterData
	AutoVerify *bool
	Priority   int
}

// IntentFilterData captures <data> attributes.
type IntentFilterData struct {
	Scheme      string
	Host        string
	Port        string
	Path        string
	PathPrefix  string
	PathPattern string
	MimeType    string
}

// ResolveComponentName resolves relative and shorthand names (e.g. ".MainActivity" or "MainActivity")
// against the application package name, while preserving the raw name in ComponentInfo.Name.
func ResolveComponentName(packageName, rawName string) string {
	rawName = strings.TrimSpace(rawName)
	if rawName == "" {
		return ""
	}
	if strings.HasPrefix(rawName, ".") {
		return packageName + rawName
	}
	if !strings.Contains(rawName, ".") {
		return packageName + "." + rawName
	}
	return rawName
}

// ParseBoolPtr parses "true" / "false" into a *bool, returning nil for omitted or malformed values.
func ParseBoolPtr(val string, ok bool) *bool {
	if !ok {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(val))
	if v == "true" || v == "1" {
		b := true
		return &b
	}
	if v == "false" || v == "0" {
		b := false
		return &b
	}
	return nil
}

// ExtractManifestDocument converts a parsed RawElement tree into a structured ManifestDocument.
func ExtractManifestDocument(root *RawElement, format string) *ManifestDocument {
	if root == nil {
		return nil
	}

	doc := &ManifestDocument{
		Format:     format,
		RawElement: root,
	}

	// 1. Package Name
	if pkg, ok := root.GetAndroidAttr("package"); ok && pkg != "" {
		doc.PackageName = pkg
	} else if pkg := root.GetAttr("", "package"); pkg != "" {
		doc.PackageName = pkg
	}
	if vCode, ok := root.GetAndroidAttr("versionCode"); ok {
		doc.VersionCode = vCode
	}
	if vName, ok := root.GetAndroidAttr("versionName"); ok {
		doc.VersionName = vName
	}
	if cSDK, ok := root.GetAndroidAttr("compileSdkVersion"); ok {
		doc.CompileSDK, _ = strconv.Atoi(cSDK)
	}

	// 2. Uses-SDK
	if usesSdk := root.FindChild("uses-sdk"); usesSdk != nil {
		if minSDK, ok := usesSdk.GetAndroidAttr("minSdkVersion"); ok {
			doc.MinSDK, _ = strconv.Atoi(minSDK)
		}
		if targetSDK, ok := usesSdk.GetAndroidAttr("targetSdkVersion"); ok {
			doc.TargetSDK, _ = strconv.Atoi(targetSDK)
		}
	}

	// 3. Custom Permissions
	for _, perm := range root.FindChildren("permission") {
		name, _ := perm.GetAndroidAttr("name")
		prot, _ := perm.GetAndroidAttr("protectionLevel")
		group, _ := perm.GetAndroidAttr("permissionGroup")
		if name != "" {
			doc.Permissions = append(doc.Permissions, ManifestPermission{
				Name:            name,
				ProtectionLevel: prot,
				PermissionGroup: group,
			})
		}
	}

	// 4. Application
	appElem := root.FindChild("application")
	if appElem != nil {
		app := ApplicationInfo{}
		app.Name, _ = appElem.GetAndroidAttr("name")
		app.Label, _ = appElem.GetAndroidAttr("label")

		val, ok := appElem.GetAndroidAttr("debuggable")
		app.Debuggable = ParseBoolPtr(val, ok)

		val, ok = appElem.GetAndroidAttr("allowBackup")
		app.AllowBackup = ParseBoolPtr(val, ok)

		val, ok = appElem.GetAndroidAttr("usesCleartextTraffic")
		app.UsesCleartextTraffic = ParseBoolPtr(val, ok)

		app.NetworkSecurityConfig, _ = appElem.GetAndroidAttr("networkSecurityConfig")
		app.Permission, _ = appElem.GetAndroidAttr("permission")

		val, ok = appElem.GetAndroidAttr("directBootAware")
		app.DirectBootAware = ParseBoolPtr(val, ok)

		// 4a. Activities
		for _, act := range appElem.FindChildren("activity") {
			comp := extractComponentInfo(doc.PackageName, act, ComponentActivity)
			app.Activities = append(app.Activities, comp)
		}

		// 4b. Activity Aliases
		for _, alias := range appElem.FindChildren("activity-alias") {
			comp := extractComponentInfo(doc.PackageName, alias, ComponentActivityAlias)
			target, _ := alias.GetAndroidAttr("targetActivity")
			resolvedTarget := ResolveComponentName(doc.PackageName, target)
			app.ActivityAliases = append(app.ActivityAliases, ActivityAliasInfo{
				ComponentInfo:          comp,
				TargetActivity:         target,
				ResolvedTargetActivity: resolvedTarget,
			})
		}

		// 4c. Services
		for _, s := range appElem.FindChildren("service") {
			comp := extractComponentInfo(doc.PackageName, s, ComponentService)
			app.Services = append(app.Services, comp)
		}

		// 4d. Receivers
		for _, r := range appElem.FindChildren("receiver") {
			comp := extractComponentInfo(doc.PackageName, r, ComponentReceiver)
			app.Receivers = append(app.Receivers, comp)
		}

		// 4e. Providers
		for _, p := range appElem.FindChildren("provider") {
			comp := extractComponentInfo(doc.PackageName, p, ComponentProvider)
			auth, _ := p.GetAndroidAttr("authorities")
			readPerm, _ := p.GetAndroidAttr("readPermission")
			writePerm, _ := p.GetAndroidAttr("writePermission")
			grantUri, ok := p.GetAndroidAttr("grantUriPermissions")
			app.Providers = append(app.Providers, ProviderInfo{
				ComponentInfo:       comp,
				Authorities:         auth,
				ReadPermission:      readPerm,
				WritePermission:     writePerm,
				GrantUriPermissions: ParseBoolPtr(grantUri, ok),
			})
		}

		doc.Application = app
	}

	return doc
}

func extractComponentInfo(pkgName string, elem *RawElement, compType ComponentType) ComponentInfo {
	name, _ := elem.GetAndroidAttr("name")
	resolved := ResolveComponentName(pkgName, name)
	perm, _ := elem.GetAndroidAttr("permission")

	expVal, expOk := elem.GetAndroidAttr("exported")
	exported := ParseBoolPtr(expVal, expOk)

	enVal, enOk := elem.GetAndroidAttr("enabled")
	enabled := ParseBoolPtr(enVal, enOk)

	dbVal, dbOk := elem.GetAndroidAttr("directBootAware")
	directBootAware := ParseBoolPtr(dbVal, dbOk)

	// Collect all other attributes
	attrs := make(map[string]string)
	for _, a := range elem.Attrs {
		attrs[a.Name] = a.Value
	}

	// Parse Intent Filters
	var filters []IntentFilterInfo
	for _, filterElem := range elem.FindChildren("intent-filter") {
		filter := IntentFilterInfo{}

		avVal, avOk := filterElem.GetAndroidAttr("autoVerify")
		filter.AutoVerify = ParseBoolPtr(avVal, avOk)

		if prioStr, ok := filterElem.GetAndroidAttr("priority"); ok {
			filter.Priority, _ = strconv.Atoi(prioStr)
		}

		for _, action := range filterElem.FindChildren("action") {
			if aName, ok := action.GetAndroidAttr("name"); ok && aName != "" {
				filter.Actions = append(filter.Actions, aName)
			}
		}

		for _, cat := range filterElem.FindChildren("category") {
			if cName, ok := cat.GetAndroidAttr("name"); ok && cName != "" {
				filter.Categories = append(filter.Categories, cName)
			}
		}

		for _, d := range filterElem.FindChildren("data") {
			scheme, _ := d.GetAndroidAttr("scheme")
			host, _ := d.GetAndroidAttr("host")
			port, _ := d.GetAndroidAttr("port")
			pathVal, _ := d.GetAndroidAttr("path")
			pathPrefix, _ := d.GetAndroidAttr("pathPrefix")
			pathPattern, _ := d.GetAndroidAttr("pathPattern")
			mime, _ := d.GetAndroidAttr("mimeType")

			filter.Data = append(filter.Data, IntentFilterData{
				Scheme:      scheme,
				Host:        host,
				Port:        port,
				Path:        pathVal,
				PathPrefix:  pathPrefix,
				PathPattern: pathPattern,
				MimeType:    mime,
			})
		}

		filters = append(filters, filter)
	}

	return ComponentInfo{
		Type:            compType,
		Name:            name,
		ResolvedName:    resolved,
		Exported:        exported,
		Permission:      perm,
		Enabled:         enabled,
		DirectBootAware: directBootAware,
		IntentFilters:   filters,
		Attributes:      attrs,
	}
}
