package crawler

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// TokenType classifies ECMAScript lexical tokens.
type TokenType int

const (
	tokEOF TokenType = iota
	tokString
	tokTemplateNoSub
	tokTemplateHead
	tokTemplateMiddle
	tokTemplateTail
	tokIdent
	tokNumber
	tokPunctuator
	tokKeyword
	tokRegex
)

// Token represents a single lexical unit in JavaScript source.
type Token struct {
	Type   TokenType
	Value  string
	Raw    string
	Line   int
	Col    int
	Quasis []string
	Exprs  []string
}

// ASTNode represents an abstract syntax tree element in JavaScript.
type ASTNode interface {
	NodeType() string
	Pos() (int, int) // Line, Column
}

// BaseNode provides position tracking for AST elements.
type BaseNode struct {
	Line int
	Col  int
}

func (b BaseNode) Pos() (int, int) { return b.Line, b.Col }

// StringLiteralNode represents a single or double quoted string.
type StringLiteralNode struct {
	BaseNode
	Value string
	Raw   string
}

func (n *StringLiteralNode) NodeType() string { return "StringLiteral" }

// TemplateLiteralNode represents a template string (`...` or `...${...}...`).
type TemplateLiteralNode struct {
	BaseNode
	Quasis      []string  // String fragments
	Expressions []ASTNode // Embedded expressions
	Raw         string
}

func (n *TemplateLiteralNode) NodeType() string { return "TemplateLiteral" }

// IdentifierNode represents a variable, function, or property identifier.
type IdentifierNode struct {
	BaseNode
	Name string
}

func (n *IdentifierNode) NodeType() string { return "Identifier" }

// BinaryExpressionNode represents binary operations, specifically string concatenation (+).
type BinaryExpressionNode struct {
	BaseNode
	Operator string
	Left     ASTNode
	Right    ASTNode
}

func (n *BinaryExpressionNode) NodeType() string { return "BinaryExpression" }

// CallExpressionNode represents a function or method invocation: callee(args...).
type CallExpressionNode struct {
	BaseNode
	Callee    ASTNode
	Arguments []ASTNode
}

func (n *CallExpressionNode) NodeType() string { return "CallExpression" }

// MemberExpressionNode represents object property access: obj.prop or obj[prop].
type MemberExpressionNode struct {
	BaseNode
	Object   ASTNode
	Property ASTNode
	Computed bool
}

func (n *MemberExpressionNode) NodeType() string { return "MemberExpression" }

// PropertyNode represents a key-value pair in an object literal.
type PropertyNode struct {
	Key   string
	Value ASTNode
	Line  int
	Col   int
}

// ObjectExpressionNode represents an object literal: { key: value, ... }.
type ObjectExpressionNode struct {
	BaseNode
	Properties []PropertyNode
}

func (n *ObjectExpressionNode) NodeType() string { return "ObjectExpression" }

// ArrayExpressionNode represents an array literal: [ elem1, elem2, ... ].
type ArrayExpressionNode struct {
	BaseNode
	Elements []ASTNode
}

func (n *ArrayExpressionNode) NodeType() string { return "ArrayExpression" }

// VariableDeclarator represents a single variable binding in const/let/var.
type VariableDeclarator struct {
	Name string
	Init ASTNode
	Line int
	Col  int
}

// VariableDeclarationNode represents a const, let, or var declaration statement.
type VariableDeclarationNode struct {
	BaseNode
	Kind         string // "const", "let", "var"
	Declarations []VariableDeclarator
}

func (n *VariableDeclarationNode) NodeType() string { return "VariableDeclaration" }

// AssignmentExpressionNode represents an assignment: target = value.
type AssignmentExpressionNode struct {
	BaseNode
	Left  ASTNode
	Right ASTNode
}

func (n *AssignmentExpressionNode) NodeType() string { return "AssignmentExpression" }

// FunctionExpressionNode represents a function or arrow function definition.
type FunctionExpressionNode struct {
	BaseNode
	Name   string
	Params []string
	Body   []ASTNode
}

func (n *FunctionExpressionNode) NodeType() string { return "FunctionExpression" }

// ImportExpressionNode represents a dynamic import: import("...").
type ImportExpressionNode struct {
	BaseNode
	Source ASTNode
}

func (n *ImportExpressionNode) NodeType() string { return "ImportExpression" }

// JSLexer performs bounded, safe tokenization of JavaScript / ECMAScript source code.
type JSLexer struct {
	src       []rune
	pos       int
	length    int
	line      int
	col       int
	tokens    []Token
	maxTokens int
	warnings  []string
}

// NewJSLexer creates a new lexer instance with bounded token allocation.
func NewJSLexer(input string, maxTokens int) *JSLexer {
	if maxTokens <= 0 {
		maxTokens = 500000
	}
	return &JSLexer{
		src:       []rune(input),
		length:    len([]rune(input)),
		line:      1,
		col:       1,
		maxTokens: maxTokens,
	}
}

func (l *JSLexer) peek() rune {
	if l.pos >= l.length {
		return 0
	}
	return l.src[l.pos]
}

func (l *JSLexer) peekNext() rune {
	if l.pos+1 >= l.length {
		return 0
	}
	return l.src[l.pos+1]
}

func (l *JSLexer) next() rune {
	if l.pos >= l.length {
		return 0
	}
	r := l.src[l.pos]
	l.pos++
	if r == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return r
}

// Tokenize converts the source into a sequence of tokens with bounded limits.
func (l *JSLexer) Tokenize() ([]Token, error) {
	for l.pos < l.length {
		if len(l.tokens) >= l.maxTokens {
			l.warnings = append(l.warnings, fmt.Sprintf("Token count exceeded safety ceiling (%d); truncating scan", l.maxTokens))
			break
		}

		ch := l.peek()

		// Skip whitespace
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			l.next()
			continue
		}

		// Single-line and multi-line comments
		if ch == '/' {
			nextCh := l.peekNext()
			if nextCh == '/' {
				l.next() // '/'
				l.next() // '/'
				for l.pos < l.length && l.peek() != '\n' {
					l.next()
				}
				continue
			} else if nextCh == '*' {
				l.next() // '/'
				l.next() // '*'
				for l.pos < l.length {
					if l.next() == '*' && l.peek() == '/' {
						l.next()
						break
					}
				}
				continue
			}
		}

		line, col := l.line, l.col

		// String literals ('...' or "...")
		if ch == '"' || ch == '\'' {
			strVal, raw, err := l.scanString(ch)
			if err != nil {
				l.warnings = append(l.warnings, fmt.Sprintf("Line %d:%d: Unterminated string literal", line, col))
				continue
			}
			l.tokens = append(l.tokens, Token{
				Type:  tokString,
				Value: strVal,
				Raw:   raw,
				Line:  line,
				Col:   col,
			})
			continue
		}

		// Template literals (`...`)
		if ch == '`' {
			l.scanTemplate(line, col)
			continue
		}

		// Identifiers and Keywords
		if isIdentStart(ch) {
			val := l.scanIdent()
			tType := tokIdent
			if isKeyword(val) {
				tType = tokKeyword
			}
			l.tokens = append(l.tokens, Token{
				Type:  tType,
				Value: val,
				Raw:   val,
				Line:  line,
				Col:   col,
			})
			continue
		}

		// Numbers
		if unicode.IsDigit(ch) {
			numVal := l.scanNumber()
			l.tokens = append(l.tokens, Token{
				Type:  tokNumber,
				Value: numVal,
				Raw:   numVal,
				Line:  line,
				Col:   col,
			})
			continue
		}

		// Punctuators and Operators
		punc := l.scanPunctuator()
		l.tokens = append(l.tokens, Token{
			Type:  tokPunctuator,
			Value: punc,
			Raw:   punc,
			Line:  line,
			Col:   col,
		})
	}

	l.tokens = append(l.tokens, Token{
		Type: tokEOF,
		Line: l.line,
		Col:  l.col,
	})

	return l.tokens, nil
}

func (l *JSLexer) scanString(quote rune) (string, string, error) {
	l.next() // consume opening quote
	var sb strings.Builder
	var raw strings.Builder
	raw.WriteRune(quote)

	for l.pos < l.length {
		ch := l.next()
		raw.WriteRune(ch)

		if ch == quote {
			return sb.String(), raw.String(), nil
		}

		if ch == '\\' {
			if l.pos >= l.length {
				break
			}
			esc := l.next()
			raw.WriteRune(esc)
			switch esc {
			case 'n':
				sb.WriteRune('\n')
			case 'r':
				sb.WriteRune('\r')
			case 't':
				sb.WriteRune('\t')
			case '\\':
				sb.WriteRune('\\')
			case '\'':
				sb.WriteRune('\'')
			case '"':
				sb.WriteRune('"')
			case 'x':
				// \xHH
				var hexChars []rune
				for i := 0; i < 2 && l.pos < l.length; i++ {
					h := l.next()
					raw.WriteRune(h)
					hexChars = append(hexChars, h)
				}
				if val, err := strconv.ParseInt(string(hexChars), 16, 32); err == nil {
					sb.WriteRune(rune(val))
				}
			case 'u':
				// \uHHHH
				var hexChars []rune
				if l.peek() == '{' {
					// \u{H...}
					raw.WriteRune(l.next())
					for l.pos < l.length && l.peek() != '}' {
						h := l.next()
						raw.WriteRune(h)
						hexChars = append(hexChars, h)
					}
					if l.peek() == '}' {
						raw.WriteRune(l.next())
					}
				} else {
					for i := 0; i < 4 && l.pos < l.length; i++ {
						h := l.next()
						raw.WriteRune(h)
						hexChars = append(hexChars, h)
					}
				}
				if val, err := strconv.ParseInt(string(hexChars), 16, 32); err == nil {
					sb.WriteRune(rune(val))
				}
			default:
				sb.WriteRune(esc)
			}
			continue
		}

		sb.WriteRune(ch)
	}

	return sb.String(), raw.String(), errors.New("unterminated string")
}

func (l *JSLexer) scanTemplate(startLine, startCol int) {
	l.next() // consume opening '`'
	var quasis []string
	var exprs []string
	var sb strings.Builder
	var raw strings.Builder
	raw.WriteRune('`')

	for l.pos < l.length {
		ch := l.next()
		raw.WriteRune(ch)

		if ch == '`' {
			quasis = append(quasis, sb.String())
			l.tokens = append(l.tokens, Token{
				Type:   tokTemplateNoSub,
				Value:  sb.String(),
				Raw:    raw.String(),
				Line:   startLine,
				Col:    startCol,
				Quasis: quasis,
				Exprs:  exprs,
			})
			return
		}

		if ch == '$' && l.peek() == '{' {
			raw.WriteRune(l.next()) // consume '{'
			quasis = append(quasis, sb.String())
			sb.Reset()

			var exprSb strings.Builder
			braceDepth := 1
			for l.pos < l.length && braceDepth > 0 {
				ech := l.next()
				raw.WriteRune(ech)
				if ech == '{' {
					braceDepth++
					exprSb.WriteRune(ech)
				} else if ech == '}' {
					braceDepth--
					if braceDepth == 0 {
						break
					}
					exprSb.WriteRune(ech)
				} else {
					exprSb.WriteRune(ech)
				}
			}
			exprs = append(exprs, strings.TrimSpace(exprSb.String()))
			continue
		}

		if ch == '\\' && l.pos < l.length {
			esc := l.next()
			raw.WriteRune(esc)
			switch esc {
			case 'n':
				sb.WriteRune('\n')
			case 'r':
				sb.WriteRune('\r')
			case 't':
				sb.WriteRune('\t')
			case '`':
				sb.WriteRune('`')
			case '\\':
				sb.WriteRune('\\')
			default:
				sb.WriteRune(esc)
			}
			continue
		}

		sb.WriteRune(ch)
	}

	quasis = append(quasis, sb.String())
	l.tokens = append(l.tokens, Token{
		Type:   tokTemplateNoSub,
		Value:  sb.String(),
		Raw:    raw.String(),
		Line:   startLine,
		Col:    startCol,
		Quasis: quasis,
		Exprs:  exprs,
	})
}

func (l *JSLexer) scanIdent() string {
	var sb strings.Builder
	for l.pos < l.length {
		ch := l.peek()
		if isIdentPart(ch) {
			sb.WriteRune(l.next())
		} else {
			break
		}
	}
	return sb.String()
}

func (l *JSLexer) scanNumber() string {
	var sb strings.Builder
	for l.pos < l.length {
		ch := l.peek()
		if unicode.IsDigit(ch) || ch == '.' || ch == 'x' || ch == 'X' || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			sb.WriteRune(l.next())
		} else {
			break
		}
	}
	return sb.String()
}

func (l *JSLexer) scanPunctuator() string {
	ch := l.next()
	nextCh := l.peek()

	// Multi-char operators: =>, ===, ==, !==, !=, &&, ||, ++, --, +=
	two := string([]rune{ch, nextCh})
	switch two {
	case "=>", "==", "!=", "&&", "||", "++", "--", "+=", "-=", "<=", ">=":
		l.next()
		return two
	}

	return string(ch)
}

func isIdentStart(r rune) bool {
	return r == '$' || r == '_' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return r == '$' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isKeyword(s string) bool {
	switch s {
	case "const", "let", "var", "function", "return", "import", "export",
		"if", "else", "switch", "case", "default", "for", "while", "do",
		"break", "continue", "new", "class", "extends", "super", "this",
		"try", "catch", "finally", "throw", "typeof", "instanceof", "in", "of":
		return true
	}
	return false
}

// JSParser converts a token stream into an AST with safe fallback on error.
type JSParser struct {
	tokens   []Token
	pos      int
	length   int
	warnings []string
	depth    int
}

// NewJSParser initializes an AST parser.
func NewJSParser(tokens []Token) *JSParser {
	return &JSParser{
		tokens: tokens,
		length: len(tokens),
	}
}

func (p *JSParser) peek() Token {
	if p.pos >= p.length {
		return Token{Type: tokEOF}
	}
	return p.tokens[p.pos]
}

func (p *JSParser) next() Token {
	tok := p.peek()
	if p.pos < p.length {
		p.pos++
	}
	return tok
}

func (p *JSParser) match(val string) bool {
	if p.peek().Value == val {
		p.next()
		return true
	}
	return false
}

func (p *JSParser) matchType(t TokenType) bool {
	if p.peek().Type == t {
		p.next()
		return true
	}
	return false
}

// Parse extracts top-level statements and expressions with bounded depth.
func (p *JSParser) Parse() ([]ASTNode, []string) {
	var nodes []ASTNode

	for p.pos < p.length && p.peek().Type != tokEOF {
		stmt := p.parseStatement()
		if stmt != nil {
			nodes = append(nodes, stmt)
		} else {
			// Skip unrecognized token to prevent infinite loop
			p.next()
		}
	}

	return nodes, p.warnings
}

func (p *JSParser) parseStatement() ASTNode {
	tok := p.peek()

	// Variable declaration: const/let/var
	if tok.Type == tokKeyword && (tok.Value == "const" || tok.Value == "let" || tok.Value == "var") {
		return p.parseVariableDeclaration()
	}

	// Function declaration
	if tok.Type == tokKeyword && tok.Value == "function" {
		return p.parseFunctionExpression()
	}

	// Dynamic import statement
	if tok.Type == tokKeyword && tok.Value == "import" {
		return p.parseExpression()
	}

	// General expression statement
	expr := p.parseExpression()
	p.match(";") // optional semicolon
	return expr
}

func (p *JSParser) parseVariableDeclaration() *VariableDeclarationNode {
	startTok := p.next() // consume const/let/var
	declNode := &VariableDeclarationNode{
		BaseNode: BaseNode{Line: startTok.Line, Col: startTok.Col},
		Kind:     startTok.Value,
	}

	for p.pos < p.length && p.peek().Type != tokEOF {
		if p.peek().Type != tokIdent {
			break
		}
		identTok := p.next()
		decl := VariableDeclarator{
			Name: identTok.Value,
			Line: identTok.Line,
			Col:  identTok.Col,
		}

		if p.match("=") {
			decl.Init = p.parseExpression()
		}

		declNode.Declarations = append(declNode.Declarations, decl)

		if !p.match(",") {
			break
		}
	}

	p.match(";")
	return declNode
}

func (p *JSParser) parseExpression() ASTNode {
	return p.parseAssignment()
}

func (p *JSParser) parseAssignment() ASTNode {
	left := p.parseBinary(0)
	if left == nil {
		return nil
	}

	if p.match("=") {
		right := p.parseAssignment()
		line, col := left.Pos()
		return &AssignmentExpressionNode{
			BaseNode: BaseNode{Line: line, Col: col},
			Left:     left,
			Right:    right,
		}
	}

	return left
}

func (p *JSParser) parseBinary(minPrec int) ASTNode {
	left := p.parseUnary()
	if left == nil {
		return nil
	}

	for p.pos < p.length {
		opTok := p.peek()
		if opTok.Type != tokPunctuator {
			break
		}

		prec := binaryPrecedence(opTok.Value)
		if prec < minPrec {
			break
		}

		p.next() // consume operator
		right := p.parseBinary(prec + 1)
		line, col := left.Pos()
		left = &BinaryExpressionNode{
			BaseNode: BaseNode{Line: line, Col: col},
			Operator: opTok.Value,
			Left:     left,
			Right:    right,
		}
	}

	return left
}

func binaryPrecedence(op string) int {
	switch op {
	case "||":
		return 1
	case "&&":
		return 2
	case "==", "!=":
		return 3
	case "+", "-":
		return 4
	case "*", "/", "%":
		return 5
	}
	return -1
}

func (p *JSParser) parseUnary() ASTNode {
	return p.parsePostfix()
}

func (p *JSParser) parsePostfix() ASTNode {
	expr := p.parsePrimary()
	if expr == nil {
		return nil
	}

	for p.pos < p.length {
		// Member access: .prop
		if p.match(".") {
			propTok := p.next()
			line, col := expr.Pos()
			expr = &MemberExpressionNode{
				BaseNode: BaseNode{Line: line, Col: col},
				Object:   expr,
				Property: &IdentifierNode{
					BaseNode: BaseNode{Line: propTok.Line, Col: propTok.Col},
					Name:     propTok.Value,
				},
				Computed: false,
			}
			continue
		}

		// Computed member access: [prop]
		if p.match("[") {
			propExpr := p.parseExpression()
			p.match("]")
			line, col := expr.Pos()
			expr = &MemberExpressionNode{
				BaseNode: BaseNode{Line: line, Col: col},
				Object:   expr,
				Property: propExpr,
				Computed: true,
			}
			continue
		}

		// Function call: (arg1, arg2...)
		if p.match("(") {
			var args []ASTNode
			for p.pos < p.length && p.peek().Value != ")" && p.peek().Type != tokEOF {
				arg := p.parseExpression()
				if arg != nil {
					args = append(args, arg)
				}
				if !p.match(",") {
					break
				}
			}
			p.match(")")
			line, col := expr.Pos()
			expr = &CallExpressionNode{
				BaseNode:  BaseNode{Line: line, Col: col},
				Callee:    expr,
				Arguments: args,
			}
			continue
		}

		break
	}

	return expr
}

func (p *JSParser) parsePrimary() ASTNode {
	tok := p.peek()

	// String literal
	if tok.Type == tokString {
		p.next()
		return &StringLiteralNode{
			BaseNode: BaseNode{Line: tok.Line, Col: tok.Col},
			Value:    tok.Value,
			Raw:      tok.Raw,
		}
	}

	// Template literal: `...` or `...${...}...`
	if tok.Type == tokTemplateNoSub || tok.Type == tokTemplateHead {
		p.next()
		var exprNodes []ASTNode
		for _, e := range tok.Exprs {
			exprNodes = append(exprNodes, &IdentifierNode{
				BaseNode: BaseNode{Line: tok.Line, Col: tok.Col},
				Name:     e,
			})
		}
		quasis := tok.Quasis
		if len(quasis) == 0 {
			quasis = []string{tok.Value}
		}
		return &TemplateLiteralNode{
			BaseNode:    BaseNode{Line: tok.Line, Col: tok.Col},
			Quasis:      quasis,
			Expressions: exprNodes,
			Raw:         tok.Raw,
		}
	}

	// Identifier
	if tok.Type == tokIdent {
		p.next()
		// Check for arrow function: ident => ...
		if p.match("=>") {
			body := p.parseExpression()
			return &FunctionExpressionNode{
				BaseNode: BaseNode{Line: tok.Line, Col: tok.Col},
				Params:   []string{tok.Value},
				Body:     []ASTNode{body},
			}
		}
		return &IdentifierNode{
			BaseNode: BaseNode{Line: tok.Line, Col: tok.Col},
			Name:     tok.Value,
		}
	}

	// Function expression: function(...) { ... }
	if tok.Type == tokKeyword && tok.Value == "function" {
		return p.parseFunctionExpression()
	}

	// Dynamic import: import(...)
	if tok.Type == tokKeyword && tok.Value == "import" {
		p.next()
		if p.match("(") {
			src := p.parseExpression()
			p.match(")")
			return &ImportExpressionNode{
				BaseNode: BaseNode{Line: tok.Line, Col: tok.Col},
				Source:   src,
			}
		}
		return nil
	}

	// Object literal: { ... }
	if tok.Type == tokPunctuator && tok.Value == "{" {
		return p.parseObjectExpression()
	}

	// Array literal: [ ... ]
	if tok.Type == tokPunctuator && tok.Value == "[" {
		return p.parseArrayExpression()
	}

	// Parenthesized expression or arrow func: (a, b) => ...
	if tok.Type == tokPunctuator && tok.Value == "(" {
		p.next()
		expr := p.parseExpression()
		p.match(")")
		if p.match("=>") {
			body := p.parseExpression()
			return &FunctionExpressionNode{
				BaseNode: BaseNode{Line: tok.Line, Col: tok.Col},
				Body:     []ASTNode{body},
			}
		}
		return expr
	}

	// Number / other tokens
	if tok.Type == tokNumber {
		p.next()
		return nil
	}

	return nil
}

func (p *JSParser) parseTemplateWithSubs() *TemplateLiteralNode {
	startTok := p.next() // tokTemplateHead
	tpl := &TemplateLiteralNode{
		BaseNode: BaseNode{Line: startTok.Line, Col: startTok.Col},
		Quasis:   []string{startTok.Value},
		Raw:      startTok.Raw,
	}

	for p.pos < p.length {
		expr := p.parseExpression()
		if expr != nil {
			tpl.Expressions = append(tpl.Expressions, expr)
		}

		if p.match("}") {
			// Scan remaining quasis
			// For simplicity in client bundle scanning, if subsequent template parts exist, capture them
			if p.peek().Type == tokTemplateNoSub || p.peek().Type == tokTemplateTail {
				tailTok := p.next()
				tpl.Quasis = append(tpl.Quasis, tailTok.Value)
				tpl.Raw += tailTok.Raw
				break
			} else if p.peek().Type == tokTemplateMiddle {
				midTok := p.next()
				tpl.Quasis = append(tpl.Quasis, midTok.Value)
				tpl.Raw += midTok.Raw
				continue
			}
			break
		}
		break
	}

	return tpl
}

func (p *JSParser) parseObjectExpression() *ObjectExpressionNode {
	startTok := p.next() // consume '{'
	objNode := &ObjectExpressionNode{
		BaseNode: BaseNode{Line: startTok.Line, Col: startTok.Col},
	}

	for p.pos < p.length && p.peek().Value != "}" && p.peek().Type != tokEOF {
		tok := p.peek()
		key := ""
		if tok.Type == tokIdent || tok.Type == tokString || tok.Type == tokKeyword || tok.Type == tokNumber {
			p.next()
			key = tok.Value
		}

		if key != "" && p.match(":") {
			val := p.parseExpression()
			objNode.Properties = append(objNode.Properties, PropertyNode{
				Key:   key,
				Value: val,
				Line:  tok.Line,
				Col:   tok.Col,
			})
		} else if key != "" {
			// Shorthand property: { key }
			objNode.Properties = append(objNode.Properties, PropertyNode{
				Key:   key,
				Value: &IdentifierNode{BaseNode: BaseNode{Line: tok.Line, Col: tok.Col}, Name: key},
				Line:  tok.Line,
				Col:   tok.Col,
			})
		}

		if !p.match(",") {
			break
		}
	}

	p.match("}")
	return objNode
}

func (p *JSParser) parseArrayExpression() *ArrayExpressionNode {
	startTok := p.next() // consume '['
	arrNode := &ArrayExpressionNode{
		BaseNode: BaseNode{Line: startTok.Line, Col: startTok.Col},
	}

	for p.pos < p.length && p.peek().Value != "]" && p.peek().Type != tokEOF {
		elem := p.parseExpression()
		if elem != nil {
			arrNode.Elements = append(arrNode.Elements, elem)
		}
		if !p.match(",") {
			break
		}
	}

	p.match("]")
	return arrNode
}

func (p *JSParser) parseFunctionExpression() *FunctionExpressionNode {
	fnTok := p.next() // consume 'function'
	name := ""
	if p.peek().Type == tokIdent {
		name = p.next().Value
	}

	var params []string
	if p.match("(") {
		for p.pos < p.length && p.peek().Value != ")" && p.peek().Type != tokEOF {
			if p.peek().Type == tokIdent {
				params = append(params, p.next().Value)
			}
			if !p.match(",") {
				break
			}
		}
		p.match(")")
	}

	var body []ASTNode
	if p.match("{") {
		for p.pos < p.length && p.peek().Value != "}" && p.peek().Type != tokEOF {
			stmt := p.parseStatement()
			if stmt != nil {
				body = append(body, stmt)
			} else {
				p.next()
			}
		}
		p.match("}")
	}

	return &FunctionExpressionNode{
		BaseNode: BaseNode{Line: fnTok.Line, Col: fnTok.Col},
		Name:     name,
		Params:   params,
		Body:     body,
	}
}
