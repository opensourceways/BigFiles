# Security Best Practices for Go

This document provides detailed guidance on fixing common security issues detected by Gosec and preventing secrets from being committed.

## Gosec Security Issues

### G101: Hardcoded Credentials

**Issue**: Credentials, API keys, or passwords hardcoded in source code.

**Bad**:
```go
const apiKey = "sk-1234567890abcdef"
const dbPassword = "MySecretPassword123"
```

**Good**:
```go
// Use environment variables
apiKey := os.Getenv("API_KEY")
if apiKey == "" {
    log.Fatal("API_KEY environment variable not set")
}

// Or use configuration files (add to .gitignore)
type Config struct {
    APIKey     string `yaml:"api_key"`
    DBPassword string `yaml:"db_password"`
}
```

### G104: Unhandled Errors

**Issue**: Error return values not checked, potentially hiding failures.

**Bad**:
```go
file, _ := os.Open("config.txt")
file.Close()
```

**Good**:
```go
file, err := os.Open("config.txt")
if err != nil {
    return fmt.Errorf("failed to open config: %w", err)
}
defer func() {
    if err := file.Close(); err != nil {
        log.Printf("failed to close file: %v", err)
    }
}()
```

### G201/G202: SQL Injection

**Issue**: SQL queries constructed using string concatenation or formatting.

**Bad**:
```go
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId)
rows, err := db.Query(query)
```

**Good**:
```go
// Use parameterized queries
query := "SELECT * FROM users WHERE id = ?"
rows, err := db.Query(query, userId)

// For multiple parameters
query := "SELECT * FROM users WHERE name = ? AND age > ?"
rows, err := db.Query(query, userName, minAge)
```

### G304: File Path Traversal

**Issue**: File paths constructed from user input without validation.

**Bad**:
```go
func ReadFile(filename string) ([]byte, error) {
    return ioutil.ReadFile(filename)
}
// User could pass: "../../../../etc/passwd"
```

**Good**:
```go
func ReadFile(filename string) ([]byte, error) {
    // Clean the path
    cleanPath := filepath.Clean(filename)

    // Ensure it's within allowed directory
    allowedDir := "/var/app/data"
    absPath, err := filepath.Abs(cleanPath)
    if err != nil {
        return nil, err
    }

    if !strings.HasPrefix(absPath, allowedDir) {
        return nil, fmt.Errorf("access denied: path outside allowed directory")
    }

    return ioutil.ReadFile(absPath)
}
```

### G401-G406: Weak Cryptography

**Issue**: Use of weak or broken cryptographic algorithms.

**Bad**:
```go
import "crypto/md5"
import "crypto/sha1"

// MD5 is broken
h := md5.New()
h.Write([]byte(password))
hash := h.Sum(nil)

// SHA1 is weak
h := sha1.New()
h.Write([]byte(data))
hash := h.Sum(nil)
```

**Good**:
```go
import "crypto/sha256"
import "golang.org/x/crypto/bcrypt"

// For hashing data
h := sha256.New()
h.Write([]byte(data))
hash := h.Sum(nil)

// For password hashing, use bcrypt
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
if err != nil {
    return err
}

// Verify password
err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(inputPassword))
if err != nil {
    return errors.New("invalid password")
}
```

### G204: Command Injection

**Issue**: Executing commands with user-supplied input.

**Bad**:
```go
cmd := exec.Command("sh", "-c", "ls "+userInput)
output, err := cmd.Output()
```

**Good**:
```go
// Validate input first
if !isValidFilename(userInput) {
    return errors.New("invalid filename")
}

// Use exec.Command with separate arguments (not shell)
cmd := exec.Command("ls", userInput)
output, err := cmd.Output()
```

### G301-G306: File Permissions

**Issue**: Files created with overly permissive permissions.

**Bad**:
```go
// 0777 allows anyone to read/write/execute
ioutil.WriteFile("config.txt", data, 0777)
```

**Good**:
```go
// 0600 = owner read/write only
ioutil.WriteFile("config.txt", data, 0600)

// 0644 = owner read/write, others read-only
ioutil.WriteFile("public.txt", data, 0644)

// For directories: 0700 = owner only
os.MkdirAll("secrets", 0700)
```

## Preventing Secret Leaks

### 1. Use Environment Variables

```go
// config.go
type Config struct {
    APIKey        string
    DatabaseURL   string
    JWTSecret     string
}

func LoadConfig() (*Config, error) {
    return &Config{
        APIKey:      os.Getenv("API_KEY"),
        DatabaseURL: os.Getenv("DATABASE_URL"),
        JWTSecret:   os.Getenv("JWT_SECRET"),
    }, nil
}
```

### 2. Use Configuration Files (with .gitignore)

```go
// config.yaml (add to .gitignore)
api_key: sk-1234567890abcdef
database:
  host: localhost
  password: secret123

// config.go
type Config struct {
    APIKey   string `yaml:"api_key"`
    Database struct {
        Host     string `yaml:"host"`
        Password string `yaml:"password"`
    } `yaml:"database"`
}
```

### 3. Gitleaks Configuration

Create `.gitleaks.toml` to customize detection:

```toml
# Extend default rules
[extend]
useDefault = true

# Add custom rules
[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''myapp_[a-zA-Z0-9]{32}'''
tags = ["key", "API"]

# Allowlist (paths to ignore)
[allowlist]
description = "Allowlisted files"
paths = [
    '''.*_test\.go''',
    '''testdata/.*''',
    '''examples/.*''',
]
```

### 4. Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run gitleaks before commit

if command -v gitleaks &> /dev/null; then
    echo "Running gitleaks scan..."
    if ! gitleaks protect --staged --verbose; then
        echo ""
        echo "❌ Gitleaks detected secrets!"
        echo "Commit aborted. Remove secrets and try again."
        exit 1
    fi
fi

exit 0
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

## Best Practices Summary

1. **Never hardcode secrets** - use environment variables or secret managers
2. **Always check errors** - don't ignore error return values
3. **Use parameterized queries** - prevent SQL injection
4. **Validate file paths** - prevent path traversal attacks
5. **Use strong crypto** - SHA256+ for hashing, bcrypt for passwords
6. **Validate command input** - prevent command injection
7. **Set proper file permissions** - 0600 for secrets, 0644 for public files
8. **Scan before commit** - use pre-commit hooks
9. **Rotate compromised secrets** - immediately if leaked
10. **Review security regularly** - run gosec and gitleaks frequently

## Resources

- [Gosec Rules](https://github.com/securego/gosec#available-rules)
- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_SCP.html)
- [Go Crypto Best Practices](https://golang.org/pkg/crypto/)
