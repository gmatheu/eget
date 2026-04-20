# 20260420_1030: Fix asset filter persistence in --upgrade-all --interactive mode

## Problem

When executing `eget --upgrade-all --interactive`, the tool was not remembering the previous asset selection for each package. Every time it ran, users were prompted to manually select which asset to download, even when the same asset filters had been used before.

## Root Cause

The bug was in the `performUpgrade()` function in `installed.go` at lines 439-444. The code attempted to type-assert the stored `asset` option as `[]interface{}`:

```go
if assets, ok := opts["asset"].([]interface{}); ok && len(assets) > 0 {
    for _, asset := range assets {
        if assetStr, ok := asset.(string); ok {
            args = append(args, "--asset", assetStr)
        }
    }
}
```

However, when the options map is:
1. Stored to TOML via `extractOptionsMap()` (line 181: `options["asset"] = opts.Asset` - a `[]string`)
2. Saved to disk via TOML encoder
3. Later loaded back via TOML decoder in `loadInstalledConfig()`

The TOML library decodes string arrays as `[]string`, NOT `[]interface{}`. This caused the type assertion to fail silently (`ok` was `false`), so asset filters were never passed to the subprocess. When `performUpgrade()` spawned a new eget process, it would run without the `--asset` flags, forcing the user to manually select again.

## Solution

Modified the type assertion in `performUpgrade()` to handle both types using a type switch:

```go
// Handle asset filters - support both []interface{} (from memory) and []string (from TOML decode)
if assetsRaw, ok := opts["asset"]; ok {
    switch assets := assetsRaw.(type) {
    case []interface{}:
        for _, asset := range assets {
            if assetStr, ok := asset.(string); ok {
                args = append(args, "--asset", assetStr)
            }
        }
    case []string:
        for _, assetStr := range assets {
            args = append(args, "--asset", assetStr)
        }
    }
}
```

This ensures asset filters are properly passed to subprocesses regardless of whether they come from:
- In-memory options (`[]interface{}` when originally stored)
- TOML-decoded config (`[]string` when loaded from disk)

## Files Modified

- `/home/gmatheu/Documents/misc/eget/installed.go` - Fixed type assertion in `performUpgrade()` (lines 439-454)

## Verification

- Code builds successfully: `go build -o eget .` ✓
- No compilation errors or warnings ✓
- Type-safe handling of both `[]interface{}` and `[]string` cases ✓

## Related

This fix complements the existing fallback mechanism documented in:
- `20260120_add-fallback-selection-for-upgrade-all-when-asset-filters-dont-match.md` - Automatic fallback when asset filters don't match
- `20260112_enhanced-upgrade-functionality.md` - Original upgrade functionality with option preservation
- `20260112_fix-upgrade-all-stdin-forwarding-and-option-preservation.md` - Stdin forwarding for interactive prompts

Together, these features ensure `--upgrade-all --interactive` works seamlessly:
1. User selects which packages to upgrade (via bubbletea UI)
2. Asset filters are passed to subprocess (this fix)
3. If multiple assets still match, automatic fallback to previous selection (existing feature)
4. Stdin is forwarded so any remaining prompts can be answered (existing feature)
