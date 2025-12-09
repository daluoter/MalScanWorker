rule placeholder {
    meta:
        description = "Placeholder rule - replace with real rules"
        author = "MalScan"
    strings:
        $placeholder = "PLACEHOLDER_STRING_THAT_WONT_MATCH"
    condition:
        $placeholder
}
