## ADDED Requirements

### Requirement: Upload Filename Sanitization
The backend MUST sanitize uploaded filenames before storing them in the database.

#### Scenario: Path traversal characters removed
- **WHEN** a file is uploaded with filename `../../etc/passwd`
- **THEN** the system SHALL strip all path components and store only `passwd`

#### Scenario: Null bytes removed
- **WHEN** a file is uploaded with filename containing null bytes `evil\x00.exe`
- **THEN** the system SHALL remove all null bytes before storing the filename

#### Scenario: Windows path separators handled
- **WHEN** a file is uploaded with filename `C:\Users\test\malware.exe`
- **THEN** the system SHALL normalize backslashes and store only `malware.exe`

#### Scenario: Filename length limited
- **WHEN** a file is uploaded with a filename exceeding 255 characters
- **THEN** the system SHALL truncate the filename to 255 characters

#### Scenario: Empty filename fallback
- **WHEN** a file is uploaded with an empty or whitespace-only filename
- **THEN** the system SHALL use the fallback name `unnamed`
