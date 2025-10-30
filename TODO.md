# TODO.md - Report Storage System Audit

## 🔍 PHASE 1: STORAGE LOCATION AUDIT

### 1.1. Database Storage Verification
- [ ] Check if SQLite database exists at `./results/pentest.db`
- [ ] Verify all required tables are created:
  - [ ] `sessions` table with proper columns
  - [ ] `scans` table with foreign key relationships
  - [ ] `vulnerabilities` table with evidence storage
  - [ ] `exploitations` table with PoC storage
- [ ] Test database connection and permissions
- [ ] Verify data persistence after application restart

### 1.2. File System Storage
- [ ] Check `./results/` directory structure
- [ ] Verify `./logs/` directory and files:
  - [ ] `framework.log` - General activity logs
  - [ ] `audit.jsonl` - Detailed audit trail
  - [ ] Log rotation files (.1, .2, etc.)
- [ ] Check `./reports/` directory for generated reports
- [ ] Verify file permissions and write access

## 📊 PHASE 2: DATA INTEGRITY AUDIT

### 2.1. Session Data Storage
- [ ] Verify new sessions are created in database
- [ ] Check session IDs are unique and properly formatted
- [ ] Test session start/end timestamps
- [ ] Verify session configuration is stored correctly
- [ ] Check session status updates (running, completed, failed)

### 2.2. Scan Results Storage
- [ ] Verify scan results are saved to `scans` table
- [ ] Check scan types are properly categorized
- [ ] Test storage of port scan results
- [ ] Verify service detection data persistence
- [ ] Check OS fingerprinting results storage

### 2.3. Vulnerability Data Storage
- [ ] Verify vulnerabilities are saved with correct severity
- [ ] Check evidence field stores proper JSON data
- [ ] Test remediation suggestions storage
- [ ] Verify vulnerability-target relationships
- [ ] Check duplicate vulnerability prevention

## 🐛 PHASE 3: COMMON STORAGE ISSUES

### 3.1. Database Connection Issues
- [ ] Test database connection error handling
- [ ] Verify transaction rollback on failures
- [ ] Check for database locking issues
- [ ] Test concurrent access handling
- [ ] Verify connection timeout settings

### 3.2. Data Serialization Problems
- [ ] Check JSON serialization of complex objects
- [ ] Verify datetime object handling
- [ ] Test binary data storage (evidence, screenshots)
- [ ] Check foreign key constraint violations
- [ ] Verify data type compatibility

### 3.3. File System Issues
- [ ] Test directory creation permissions
- [ ] Verify file write permissions
- [ ] Check disk space monitoring
- [ ] Test file locking during writes
- [ ] Verify log rotation functionality

## 🔧 PHASE 4: STORAGE SYSTEM TESTING

### 4.1. Functional Tests
- [ ] Create test session and verify database entry
- [ ] Run port scan and verify results storage
- [ ] Detect vulnerabilities and check database persistence
- [ ] Generate reports and verify file creation
- [ ] Test data retrieval for reporting

### 4.2. Error Scenario Tests
- [ ] Test storage with full disk
- [ ] Verify behavior with corrupted database
- [ ] Test with missing directories
- [ ] Check permission denied scenarios
- [ ] Verify recovery from storage failures

### 4.3. Performance Tests
- [ ] Test storage with large scan results
- [ ] Verify performance with many vulnerabilities
- [ ] Check memory usage during data storage
- [ ] Test concurrent session storage
- [ ] Verify storage speed benchmarks

## 📋 PHASE 5: VALIDATION CHECKLIST

### 5.1. Data Persistence Verification
- [ ] ✅ Sessions persist after application restart
- [ ] ✅ Scan results remain accessible
- [ ] ✅ Vulnerabilities don't disappear
- [ ] ✅ Reports can be regenerated from stored data
- [ ] ✅ Audit trail is complete and accurate

### 5.2. Data Integrity Checks
- [ ] ✅ No data corruption in database
- [ ] ✅ All foreign key relationships valid
- [ ] ✅ No missing scan results
- [ ] ✅ Vulnerability evidence is complete
- [ ] ✅ Timestamps are accurate and consistent

### 5.3. Storage System Health
- [ ] ✅ Database file size is reasonable
- [ ] ✅ Log files are rotating properly
- [ ] ✅ No storage leaks detected
- [ ] ✅ Backup systems working (if implemented)
- [ ] ✅ Storage performance meets requirements

## 🚨 DEBUGGING SPECIFIC ISSUES

### If Results Aren't Saving:
- [ ] Check database connection in `core/database.py`
- [ ] Verify `ResultDatabase` methods are being called
- [ ] Check for silent exceptions in storage operations
- [ ] Verify data is being passed to storage methods
- [ ] Test storage with simple data first

### If Data is Incomplete:
- [ ] Check JSON serialization of complex objects
- [ ] Verify all required fields are being saved
- [ ] Test individual storage methods separately
- [ ] Check for transaction commits
- [ ] Verify error handling isn't hiding issues