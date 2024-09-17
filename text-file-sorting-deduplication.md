# README: Sorting and Removing Duplicates from Text Files

## Overview

This guide provides instructions for sorting and removing duplicate lines from text files using command-line tools like `sort` and `uniq`. It also includes examples to demonstrate the process.

## Prerequisites

- Basic understanding of command-line operations.
- Access to a Unix-like operating system with `sort`, `uniq`, and `sed` installed.

## Steps

### 1. Combine Files (if needed)

If you have multiple files and want to combine them into a single file for processing, use the `cat` command:

```bash
cat file1.txt file2.txt > combined.txt
```

**Example:**

```bash
cat complaince waf > combined.txt
```

This will merge the contents of `complaince` and `waf` into `combined.txt`.

### 2. Convert Delimiters (if necessary)

If your file uses tabs or spaces and you want to handle it as comma-separated values (CSV), convert the delimiters to commas:

- **For Tab-Separated Files:**

  ```bash
  sed 's/\t/,/g' combined.txt > combined_csv.txt
  ```

- **For Space-Separated Files:**

  ```bash
  sed 's/ \{1,\}/,/g' combined.txt > combined_csv.txt
  ```

**Example:**

Convert tabs to commas in `combined.txt`:

```bash
sed 's/\t/,/g' combined.txt > combined_csv.txt
```

### 3. Sort the File

Use `sort` to arrange the lines in alphabetical order. If the file is CSV, specify the delimiter with `-t,`:

```bash
sort -t, -k1,1 -k2,2 combined_csv.txt > sorted_csv.txt
```

**Example:**

Sort `combined_csv.txt`:

```bash
sort -t, -k1,1 -k2,2 combined_csv.txt > sorted_csv.txt
```

### 4. Remove Duplicate Lines

After sorting, use `uniq` to remove duplicate lines:

```bash
uniq sorted_csv.txt > unique_csv.txt
```

**Example:**

Remove duplicates from `sorted_csv.txt`:

```bash
uniq sorted_csv.txt > unique_csv.txt
```

### 5. View the Results

Display the contents of the final file to verify the results:

```bash
cat unique_csv.txt
```

**Example:**

View `unique_csv.txt`:

```bash
cat unique_csv.txt
```

## Summary of Commands

1. **Combine Files:**

   ```bash
   cat file1.txt file2.txt > combined.txt
   ```

2. **Convert Delimiters:**

   ```bash
   sed 's/\t/,/g' combined.txt > combined_csv.txt
   # or for spaces
   sed 's/ \{1,\}/,/g' combined.txt > combined_csv.txt
   ```

3. **Sort the File:**

   ```bash
   sort -t, -k1,1 -k2,2 combined_csv.txt > sorted_csv.txt
   ```

4. **Remove Duplicate Lines:**

   ```bash
   uniq sorted_csv.txt > unique_csv.txt
   ```

5. **View the Results:**

   ```bash
   cat unique_csv.txt
   ```

## Example

Suppose you have two files, `complaince` and `waf`, containing the following data:

- **complaince:**

  ```
  Operational Excellence,API Gateway stage logging should be enabled,AWS Well-Architected Framework
  Operational Excellence,Auto Scaling groups with a load balancer should use health checks,AWS Well-Architected Framework
  ```

- **waf:**

  ```
  Operational Excellence,API Gateway stage logging should be enabled,AWS Well-Architected Framework
  Reliability,Lambda functions concurrent execution limit configured,AWS Well-Architected
  ```

**Steps:**

1. Combine:

   ```bash
   cat complaince waf > combined.txt
   ```

2. Convert (if necessary):

   ```bash
   sed 's/\t/,/g' combined.txt > combined_csv.txt
   ```

3. Sort:

   ```bash
   sort -t, -k1,1 -k2,2 combined_csv.txt > sorted_csv.txt
   ```

4. Remove duplicates:

   ```bash
   uniq sorted_csv.txt > unique_csv.txt
   ```

5. View results:

   ```bash
   cat unique_csv.txt
   ```
